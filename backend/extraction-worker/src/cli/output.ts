/**
 * Read results from PGLite after a local pipeline run and write JSON files.
 *
 * Keys are sorted deterministically so snapshot diffs (M4) are stable.
 * Timestamps and run IDs are preserved in the output — the snapshot runner
 * applies its own ignore list rather than stripping them here.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { Storage } from '../storage';

export type Severity = 'low' | 'medium' | 'high' | 'critical' | 'info' | 'unknown';

export const SEVERITY_RANK: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  moderate: 2,
  high: 3,
  critical: 4,
  unknown: 0,
};

export interface RunSummary {
  schema_version: string;
  organization_id: string;
  project_id: string;
  project_name: string;
  extraction_run_id: string;
  ecosystem: string;
  duration_ms: number;
  dependencies_count: number;
  vulnerabilities_count: number;
  semgrep_count: number;
  secrets_count: number;
  reachable_flows_count: number;
  finalize_summary?: unknown;
}

export interface WriteOutputsOptions {
  outputDir: string;
  organizationId: string;
  projectId: string;
  projectName: string;
  extractionRunId: string;
  ecosystem: string;
  startedAtMs: number;
  severityFilter?: Set<string>;
  finalizeSummary?: unknown;
}

export interface WriteOutputsResult {
  summary: RunSummary;
  vulns: any[];
  deps: any[];
  semgrep: any[];
  secrets: any[];
}

export async function writeOutputs(
  storage: Storage,
  opts: WriteOutputsOptions,
): Promise<WriteOutputsResult> {
  fs.mkdirSync(opts.outputDir, { recursive: true });

  const [depsRaw, vulnsRaw, semgrepRaw, secretsRaw, flowsRaw] = await Promise.all([
    fetchRows(storage, 'project_dependencies', 'project_id', opts.projectId),
    fetchRows(storage, 'project_dependency_vulnerabilities', 'project_id', opts.projectId),
    fetchRows(storage, 'project_semgrep_findings', 'project_id', opts.projectId),
    fetchRows(storage, 'project_secret_findings', 'project_id', opts.projectId),
    fetchRows(storage, 'project_reachable_flows', 'project_id', opts.projectId),
  ]);

  const vulns = opts.severityFilter
    ? vulnsRaw.filter((v: any) =>
        opts.severityFilter!.has(String(v.severity ?? 'unknown').toLowerCase()),
      )
    : vulnsRaw;

  const summary: RunSummary = {
    schema_version: 'deptex-local-v1',
    organization_id: opts.organizationId,
    project_id: opts.projectId,
    project_name: opts.projectName,
    extraction_run_id: opts.extractionRunId,
    ecosystem: opts.ecosystem,
    duration_ms: Date.now() - opts.startedAtMs,
    dependencies_count: depsRaw.length,
    vulnerabilities_count: vulnsRaw.length,
    semgrep_count: semgrepRaw.length,
    secrets_count: secretsRaw.length,
    reachable_flows_count: flowsRaw.length,
    finalize_summary: opts.finalizeSummary ?? null,
  };

  writeJson(path.join(opts.outputDir, 'summary.json'), summary);
  writeJson(path.join(opts.outputDir, 'deps.json'), sortRows(depsRaw));
  writeJson(path.join(opts.outputDir, 'vulns.json'), sortRows(vulns));
  writeJson(path.join(opts.outputDir, 'semgrep.json'), sortRows(semgrepRaw));
  writeJson(path.join(opts.outputDir, 'secrets.json'), sortRows(secretsRaw));
  writeJson(path.join(opts.outputDir, 'reachable_flows.json'), sortRows(flowsRaw));

  return { summary, vulns, deps: depsRaw, semgrep: semgrepRaw, secrets: secretsRaw };
}

async function fetchRows(
  storage: Storage,
  table: string,
  filterCol: string,
  filterVal: string,
): Promise<any[]> {
  const { data, error } = await storage
    .from(table)
    .select('*')
    .eq(filterCol, filterVal);
  if (error) {
    throw new Error(`read ${table} failed: ${error.message}`);
  }
  return Array.isArray(data) ? data : [];
}

/**
 * Fields that are random-per-run (auto-gen UUIDs) or time-dependent. Including
 * them in the canonical sort key would make row order change between runs
 * even though the data is semantically identical — breaking snapshot diffs.
 */
const UNSTABLE_SORT_FIELDS = new Set([
  'id',
  'project_id',
  'organization_id',
  'dependency_id',
  'dependency_version_id',
  'project_dependency_id',
  'extraction_run_id',
  'last_seen_extraction_run_id',
  'active_extraction_run_id',
  'previous_extraction_run_id',
  'created_at',
  'updated_at',
  'removed_at',
  'detected_at',
  'completed_at',
  'started_at',
  'heartbeat_at',
  'policy_evaluated_at',
  'ast_parsed_at',
  'last_vuln_check_at',
  'first_seen_at',
  'last_seen_at',
  'sla_due_at',
  'duration_ms',
]);

function sortRows(rows: any[]): any[] {
  return [...rows].sort((a, b) => {
    const ak = canonical(a);
    const bk = canonical(b);
    return ak < bk ? -1 : ak > bk ? 1 : 0;
  });
}

function canonical(row: any): string {
  if (!row || typeof row !== 'object') return String(row);
  // Build a stable key from non-random fields only.
  const stable: Record<string, unknown> = {};
  for (const k of Object.keys(row).sort()) {
    if (UNSTABLE_SORT_FIELDS.has(k)) continue;
    stable[k] = row[k];
  }
  try {
    return JSON.stringify(stable);
  } catch {
    return String(row);
  }
}

function writeJson(filePath: string, data: unknown): void {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

/** Determine CLI exit code based on findings severity vs --fail-on threshold. */
export function computeExitCode(
  vulns: any[],
  failOn: string | null,
): number {
  if (!failOn) return 0;
  const threshold = SEVERITY_RANK[failOn.toLowerCase()];
  if (threshold == null) return 0;
  for (const v of vulns) {
    const sev = SEVERITY_RANK[String(v.severity ?? '').toLowerCase()] ?? 0;
    if (sev >= threshold) return 1;
  }
  return 0;
}
