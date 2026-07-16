/**
 * dogfood-check — verify that a `depscanner/test-repos/<framework>/` fixture's
 * actual scan findings match its committed `.deptex/expected.yaml`.
 *
 * Authoritative cross-batch gate for the depscanner dogfood corpus
 * (`depscanner/test-repos/README.md`). Walked manually via the runbook
 * (`docs/runbooks/depscanner-dogfood.md`).
 *
 * Auth: service-role direct Supabase query — bypasses the HTTP API. The
 * manual walkthrough is what validates the API surface; the harness only
 * cares about findings-vs-expected ground truth.
 *
 * Single-fixture mode (current):
 *   npm run dogfood:check -- --fixture express --project-id <uuid>
 *
 * All-fixtures mode (lit up in M2 once we have a manifest of fixture →
 * project_id mappings):
 *   npm run dogfood:check
 *
 * Env (loaded from backend/.env):
 *   SUPABASE_URL
 *   SUPABASE_SERVICE_ROLE_KEY
 *
 * Match semantics — see `docs/runbooks/depscanner-dogfood.md`:
 *  - subset, not 1:1 (actual ⊇ expected; extras are logged in RESULTS.md)
 *  - alias-aware on osv_id (any value in `aliases` is accepted)
 *  - bucket-tolerant reachability (`reachable` ↔ {confirmed, data_flow,
 *    function}; `unreachable` ↔ {module, unreachable}; `any` skips check)
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { createClient, SupabaseClient } from '@supabase/supabase-js';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import * as yaml from 'js-yaml';
import * as dotenv from 'dotenv';

// ---------------------------------------------------------------------------
// expected.yaml types
// ---------------------------------------------------------------------------

export interface ExpectedVuln {
  osv_id: string;
  aliases?: string[];
  file?: string;
  line?: number;
  reachability_bucket?: 'reachable' | 'unreachable' | 'any';
}

export interface ExpectedIacFinding {
  rule_id: string;
  file?: string;
  line?: number;
}

export interface ExpectedContainerCve {
  osv_id: string;
  aliases?: string[];
  base_image?: string;
}

export interface ExpectedSecret {
  rule_id: string;
  file?: string;
  line?: number;
}

export interface ExpectedMaliciousPkg {
  package: string;
  ecosystem: string;
  note?: string;
}

export interface ExpectedSemgrepFinding {
  rule_id: string;
  file?: string;
  line?: number;
}

export interface ExpectedDastFinding {
  alert: string;
  url_pattern?: string;
}

/**
 * Entry-point auth classification (T6a). Assert a detected route's
 * `project_entry_points.classification`. Match by `route` (route_pattern
 * substring) and/or `file` (file_path). At least one must be given.
 */
export interface ExpectedEntryPoint {
  classification: 'PUBLIC_UNAUTH' | 'AUTH_INTERNAL' | 'OFFLINE_WORKER' | 'UNKNOWN';
  route?: string;
  file?: string;
}

/**
 * Entry-point auth classification (T6a). Assert that at least one taint-engine
 * flow whose source is in `file` carries `entry_point_tag = tag`. `line` is
 * optional (line-tolerant so byte drift in the fixture doesn't break the check).
 */
export interface ExpectedFlowTag {
  file: string;
  tag: string;
  line?: number;
}

export interface ExpectedYaml {
  reachable_vulns?: ExpectedVuln[];
  unreachable_vulns?: ExpectedVuln[];
  iac_findings?: ExpectedIacFinding[];
  container_cves?: ExpectedContainerCve[];
  secrets?: ExpectedSecret[];
  malicious_pkg?: ExpectedMaliciousPkg[];
  semgrep_findings?: ExpectedSemgrepFinding[];
  dast_findings?: ExpectedDastFinding[];
  entry_points?: ExpectedEntryPoint[];
  flow_tags?: ExpectedFlowTag[];
}

// ---------------------------------------------------------------------------
// actual findings (DB-shaped subsets — only what we diff against)
// ---------------------------------------------------------------------------

export interface ActualVuln {
  osv_id: string;
  aliases: string[];
  reachability_level: string | null;
}

export interface ActualIacFinding {
  rule_id: string;
  file_path: string;
}

export interface ActualContainerCve {
  osv_id: string | null;
  cve_id: string | null;
  image_reference: string;
}

export interface ActualSecret {
  detector_type: string;
  file_path: string;
}

export interface ActualMaliciousPkg {
  package_name: string;
  rule_id: string;
}

export interface ActualSemgrepFinding {
  rule_id: string;
  file_path: string;
}

export interface ActualDastFinding {
  vulnerability_type: string;
  endpoint_url: string;
}

export interface ActualEntryPoint {
  file_path: string;
  route_pattern: string | null;
  classification: string | null;
}

export interface ActualFlowTag {
  entry_point_file: string;
  entry_point_line: number | null;
  entry_point_tag: string | null;
}

export interface ActualFindings {
  vulns: ActualVuln[];
  iac: ActualIacFinding[];
  container: ActualContainerCve[];
  secrets: ActualSecret[];
  malicious: ActualMaliciousPkg[];
  semgrep: ActualSemgrepFinding[];
  dast: ActualDastFinding[];
  entryPoints: ActualEntryPoint[];
  flowTags: ActualFlowTag[];
}

// ---------------------------------------------------------------------------
// pure match + diff logic (exported so the test file can call directly)
// ---------------------------------------------------------------------------

const REACHABLE_BUCKET = new Set(['confirmed', 'data_flow', 'function']);
const UNREACHABLE_BUCKET = new Set(['module', 'unreachable']);

/**
 * Alias-aware OSV match. Returns the actual finding whose osv_id, or any
 * value in its aliases array, equals either the expected osv_id or any
 * value in the expected aliases array.
 */
export function findOsvMatch(
  expected: { osv_id: string; aliases?: string[] },
  actual: ActualVuln[],
): ActualVuln | undefined {
  const expectedIds = new Set<string>([expected.osv_id, ...(expected.aliases ?? [])]);
  for (const a of actual) {
    const actualIds = new Set<string>([a.osv_id, ...(a.aliases ?? [])]);
    for (const id of actualIds) {
      if (expectedIds.has(id)) return a;
    }
  }
  return undefined;
}

/**
 * Bucket-tolerant reachability check. `reachable` ↔ {confirmed, data_flow,
 * function}; `unreachable` ↔ {module, unreachable}; `any` always passes;
 * undefined means caller didn't care.
 */
export function matchesReachabilityBucket(
  expectedBucket: ExpectedVuln['reachability_bucket'] | undefined,
  actualLevel: string | null,
): boolean {
  if (!expectedBucket || expectedBucket === 'any') return true;
  if (expectedBucket === 'reachable') {
    return actualLevel !== null && REACHABLE_BUCKET.has(actualLevel);
  }
  if (expectedBucket === 'unreachable') {
    return actualLevel === null || UNREACHABLE_BUCKET.has(actualLevel);
  }
  return false;
}

export interface DiffEntry {
  category: string;
  detail: string;
}

export interface DiffResult {
  missing: DiffEntry[];
  extras: DiffEntry[]; // informational only
  ok: boolean;
}

/**
 * Pure diff. Subset semantics: missing entries fail, extras are logged but
 * never fail. Caller is responsible for printing + exit code.
 */
export function diffExpectedVsActual(
  expected: ExpectedYaml,
  actual: ActualFindings,
): DiffResult {
  const missing: DiffEntry[] = [];
  const extras: DiffEntry[] = [];

  // --- reachable_vulns ---
  for (const e of expected.reachable_vulns ?? []) {
    const match = findOsvMatch(e, actual.vulns);
    if (!match) {
      missing.push({
        category: 'reachable_vulns',
        detail: `${e.osv_id} not found (aliases=${(e.aliases ?? []).join(',') || '-'})`,
      });
      continue;
    }
    const bucket = e.reachability_bucket ?? 'reachable';
    if (!matchesReachabilityBucket(bucket, match.reachability_level)) {
      missing.push({
        category: 'reachable_vulns',
        detail: `${e.osv_id} bucket mismatch: expected ${bucket}, actual reachability_level=${match.reachability_level ?? 'null'}`,
      });
    }
  }

  // --- unreachable_vulns ---
  for (const e of expected.unreachable_vulns ?? []) {
    const match = findOsvMatch(e, actual.vulns);
    if (!match) {
      missing.push({
        category: 'unreachable_vulns',
        detail: `${e.osv_id} not found (aliases=${(e.aliases ?? []).join(',') || '-'})`,
      });
      continue;
    }
    const bucket = e.reachability_bucket ?? 'unreachable';
    if (!matchesReachabilityBucket(bucket, match.reachability_level)) {
      missing.push({
        category: 'unreachable_vulns',
        detail: `${e.osv_id} bucket mismatch: expected ${bucket}, actual reachability_level=${match.reachability_level ?? 'null'}`,
      });
    }
  }

  // --- iac_findings ---
  for (const e of expected.iac_findings ?? []) {
    const match = actual.iac.find((a) => a.rule_id === e.rule_id);
    if (!match) {
      missing.push({
        category: 'iac_findings',
        detail: `${e.rule_id} not found${e.file ? ` (expected file=${e.file})` : ''}`,
      });
    }
  }

  // --- container_cves ---
  for (const e of expected.container_cves ?? []) {
    const expectedIds = new Set<string>([e.osv_id, ...(e.aliases ?? [])]);
    const match = actual.container.find((a) => {
      if (a.osv_id && expectedIds.has(a.osv_id)) return true;
      if (a.cve_id && expectedIds.has(a.cve_id)) return true;
      return false;
    });
    if (!match) {
      missing.push({
        category: 'container_cves',
        detail: `${e.osv_id} not found in container findings (aliases=${(e.aliases ?? []).join(',') || '-'})`,
      });
    }
  }

  // --- secrets ---
  // expected.yaml uses `rule_id`, schema column is `detector_type`. We accept
  // either form as a match.
  for (const e of expected.secrets ?? []) {
    const match = actual.secrets.find((a) => a.detector_type === e.rule_id);
    if (!match) {
      missing.push({
        category: 'secrets',
        detail: `${e.rule_id} not found (expected file=${e.file ?? '-'})`,
      });
    }
  }

  // --- malicious_pkg ---
  for (const e of expected.malicious_pkg ?? []) {
    const match = actual.malicious.find((a) => a.package_name === e.package);
    if (!match) {
      missing.push({
        category: 'malicious_pkg',
        detail: `${e.package} (${e.ecosystem}) not found in malicious findings`,
      });
    }
  }

  // --- semgrep_findings ---
  for (const e of expected.semgrep_findings ?? []) {
    const match = actual.semgrep.find((a) => a.rule_id === e.rule_id);
    if (!match) {
      missing.push({
        category: 'semgrep_findings',
        detail: `${e.rule_id} not found`,
      });
    }
  }

  // --- dast_findings ---
  for (const e of expected.dast_findings ?? []) {
    const match = actual.dast.find((a) => {
      // vulnerability_type matches the expected alert verbatim, OR
      // case-insensitive substring match for ZAP / Nuclei naming drift.
      const vt = a.vulnerability_type.toLowerCase();
      const alertLower = e.alert.toLowerCase();
      if (vt === alertLower || vt.includes(alertLower)) {
        if (e.url_pattern && !a.endpoint_url.includes(e.url_pattern)) return false;
        return true;
      }
      return false;
    });
    if (!match) {
      missing.push({
        category: 'dast_findings',
        detail: `"${e.alert}" not found${e.url_pattern ? ` for url pattern ${e.url_pattern}` : ''}`,
      });
    }
  }

  // --- entry_points (entry-point auth classification, T6a) ---
  for (const e of expected.entry_points ?? []) {
    const candidates = actual.entryPoints.filter((a) => {
      if (e.route && !(a.route_pattern ?? '').includes(e.route)) return false;
      if (e.file && !a.file_path.includes(e.file)) return false;
      return e.route != null || e.file != null;
    });
    if (candidates.length === 0) {
      missing.push({
        category: 'entry_points',
        detail: `no entry point matched route=${e.route ?? '-'} file=${e.file ?? '-'}`,
      });
      continue;
    }
    if (!candidates.some((a) => a.classification === e.classification)) {
      const got = Array.from(new Set(candidates.map((a) => a.classification ?? 'null'))).join(',');
      missing.push({
        category: 'entry_points',
        detail: `route=${e.route ?? '-'} file=${e.file ?? '-'} classification mismatch: expected ${e.classification}, got ${got}`,
      });
    }
  }

  // --- flow_tags (entry-point auth classification, T6a) ---
  for (const e of expected.flow_tags ?? []) {
    const candidates = actual.flowTags.filter((a) => {
      if (!a.entry_point_file.includes(e.file)) return false;
      if (e.line != null && a.entry_point_line !== e.line) return false;
      return true;
    });
    if (candidates.length === 0) {
      missing.push({
        category: 'flow_tags',
        detail: `no taint-engine flow at file=${e.file}${e.line != null ? `:${e.line}` : ''}`,
      });
      continue;
    }
    if (!candidates.some((a) => a.entry_point_tag === e.tag)) {
      const got = Array.from(new Set(candidates.map((a) => a.entry_point_tag ?? 'null'))).join(',');
      missing.push({
        category: 'flow_tags',
        detail: `file=${e.file}${e.line != null ? `:${e.line}` : ''} tag mismatch: expected ${e.tag}, got ${got}`,
      });
    }
  }

  // --- collect informational extras (not failure-driving) ---
  // (Only categories where the expected set is non-empty get extras logged,
  // to avoid noise on fixtures that intentionally don't cover a category.)
  const expectedOsvIds = new Set<string>();
  for (const e of [...(expected.reachable_vulns ?? []), ...(expected.unreachable_vulns ?? [])]) {
    expectedOsvIds.add(e.osv_id);
    for (const a of e.aliases ?? []) expectedOsvIds.add(a);
  }
  if (expectedOsvIds.size > 0) {
    for (const a of actual.vulns) {
      const ids = [a.osv_id, ...(a.aliases ?? [])];
      if (!ids.some((id) => expectedOsvIds.has(id))) {
        extras.push({ category: 'vulns', detail: `unexpected ${a.osv_id}` });
      }
    }
  }

  return { missing, extras, ok: missing.length === 0 };
}

// ---------------------------------------------------------------------------
// IO — file + Supabase
// ---------------------------------------------------------------------------

export function loadExpected(fixtureDir: string): ExpectedYaml {
  const expectedPath = path.join(fixtureDir, '.deptex', 'expected.yaml');
  if (!fs.existsSync(expectedPath)) {
    throw new Error(`expected.yaml not found at ${expectedPath}`);
  }
  const raw = fs.readFileSync(expectedPath, 'utf-8');
  const parsed = yaml.load(raw);
  if (parsed === null || typeof parsed !== 'object') {
    throw new Error(`expected.yaml at ${expectedPath} did not parse to an object`);
  }
  return parsed as ExpectedYaml;
}

async function loadActual(
  supabase: SupabaseClient,
  projectId: string,
): Promise<ActualFindings> {
  const out: ActualFindings = {
    vulns: [],
    iac: [],
    container: [],
    secrets: [],
    malicious: [],
    semgrep: [],
    dast: [],
    entryPoints: [],
    flowTags: [],
  };

  const vulnsRes = await supabase
    .from('project_dependency_vulnerabilities')
    .select('osv_id, aliases, reachability_level')
    .eq('project_id', projectId)
    .eq('status', 'open');
  if (vulnsRes.error) throw new Error(`vulns query: ${vulnsRes.error.message}`);
  out.vulns = (vulnsRes.data ?? []).map((r: any) => ({
    osv_id: r.osv_id,
    aliases: r.aliases ?? [],
    reachability_level: r.reachability_level ?? null,
  }));

  const iacRes = await supabase
    .from('project_iac_findings')
    .select('rule_id, file_path')
    .eq('project_id', projectId)
    .eq('status', 'open');
  if (iacRes.error) throw new Error(`iac query: ${iacRes.error.message}`);
  out.iac = (iacRes.data ?? []).map((r: any) => ({
    rule_id: r.rule_id,
    file_path: r.file_path,
  }));

  const containerRes = await supabase
    .from('project_container_findings')
    .select('osv_id, cve_id, image_reference')
    .eq('project_id', projectId)
    .eq('status', 'open');
  if (containerRes.error) throw new Error(`container query: ${containerRes.error.message}`);
  out.container = (containerRes.data ?? []).map((r: any) => ({
    osv_id: r.osv_id,
    cve_id: r.cve_id,
    image_reference: r.image_reference,
  }));

  const secretsRes = await supabase
    .from('project_secret_findings')
    .select('detector_type, file_path')
    .eq('project_id', projectId)
    .eq('status', 'open');
  if (secretsRes.error) throw new Error(`secrets query: ${secretsRes.error.message}`);
  out.secrets = (secretsRes.data ?? []).map((r: any) => ({
    detector_type: r.detector_type,
    file_path: r.file_path,
  }));

  // Malicious findings have only project_dependency_id — join via the
  // dependency table to resolve package names.
  const maliciousRes = await supabase
    .from('project_malicious_findings')
    .select('rule_id, project_dependency_id, project_dependencies!inner(name)')
    .eq('project_id', projectId);
  if (maliciousRes.error) throw new Error(`malicious query: ${maliciousRes.error.message}`);
  out.malicious = (maliciousRes.data ?? []).map((r: any) => ({
    package_name: r.project_dependencies?.name ?? '',
    rule_id: r.rule_id,
  }));

  const semgrepRes = await supabase
    .from('project_semgrep_findings')
    .select('rule_id, file_path')
    .eq('project_id', projectId)
    .eq('status', 'open');
  if (semgrepRes.error) throw new Error(`semgrep query: ${semgrepRes.error.message}`);
  out.semgrep = (semgrepRes.data ?? []).map((r: any) => ({
    rule_id: r.rule_id,
    file_path: r.file_path,
  }));

  const dastRes = await supabase
    .from('project_dast_findings')
    .select('vulnerability_type, endpoint_url')
    .eq('project_id', projectId)
    .eq('status', 'open');
  if (dastRes.error) throw new Error(`dast query: ${dastRes.error.message}`);
  out.dast = (dastRes.data ?? []).map((r: any) => ({
    vulnerability_type: r.vulnerability_type,
    endpoint_url: r.endpoint_url,
  }));

  // Entry-point auth classification (T6a). Scope to the active run so a
  // re-scanned fixture doesn't diff against stale rows.
  const activeRunRes = await supabase
    .from('projects')
    .select('active_extraction_run_id')
    .eq('id', projectId)
    .maybeSingle();
  const activeRunId = (activeRunRes.data as any)?.active_extraction_run_id ?? null;

  let epQuery = supabase
    .from('project_entry_points')
    .select('file_path, route_pattern, classification')
    .eq('project_id', projectId);
  if (activeRunId) epQuery = epQuery.eq('extraction_run_id', activeRunId);
  const epRes = await epQuery;
  if (epRes.error) throw new Error(`entry_points query: ${epRes.error.message}`);
  out.entryPoints = (epRes.data ?? []).map((r: any) => ({
    file_path: r.file_path,
    route_pattern: r.route_pattern ?? null,
    classification: r.classification ?? null,
  }));

  let ftQuery = supabase
    .from('project_reachable_flows')
    .select('entry_point_file, entry_point_line, entry_point_tag')
    .eq('project_id', projectId)
    .eq('reachability_source', 'taint_engine');
  if (activeRunId) ftQuery = ftQuery.eq('extraction_run_id', activeRunId);
  const ftRes = await ftQuery;
  if (ftRes.error) throw new Error(`flow_tags query: ${ftRes.error.message}`);
  out.flowTags = (ftRes.data ?? []).map((r: any) => ({
    entry_point_file: r.entry_point_file,
    entry_point_line: r.entry_point_line ?? null,
    entry_point_tag: r.entry_point_tag ?? null,
  }));

  return out;
}

// ---------------------------------------------------------------------------
// CLI shell
// ---------------------------------------------------------------------------

function fixtureDirFor(fixtureName: string): string {
  return path.resolve(__dirname, '..', 'test-repos', fixtureName);
}

function printReport(fixture: string, diff: DiffResult): void {
  const status = diff.ok ? 'PASS' : 'FAIL';
  console.log(`[${status}] ${fixture}`);
  if (diff.missing.length > 0) {
    console.log('  missing:');
    for (const m of diff.missing) console.log(`    - [${m.category}] ${m.detail}`);
  }
  if (diff.extras.length > 0) {
    console.log('  extras (informational, not failing):');
    for (const e of diff.extras) console.log(`    - [${e.category}] ${e.detail}`);
  }
}

async function main(): Promise<void> {
  dotenv.config({ path: path.resolve(__dirname, '../../backend/.env') });

  const { values } = parseArgs({
    options: {
      fixture: { type: 'string' },
      'project-id': { type: 'string' },
    },
    allowPositionals: false,
  });

  const fixtureName = values.fixture;
  const projectId = values['project-id'];

  if (!fixtureName) {
    console.error(
      'usage: npm run dogfood:check -- --fixture <name> --project-id <uuid>\n' +
        '       (all-fixtures mode without --fixture is wired in M2; current build requires both flags)',
    );
    process.exit(2);
  }

  if (!projectId) {
    console.error(`--project-id is required for fixture "${fixtureName}".`);
    process.exit(2);
  }

  const fixtureDir = fixtureDirFor(fixtureName);
  if (!fs.existsSync(fixtureDir)) {
    console.error(`fixture directory not found: ${fixtureDir}`);
    process.exit(2);
  }

  const SUPABASE_URL = process.env.SUPABASE_URL;
  const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
    console.error(
      'SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set (loaded from backend/.env).',
    );
    process.exit(2);
  }

  const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
    auth: { persistSession: false },
  });

  let expected: ExpectedYaml;
  try {
    expected = loadExpected(fixtureDir);
  } catch (err) {
    console.error(`failed to load expected.yaml: ${(err as Error).message}`);
    process.exit(2);
  }

  let actual: ActualFindings;
  try {
    actual = await loadActual(supabase, projectId);
  } catch (err) {
    console.error(`failed to load actual findings: ${(err as Error).message}`);
    process.exit(2);
  }

  const diff = diffExpectedVsActual(expected, actual);
  printReport(fixtureName, diff);
  process.exit(diff.ok ? 0 : 1);
}

// Only run main() when invoked directly (not when imported by tests).
if (require.main === module) {
  main().catch((err) => {
    console.error(err);
    process.exit(2);
  });
}
