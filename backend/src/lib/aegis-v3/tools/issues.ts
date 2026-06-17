import { jsonSchema } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { getActiveExtractionId, NO_ACTIVE_RUN } from '../../active-extraction';
import { vulnAutoIgnoreReason } from '../finding-triage';
import { resolveProject } from './resolvers';
import type { AegisToolEntry } from '../tool-types';

const ISSUE_TYPES = ['vulnerability', 'semgrep', 'secret'] as const;
type IssueType = (typeof ISSUE_TYPES)[number];

// Cross-source severity ranking. Semgrep emits ERROR/WARNING/INFO; advisories
// emit critical/high/medium/low; secrets are bucketed by is_verified. Keep one
// table that maps any of those into the same ordinal so the unified sort is
// monotonic regardless of which source a row came from.
const SEVERITY_RANK: Record<string, number> = {
  critical: 4,
  error: 3,
  high: 3,
  warning: 2,
  medium: 2,
  low: 1,
  info: 0,
};

interface UnifiedIssue {
  // Opaque, non-UUID handle to pass back to `request_fix` as findingHandle.
  // For vulnerabilities this is the OSV id (CVE-/GHSA-); for semgrep/secret
  // it's `<file_path>:<line>`. Server-side resolves the handle to the row id.
  handle: string;
  type: IssueType;
  severity: string | null;
  title: string;
  file_path: string | null;
  line: number | null;
  rule_or_cve: string | null;
  cwe_ids: string[] | null;
  depscore: number | null;
  status: string | null;
}

const listProjectIssues: AegisToolEntry<{
  projectName: string;
  types?: IssueType[];
  limit?: number;
  includeAutoIgnored?: boolean;
}> = {
  name: 'list_project_issues',
  description:
    "List the security issues on a project — vulnerabilities (open-source CVEs / GHSAs), Semgrep static-analysis findings, and detected secrets — in one unified, depscore-sorted view. Each row includes `handle` (opaque, NEVER show this string to the user — it's only for the `findingHandle` arg to `request_fix`), `type` ('vulnerability' | 'semgrep' | 'secret'), `severity`, `title`, `file_path`, `line`, `rule_or_cve`, `cwe_ids`, `depscore`, and `status`. When you describe an issue to the user in prose, use `title` / `file_path` / `line` — never the handle. Use this BEFORE `request_fix` to find the right handle and type. Only `status: 'open'` issues are returned by default — vulnerabilities the platform auto-ignores (not reachable / not confirmed reachable, the findings table's Auto Ignored rows) are excluded unless `includeAutoIgnored: true`.",
  danger: 'safe',
  inputSchema: jsonSchema({
    type: 'object',
    properties: {
      projectName: { type: 'string', minLength: 1, description: 'Project name as the user said it.' },
      types: {
        type: 'array',
        items: { type: 'string', enum: [...ISSUE_TYPES] },
        description: 'Optional: filter to specific issue types. Default: all three.',
      },
      limit: { type: 'integer', minimum: 1, maximum: 200 },
      includeAutoIgnored: {
        type: 'boolean',
        description:
          "Include vulnerabilities the platform auto-ignored (not reachable). They come back with status 'auto_ignored'. Default false.",
      },
    },
    required: ['projectName'],
    additionalProperties: false,
  }),
  execute: async ({ projectName, types, limit, includeAutoIgnored }, ctx) => {
    const resolved = await resolveProject(projectName, ctx.orgId, ctx.supabase);
    if ('error' in resolved) return resolved;

    // Findings tables hold one generation of rows per extraction run — filter
    // to the active run or every historical scan's rows come back as
    // apparent duplicates.
    const activeRunId =
      (await getActiveExtractionId(ctx.supabase as SupabaseClient, resolved.id)) ?? NO_ACTIVE_RUN;

    const cap = limit ?? 50;
    const wanted = new Set<IssueType>(
      Array.isArray(types) && types.length > 0 ? types : [...ISSUE_TYPES],
    );
    const issues: UnifiedIssue[] = [];

    if (wanted.has('vulnerability')) {
      const { data: vulns, error } = await ctx.supabase
        .from('project_dependency_vulnerabilities')
        .select(
          'osv_id, severity, summary, depscore, status, project_dependency_id, reachability_level, is_reachable, runtime_confirmed_at',
        )
        .eq('project_id', resolved.id)
        .eq('extraction_run_id', activeRunId)
        .eq('suppressed', false)
        .eq('status', 'open')
        .order('depscore', { ascending: false, nullsFirst: false })
        .limit(cap);
      if (error) return { error: error.message };

      const pdIds = Array.from(
        new Set((vulns ?? []).map((v: { project_dependency_id: string }) => v.project_dependency_id)),
      );
      const pdById = new Map<string, { name: string; version: string | null }>();
      if (pdIds.length > 0) {
        const { data: pds } = await ctx.supabase
          .from('project_dependencies')
          .select('id, name, version')
          .in('id', pdIds);
        for (const pd of pds ?? []) {
          const row = pd as { id: string; name: string; version: string | null };
          pdById.set(row.id, { name: row.name, version: row.version });
        }
      }

      for (const v of vulns ?? []) {
        const row = v as {
          osv_id: string;
          severity: string | null;
          summary: string | null;
          depscore: number | null;
          status: string | null;
          project_dependency_id: string;
          reachability_level: string | null;
          is_reachable: boolean | null;
          runtime_confirmed_at: string | null;
        };
        // Mirror the findings table's auto-triage: rows the UI shows as
        // "Auto Ignored" (not reachable / not confirmed reachable) are
        // excluded by default so the agent doesn't propose fixes the user's
        // own findings view has set aside.
        const autoIgnored = vulnAutoIgnoreReason(row) != null;
        if (autoIgnored && !includeAutoIgnored) continue;
        const dep = pdById.get(row.project_dependency_id);
        const depLabel = dep
          ? `${dep.name}${dep.version ? `@${dep.version}` : ''}`
          : null;
        issues.push({
          handle: row.osv_id,
          type: 'vulnerability',
          severity: row.severity ? row.severity.toLowerCase() : null,
          title: depLabel ? `${row.osv_id} in ${depLabel}` : row.osv_id,
          file_path: null,
          line: null,
          rule_or_cve: row.osv_id,
          cwe_ids: null,
          depscore: row.depscore ?? null,
          status: autoIgnored ? 'auto_ignored' : row.status,
        });
      }
    }

    if (wanted.has('semgrep')) {
      const { data: rows, error } = await ctx.supabase
        .from('project_semgrep_findings')
        .select(
          'id, rule_id, severity, message, file_path, start_line, cwe_ids, depscore, status',
        )
        .eq('project_id', resolved.id)
        .eq('extraction_run_id', activeRunId)
        .eq('status', 'open')
        .order('depscore', { ascending: false, nullsFirst: false })
        .limit(cap);
      if (error) return { error: error.message };

      for (const r of rows ?? []) {
        const row = r as {
          id: string;
          rule_id: string;
          severity: string | null;
          message: string | null;
          file_path: string | null;
          start_line: number | null;
          cwe_ids: string[] | null;
          depscore: number | null;
          status: string | null;
        };
        const filename = row.file_path?.split(/[\\/]/).pop() ?? row.file_path;
        const locator = filename
          ? `${filename}${row.start_line ? `:${row.start_line}` : ''}`
          : null;
        issues.push({
          handle: `${row.file_path ?? ''}:${row.start_line ?? 0}`,
          type: 'semgrep',
          severity: row.severity ? row.severity.toLowerCase() : null,
          title: locator ? `${row.rule_id} in ${locator}` : row.rule_id,
          file_path: row.file_path,
          line: row.start_line ?? null,
          rule_or_cve: row.rule_id,
          cwe_ids: row.cwe_ids ?? null,
          depscore: row.depscore ?? null,
          status: row.status,
        });
      }
    }

    if (wanted.has('secret')) {
      const { data: rows, error } = await ctx.supabase
        .from('project_secret_findings')
        .select(
          'id, detector_type, file_path, start_line, description, depscore, status, is_verified',
        )
        .eq('project_id', resolved.id)
        .eq('extraction_run_id', activeRunId)
        .eq('status', 'open')
        .eq('is_current', true)
        .order('depscore', { ascending: false, nullsFirst: false })
        .limit(cap);
      if (error) return { error: error.message };

      for (const r of rows ?? []) {
        const row = r as {
          id: string;
          detector_type: string;
          file_path: string;
          start_line: number | null;
          description: string | null;
          depscore: number | null;
          status: string | null;
          is_verified: boolean | null;
        };
        const filename = row.file_path?.split(/[\\/]/).pop() ?? row.file_path;
        const locator = filename
          ? `${filename}${row.start_line ? `:${row.start_line}` : ''}`
          : row.file_path;
        issues.push({
          handle: `${row.file_path ?? ''}:${row.start_line ?? 0}`,
          type: 'secret',
          severity: row.is_verified ? 'high' : 'medium',
          title: `${row.detector_type} in ${locator}`,
          file_path: row.file_path,
          line: row.start_line ?? null,
          rule_or_cve: row.detector_type,
          cwe_ids: null,
          depscore: row.depscore ?? null,
          status: row.status,
        });
      }
    }

    issues.sort((a, b) => {
      const da = a.depscore ?? -1;
      const db = b.depscore ?? -1;
      if (db !== da) return db - da;
      const sa = SEVERITY_RANK[(a.severity ?? '').toLowerCase()] ?? -1;
      const sb = SEVERITY_RANK[(b.severity ?? '').toLowerCase()] ?? -1;
      return sb - sa;
    });

    const trimmed = issues.slice(0, cap);
    return {
      project: resolved.name,
      issue_count: trimmed.length,
      issues: trimmed,
    };
  },
};

export const issuesTools: AegisToolEntry[] = [listProjectIssues];
