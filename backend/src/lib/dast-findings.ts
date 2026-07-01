/**
 * Shared DAST-findings shaping + loader.
 *
 * Extracted from `routes/dast.ts` so the project findings-bundle can reuse the
 * EXACT same target-resolution → tenant-guard → findings query → DTO mapping
 * the standalone `GET /:projectId/dast/findings` route runs. Keeping one copy
 * means the bundle and the legacy endpoint can never drift on scoring or
 * cross-tenant guards.
 */
import type { SupabaseClient } from '@supabase/supabase-js';
import { loadTargetOrDeny, isLoadTargetDeny } from './dast-tenant-guard';
import type { DastFindingDTO } from '../types/dast';

// v2.1a inserted dast_zap / dast_nuclei subtypes; dry-run is its own type.
export const DAST_SCAN_TYPES = ['dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run'];

/**
 * Coarse impact class for a DAST finding, keyed off ZAP/Nuclei's alert name.
 * Server-side injection (SQLi, SSTI, command/code injection, traversal, SSRF,
 * deserialization, XXE) is the high-impact tier; XSS/CSRF/open-redirect the
 * middle; passive header/cache/cookie/info-disclosure hygiene the low tier
 * (best-practice nudges that fire on nearly every site).
 */
export function dastImpactClass(vulnType: string | null | undefined): 'injection' | 'xss' | 'passive' | 'other' {
  const t = (vulnType ?? '').toLowerCase();
  if (
    /sql injection|command injection|code injection|template injection|ldap injection|xpath|path traversal|remote os command|remote code|server side request|ssrf|xxe|xml external|deserial/.test(t)
  ) {
    return 'injection';
  }
  if (/cross site scripting|cross-site scripting|\bxss\b|cross site request|cross-site request|\bcsrf\b|open redirect/.test(t)) {
    return 'xss';
  }
  if (
    /header|\bcache|cookie|\bcsp\b|content security policy|clickjack|x-powered-by|information disclosure|source code disclosure|strict-transport|spectre|site isolation|storable|cacheable|permissions policy|sec-fetch|mime|x-content-type|charset|timestamp|comment/.test(t)
  ) {
    return 'passive';
  }
  return 'other';
}

/**
 * DAST findings carry no stored depscore (unlike container/IaC findings, which
 * are scored at scan time). We derive a priority score on read so the unified
 * findings table can sort DAST alongside every other scanner category — and so
 * the score actually differentiates findings instead of pinning every "high"
 * alert at one number. The score combines:
 *   - severity (ZAP/Nuclei risk band),
 *   - confidence (how sure the scanner is it's real — confirmed/high/med/low),
 *   - impact class (server-side injection > XSS > passive hygiene).
 * It's then floored into the critical band when the hit is cross-linked to a
 * known-vulnerable dependency (confirmed exploitable) or is CISA-KEV tagged.
 */
export function dastDepscore(
  severity: string | null | undefined,
  opts: { confidence?: string | null; vulnType?: string | null; confirmedExploitable: boolean; kev: boolean },
): number | null {
  let score: number;
  switch ((severity ?? '').toLowerCase()) {
    case 'critical': score = 90; break;
    case 'high': score = 72; break;
    case 'medium': score = 48; break;
    case 'low': score = 26; break;
    case 'info': score = 10; break;
    default: return null;
  }
  switch ((opts.confidence ?? '').toLowerCase()) {
    case 'confirmed': score += 10; break;
    case 'high': score += 6; break;
    case 'low': score -= 12; break;
    // medium / unknown: no adjustment
  }
  switch (dastImpactClass(opts.vulnType)) {
    case 'injection': score += 10; break;
    case 'xss': score += 4; break;
    case 'passive': score -= 8; break;
    // other: no adjustment
  }
  if (opts.confirmedExploitable) score = Math.max(score, 90);
  if (opts.kev) score = Math.max(score, 96);
  return Math.max(0, Math.min(100, Math.round(score)));
}

const DAST_FINDING_COLUMNS =
  'id, target_id, auth_state, engine, kev, endpoint_url, http_method, vulnerability_type, severity, cwe_id, owasp_top10_ref, rule_id, message, payload_redacted, response_evidence_redacted, confidence, handler_file_path, handler_function_name, handler_line, handler_code_snippet, linked_sca_osv_id, linked_sca_project_dependency_id, linked_sast_finding_id, cross_link_methods, status, risk_accepted_reason, created_at, finding_key, auto_ignored, auto_ignore_reason';

/** Map a raw `project_dast_findings` row to the wire DTO (incl derived depscore). */
function mapDastFindingRow(row: any): DastFindingDTO {
  const confirmedExploitable = row.linked_sca_osv_id != null;
  const kev = row.kev ?? false;
  return {
    id: row.id,
    target_id: row.target_id ?? null,
    auth_state: row.auth_state ?? null,
    engine: row.engine ?? 'zap',
    kev,
    endpoint_url: row.endpoint_url,
    http_method: row.http_method,
    vulnerability_type: row.vulnerability_type,
    severity: row.severity,
    cwe_id: row.cwe_id,
    owasp_top10_ref: row.owasp_top10_ref,
    rule_id: row.rule_id,
    message: row.message,
    payload_redacted: row.payload_redacted,
    response_evidence_redacted: row.response_evidence_redacted,
    confidence: row.confidence,
    handler_file_path: row.handler_file_path,
    handler_function_name: row.handler_function_name,
    handler_line: row.handler_line,
    handler_code_snippet: row.handler_code_snippet ?? null,
    linked_sca_osv_id: row.linked_sca_osv_id,
    linked_sca_project_dependency_id: row.linked_sca_project_dependency_id,
    linked_sast_finding_id: row.linked_sast_finding_id ?? null,
    cross_link_methods: row.cross_link_methods ?? null,
    confirmed_exploitable: confirmedExploitable,
    depscore: dastDepscore(row.severity, {
      confidence: row.confidence,
      vulnType: row.vulnerability_type,
      confirmedExploitable,
      kev,
    }),
    status: row.status,
    risk_accepted_reason: row.risk_accepted_reason,
    created_at: row.created_at,
  } as DastFindingDTO;
}

export interface DastFindingsLoad {
  findings: DastFindingDTO[];
  /**
   * Set when the STANDALONE route should respond with this error status instead
   * of a findings array (target tenant-guard 404, findings-query 500). The
   * findings-bundle ignores this and uses `findings` (always `[]` here), so a
   * single failing target degrades only the dast slice. tsconfig runs with
   * `strictNullChecks:false`, which doesn't narrow boolean-discriminated unions,
   * so this is a plain optional rather than an `{ ok }` union.
   */
  deny?: { status: number; error: string };
}

/**
 * Resolve a DAST target (explicit `filterTargetId`, or the latest scan job that
 * carries a target_id when `resolveLatestTarget`), run the cross-tenant guard,
 * read its active run, and load + shape that run's findings.
 *
 * The caller (route OR bundle) MUST have already verified the user's access to
 * `projectId`; `organizationId` is the access-resolved org used only as the
 * tenant-guard's expected tuple. Returns a discriminated result so the route
 * can surface the guard's 404 / query 500, while the bundle treats any non-ok
 * outcome as an empty slice.
 */
export async function loadDastFindings(
  supabase: SupabaseClient,
  params: {
    projectId: string;
    organizationId: string;
    limit: number;
    filterTargetId: string | null;
    resolveLatestTarget: boolean;
  },
): Promise<DastFindingsLoad> {
  const { projectId, organizationId, limit, resolveLatestTarget } = params;
  let filterTargetId = params.filterTargetId;

  if (!filterTargetId && resolveLatestTarget) {
    // Replicate the frontend rule exactly: among the most recent scan jobs
    // (created_at desc), the first one that carries a target_id. The resolved
    // target still flows through loadTargetOrDeny below, so the tenant guard is
    // unchanged — server-side resolution never widens access.
    const { data: recentJobs } = await supabase
      .from('scan_jobs')
      .select('target_id')
      .eq('project_id', projectId)
      .in('type', DAST_SCAN_TYPES)
      .order('created_at', { ascending: false })
      .limit(5);
    filterTargetId = (recentJobs ?? []).find((j: any) => j.target_id)?.target_id ?? null;
    if (!filterTargetId) return { findings: [] };
  }

  if (!filterTargetId) {
    // v2.1b: target_id is required. Every finding belongs to a
    // project_dast_targets row, so callers must specify which target's findings
    // to load (or opt into resolveLatestTarget above).
    return { findings: [] };
  }

  const guard = await loadTargetOrDeny(supabase, filterTargetId, projectId, organizationId);
  if (isLoadTargetDeny(guard)) return { findings: [], deny: { status: 404, error: 'target_not_found' } };

  const { data: targetRow } = await supabase
    .from('project_dast_targets')
    .select('active_dast_run_id')
    .eq('id', filterTargetId)
    .maybeSingle();
  if (!targetRow?.active_dast_run_id) return { findings: [] };
  const activeRunId = targetRow.active_dast_run_id;

  const { data, error } = await supabase
    .from('project_dast_findings')
    .select(DAST_FINDING_COLUMNS)
    .eq('project_id', projectId)
    .eq('target_id', filterTargetId)
    .eq('dast_run_id', activeRunId)
    .order('severity', { ascending: true })
    .limit(limit);

  if (error) {
    console.error('[dast] GET findings error:', error.message);
    return { findings: [], deny: { status: 500, error: 'Failed to load DAST findings' } };
  }

  return { findings: (data ?? []).map(mapDastFindingRow) };
}
