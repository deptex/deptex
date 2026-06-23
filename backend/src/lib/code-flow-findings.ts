/**
 * First-party data-flow findings.
 *
 * The taint engine emits source→sink flows that live entirely in the user's
 * OWN code (`project_reachable_flows.reachability_source = 'taint_engine'` AND
 * `osv_id IS NULL`) — e.g. `searchParams.msg` reaching `dangerouslySetInnerHTML`
 * in a Next.js page. These are not dependency CVEs, so there is no advisory to
 * borrow a title or severity from: the persisted `vuln_class` is what makes the
 * finding self-describing.
 *
 * This module is the single source of truth for the human label, severity
 * bucket, and Depscore of a first-party flow. The Depscore is a pure function
 * of `vuln_class` (no project-importance scaling — same as `dastDepscore`), so
 * the count-pills RPC (`security_summary_counts`) can reproduce the exact same
 * banding in SQL. If you change a score here, mirror it in
 * `phase54_security_summary_code_flows.sql`.
 */

export type FlowVulnClass =
  | 'sql_injection'
  | 'ssrf'
  | 'xss'
  | 'path_traversal'
  | 'command_injection'
  | 'prototype_pollution'
  | 'deserialization'
  | 'redos'
  | 'file_upload'
  | 'open_redirect'
  | 'log_injection'
  | 'code_injection'
  | 'weak_crypto'
  | 'auth_bypass';

export type FlowSeverityBand = 'critical' | 'high' | 'medium' | 'low';

interface FlowClassMeta {
  /** Human-facing finding title. */
  label: string;
  /** Severity bucket — drives the band the row lands in. */
  band: FlowSeverityBand;
}

/**
 * Per-class label + severity. A confirmed taint path takes no reachability
 * discount (the engine proved the data reaches the sink), so the band is the
 * class's inherent severity: injection/deserialization that yields code or
 * query execution is critical; XSS / SSRF / traversal / auth issues are high;
 * the softer classes (open redirect, ReDoS, log injection, weak crypto) are
 * medium. Every flow we surface here cleared the engine's confidence bar plus
 * (when enabled) the AI FP filter, so none floor to low.
 */
const VULN_CLASS_META: Record<FlowVulnClass, FlowClassMeta> = {
  sql_injection: { label: 'SQL injection', band: 'critical' },
  command_injection: { label: 'Command injection', band: 'critical' },
  code_injection: { label: 'Code injection', band: 'critical' },
  deserialization: { label: 'Unsafe deserialization', band: 'critical' },
  xss: { label: 'Cross-site scripting (XSS)', band: 'high' },
  ssrf: { label: 'Server-side request forgery (SSRF)', band: 'high' },
  path_traversal: { label: 'Path traversal', band: 'high' },
  file_upload: { label: 'Unrestricted file upload', band: 'high' },
  prototype_pollution: { label: 'Prototype pollution', band: 'high' },
  auth_bypass: { label: 'Authorization bypass', band: 'high' },
  open_redirect: { label: 'Open redirect', band: 'medium' },
  redos: { label: 'Regular-expression denial of service (ReDoS)', band: 'medium' },
  log_injection: { label: 'Log injection', band: 'medium' },
  weak_crypto: { label: 'Weak cryptography', band: 'medium' },
};

/** Band → Depscore. Each lands squarely inside the matching depscore-band ramp
 *  (>=90 critical / >=70 high / >=40 medium / <40 low) used by SeverityPills +
 *  the table's DepscoreValue, so a flow's colour matches its preview-pill band. */
const BAND_SCORE: Record<FlowSeverityBand, number> = {
  critical: 92,
  high: 78,
  medium: 55,
  low: 30,
};

/** A flow with an unrecognized / null vuln_class (e.g. a row written before the
 *  column existed) is still a real reachable path — surface it as a medium
 *  "Tainted data flow" rather than dropping it on the floor. */
const UNKNOWN_META: FlowClassMeta = { label: 'Tainted data flow', band: 'medium' };

function metaFor(vulnClass: string | null | undefined): FlowClassMeta {
  return (vulnClass && VULN_CLASS_META[vulnClass as FlowVulnClass]) || UNKNOWN_META;
}

/** Human-facing title for a first-party flow finding. */
export function flowVulnClassLabel(vulnClass: string | null | undefined): string {
  return metaFor(vulnClass).label;
}

/** Severity bucket for a first-party flow finding. */
export function flowSeverity(vulnClass: string | null | undefined): FlowSeverityBand {
  return metaFor(vulnClass).band;
}

/** Per-band clamp so the depth spread below never crosses a ramp boundary
 *  (>=90 critical / >=70 high / >=40 medium). Keeps a flow's depscore colour
 *  matching its severity band, and keeps the count-pills SQL — which bands the
 *  bare vuln_class score (92/78/55) — in agreement with what the table shows. */
const BAND_CLAMP: Record<FlowSeverityBand, [number, number]> = {
  critical: [90, 99],
  high: [70, 89],
  medium: [40, 69],
  low: [20, 39],
};

/** EPD-style depth nudge: a shorter, more direct source→sink path is a more
 *  clear-cut, higher-confidence finding; a long winding path is a touch softer.
 *  Mirrors EPD's alpha^depth decay for dependency CVEs, applied to first-party
 *  flows so a page of same-class findings spreads out (e.g. 90–95 across critical
 *  SQLi flows) instead of reading as a flat wall of one number. Null length
 *  (no path info) = no nudge. */
function flowDepthAdjust(flowLength: number | null | undefined): number {
  if (flowLength == null || !Number.isFinite(flowLength)) return 0;
  const n = Math.max(0, Math.floor(flowLength));
  if (n <= 2) return 3;
  if (n <= 3) return 2;
  if (n <= 4) return 1;
  if (n <= 6) return 0;
  if (n <= 8) return -1;
  if (n <= 11) return -2;
  return -3;
}

/** Depscore (0-100) for a first-party flow finding. The base is a pure function
 *  of `vuln_class` — the bare-class value the count-pills SQL mirrors (92/78/55).
 *  An optional `flowLength` then spreads it *within the band* by path depth so a
 *  list of same-class flows isn't a wall of one number. Always stays inside the
 *  class's band ramp, so colour + pill counts stay consistent. */
export function firstPartyFlowDepscore(
  vulnClass: string | null | undefined,
  flowLength?: number | null,
): number {
  const band = metaFor(vulnClass).band;
  const [lo, hi] = BAND_CLAMP[band];
  const raw = BAND_SCORE[band] + flowDepthAdjust(flowLength);
  return Math.max(lo, Math.min(hi, raw));
}

/** The shape returned by GET .../code-flow-findings and consumed by the
 *  unified findings table's `taint_flow` row. Mirrors the flow row plus the
 *  derived title / severity / depscore so the frontend renders without
 *  re-deriving the scoring. */
export interface DataFlowFinding {
  id: string;
  project_id: string;
  extraction_run_id: string;
  vuln_class: string | null;
  title: string;
  severity: FlowSeverityBand;
  depscore: number;
  entry_point_file: string | null;
  entry_point_line: number | null;
  entry_point_method: string | null;
  entry_point_tag: string | null;
  entry_point_code: string | null;
  sink_file: string | null;
  sink_line: number | null;
  sink_method: string | null;
  sink_code: string | null;
  flow_length: number | null;
  flow_nodes: unknown;
  flow_signature_hash: string | null;
  created_at: string | null;
}

/** Map a raw `project_reachable_flows` row to the finding DTO. */
export function toDataFlowFinding(row: Record<string, any>): DataFlowFinding {
  return {
    id: row.id,
    project_id: row.project_id,
    extraction_run_id: row.extraction_run_id,
    vuln_class: row.vuln_class ?? null,
    title: flowVulnClassLabel(row.vuln_class),
    severity: flowSeverity(row.vuln_class),
    depscore: firstPartyFlowDepscore(row.vuln_class, row.flow_length),
    entry_point_file: row.entry_point_file ?? null,
    entry_point_line: row.entry_point_line ?? null,
    entry_point_method: row.entry_point_method ?? null,
    entry_point_tag: row.entry_point_tag ?? null,
    entry_point_code: row.entry_point_code ?? null,
    sink_file: row.sink_file ?? null,
    sink_line: row.sink_line ?? null,
    sink_method: row.sink_method ?? null,
    sink_code: row.sink_code ?? null,
    flow_length: row.flow_length ?? null,
    flow_nodes: row.flow_nodes ?? [],
    flow_signature_hash: row.flow_signature_hash ?? null,
    created_at: row.created_at ?? null,
  };
}
