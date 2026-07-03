/**
 * Coerce non-taint detector findings into `Flow` records so they share the
 * downstream pipeline with taint flows.
 *
 * Three detector regimes emit findings the pipeline coerces to `Flow`:
 *   - Phase F4 — `detectSanitizerAbsence` on `FrameworkSink.required_arguments` (CallSite[]).
 *   - Phase 3.3 — `detectInsecureDefaults` on `FrameworkSpec.insecure_defaults` (CallSite[]).
 *   - Phase 3.2 — `detectUnsafeRegexLiterals` on `FrameworkSpec.unsafe_regex_patterns` (raw file text).
 *
 * Both shapes share enough with `Flow` to round-trip through
 * `project_reachable_flows` storage: a single-hop flow whose source == sink
 * == the offending callsite. We synthesize `entry_point_*` from the same
 * location as the sink so the writer's signature hash stays deterministic.
 *
 * Engine confidence is fixed just BELOW the default FP-filter threshold
 * (0.7) so detector flows are routed through the same LLM re-check as
 * sub-threshold taint flows. The detectors are deterministic AST matches
 * but an over-broad sink pattern or a mis-parsed options object can still
 * produce a false positive — letting them ride at 0.95 meant a busted
 * detector finding bypassed every quality gate straight into the survivors.
 *
 * `taint_kind` is set to 'http_input' as a placeholder — these aren't
 * taint-flow shapes, but the column is NOT NULL on
 * `project_reachable_flows` and we don't want to bloat the closed enum
 * for the marker. Downstream UI / classifier doesn't branch on
 * taint_kind for detector flows.
 */

import { createHash } from 'crypto';
import type { Flow, FlowNode } from './flow';
import type { NonTaintFinding } from './non-taint-detector';
import type { InsecureDefaultFinding } from './insecure-default-detector';
import type { RegexLiteralFinding } from './regex-literal-detector';

// Just below the default FP-filter threshold (0.7) so detector flows are
// LLM-checked like sub-threshold taint flows rather than bypassing the filter.
const DETECTOR_ENGINE_CONFIDENCE = 0.65;

/**
 * Coerce a Phase F4 sanitizer-absence finding to a single-hop `Flow`.
 * `osv_id` is passed in so the caller can attach the CVE-targeted spec's
 * id (cve-specs from `organization_generated_rules`); bundled framework
 * specs leave it undefined.
 */
export function sanitizerAbsenceToFlow(
  finding: NonTaintFinding,
  framework: string,
  osvId: string | undefined,
): Flow {
  const sinkNode: FlowNode = {
    filePath: finding.sink_file,
    line: finding.sink_line,
    column: finding.sink_column,
    label: finding.sink_method,
    kind: 'sink',
  };
  return {
    id: hashFlowId('san', finding.sink_file, finding.sink_line, finding.sink_column, finding.sink_pattern),
    vuln_class: finding.vuln_class,
    taint_kind: 'http_input',
    entry_point_file: finding.sink_file,
    entry_point_line: finding.sink_line,
    entry_point_method: finding.sink_method,
    entry_point_pattern: finding.sink_pattern,
    sink_file: finding.sink_file,
    sink_line: finding.sink_line,
    sink_method: finding.sink_method,
    sink_pattern: finding.sink_pattern,
    sink_is_external: false,
    flow_nodes: [sinkNode],
    flow_length: 1,
    source_description: `sanitizer-absence detector (${framework}): missing ${finding.trigger.argument_name}`,
    sink_description: finding.description,
    engine_confidence: DETECTOR_ENGINE_CONFIDENCE,
    osv_id: osvId ?? finding.osv_id,
  };
}

/**
 * Coerce a Phase 3.3 insecure-default finding to a single-hop `Flow`.
 */
export function insecureDefaultToFlow(
  finding: InsecureDefaultFinding,
  osvId: string | undefined,
): Flow {
  const sinkNode: FlowNode = {
    filePath: finding.sink_file,
    line: finding.sink_line,
    column: finding.sink_column,
    label: finding.sink_method,
    kind: 'sink',
  };
  const argLabel =
    finding.trigger.argument_name ??
    (finding.trigger.argument_position !== undefined
      ? `arg[${finding.trigger.argument_position}]`
      : 'arg');
  return {
    id: hashFlowId('idd', finding.sink_file, finding.sink_line, finding.sink_column, finding.sink_pattern),
    vuln_class: finding.vuln_class,
    taint_kind: 'http_input',
    entry_point_file: finding.sink_file,
    entry_point_line: finding.sink_line,
    entry_point_method: finding.sink_method,
    entry_point_pattern: finding.sink_pattern,
    sink_file: finding.sink_file,
    sink_line: finding.sink_line,
    sink_method: finding.sink_method,
    sink_pattern: finding.sink_pattern,
    sink_is_external: false,
    flow_nodes: [sinkNode],
    flow_length: 1,
    source_description: `insecure-default detector (${finding.framework}): ${finding.trigger.reason} ${argLabel}${
      finding.trigger.observed_literal !== undefined ? `=${finding.trigger.observed_literal}` : ''
    }`,
    sink_description: finding.description,
    engine_confidence: DETECTOR_ENGINE_CONFIDENCE,
    osv_id: osvId,
  };
}

/**
 * Coerce a Phase 3.2 regex-literal finding to a single-hop `Flow`.
 *
 * Unlike the sanitizer-absence / insecure-default detectors (which consume
 * IR `CallSite[]`), the regex-literal detector fires on the PRESENCE of a
 * known-bad regex literal in source text — there is no callsite, so the
 * synthesized entry-point == sink == the file:line where the literal appears
 * (column is unavailable from the substring scan, so 0). `vuln_class` is
 * always `redos`: `unsafe_regex_patterns` exclusively models catastrophic-
 * backtracking ReDoS literals baked into a CVE patch.
 */
export function regexLiteralToFlow(
  finding: RegexLiteralFinding,
  osvId: string | undefined,
): Flow {
  const sinkNode: FlowNode = {
    filePath: finding.filePath,
    line: finding.line,
    column: 0,
    label: finding.regex,
    kind: 'sink',
  };
  return {
    id: hashFlowId('rgx', finding.filePath, finding.line, 0, finding.regex),
    vuln_class: 'redos',
    taint_kind: 'http_input',
    entry_point_file: finding.filePath,
    entry_point_line: finding.line,
    entry_point_method: finding.regex,
    entry_point_pattern: finding.regex,
    sink_file: finding.filePath,
    sink_line: finding.line,
    sink_method: finding.regex,
    sink_pattern: finding.regex,
    sink_is_external: false,
    flow_nodes: [sinkNode],
    flow_length: 1,
    source_description: `regex-literal detector (${finding.framework}): unsafe regex literal present`,
    sink_description: finding.description,
    engine_confidence: DETECTOR_ENGINE_CONFIDENCE,
    osv_id: osvId,
  };
}

function hashFlowId(
  tag: string,
  filePath: string,
  line: number,
  column: number,
  pattern: string,
): string {
  const h = createHash('sha1');
  h.update(`${tag}|${filePath}:${line}:${column}|${pattern}`);
  return h.digest('hex').slice(0, 16);
}
