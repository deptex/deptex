/**
 * Coerce non-taint detector findings into `Flow` records so they share the
 * downstream pipeline with taint flows.
 *
 * Two detector regimes consume `CallSite[]` and emit findings:
 *   - Phase F4 — `detectSanitizerAbsence` on `FrameworkSink.required_arguments`.
 *   - Phase 3.3 — `detectInsecureDefaults` on `FrameworkSpec.insecure_defaults`.
 *
 * Both shapes share enough with `Flow` to round-trip through
 * `project_reachable_flows` storage: a single-hop flow whose source == sink
 * == the offending callsite. We synthesize `entry_point_*` from the same
 * location as the sink so the writer's signature hash stays deterministic.
 *
 * Engine confidence is fixed at 0.95 — well above the default FP-filter
 * threshold (0.7) so detector flows bypass the LLM re-check loop. The
 * filter is for noisy taint flows; detector findings are deterministic
 * AST matches and don't need the model to vote.
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

const DETECTOR_ENGINE_CONFIDENCE = 0.95;

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
