/**
 * Output flow records produced by the propagator.
 *
 * Shape mirrors `project_reachable_flows` (per phase6b_reachability_tables.sql
 * + later alters) so that M4 can persist them with `reachability_source =
 * 'taint_engine'`. Fields like `purl` and `dependency_id` are filled in by
 * the M4 pipeline integration layer (which has access to the SBOM); the
 * propagator emits the engine's view of the flow and leaves dep resolution
 * to the writer.
 */

import type { FrameworkSink, FrameworkSource, TaintKind, VulnClass } from './spec';

export interface FlowNode {
  filePath: string;
  line: number;
  column: number;
  /** Human-readable label for this hop (variable name, function name, sink callee, etc.). */
  label: string;
  /** What kind of program point this hop represents. */
  kind: 'source' | 'assign' | 'call' | 'return' | 'sink';
}

/** A complete source → sink flow emitted by the propagator. */
export interface Flow {
  /** Unique within a single propagation run (sha1 of source loc + sink loc + path). */
  id: string;
  vuln_class: VulnClass;
  taint_kind: TaintKind;
  /** Entry point — the source-emitting statement. */
  entry_point_file: string;
  entry_point_line: number;
  entry_point_method: string;
  entry_point_pattern: string;
  /** Sink — the call expression where the tainted value is consumed. */
  sink_file: string;
  sink_line: number;
  sink_method: string;
  sink_pattern: string;
  /** Whether the sink callee resolved to an external (node_modules) function. */
  sink_is_external: boolean;
  /** Hop-by-hop trail from source to sink. */
  flow_nodes: FlowNode[];
  /** Number of hops; convenience copy of flow_nodes.length. */
  flow_length: number;
  /** The matched source spec, for telemetry. */
  source_description: string;
  /** The matched sink spec, for telemetry. */
  sink_description: string;
  /**
   * Engine's own confidence the flow is real, ∈ [0,1]. Heuristic:
   *   - short, non-wildcard, non-external sinks            → 0.9
   *   - long path / wildcard receiver / external sink      → 0.5–0.7
   *   - very long path or multiple lossy hops              → 0.3
   * Used by M7's FP filter to decide which flows the LLM should re-examine
   * (configured per-org via taint_engine_settings.ai_fp_filter_confidence_threshold,
   * default 0.7).
   */
  engine_confidence: number;
  /**
   * Phase 6.5 — when the matched sink came from a CVE-targeted FrameworkSpec
   * (`organization_generated_rules` row with spec_format='framework_spec'),
   * the sink carries an `osv_id` that the propagator copies onto the Flow
   * here. Framework-generic flows (matched against bundled
   * framework-models/*.yaml) leave it undefined.
   *
   * The classifier's confirmed-tier OR-clause keys on
   * `osv_id IS NOT NULL AND dependency_id IS NOT NULL`, so this field is
   * the discriminator that lets a CVE-targeted flow promote a PDV to
   * `confirmed`.
   */
  osv_id?: string;
}

/** Compact in-memory metadata about a tainted value flowing through the program. */
export interface TaintTrace {
  taint_kind: TaintKind;
  /** Source spec that introduced this taint. */
  source: FrameworkSource;
  /** Hop-by-hop history from the source to the current program point. */
  path: FlowNode[];
}

/** A sink-hit emitted while analyzing a function. Aggregated into Flows by the propagator. */
export interface SinkHit {
  sink: FrameworkSink;
  trace: TaintTrace;
  hit_node: FlowNode;
}

// ---------------------------------------------------------------------------
// Diagnostic serialisation (Phase 1.2 of the reachability-90-percent plan).
//
// The engine doesn't carry a canonical serialiser for TaintTrace today —
// `JSON.stringify(trace)` works incidentally because the interface is
// data-only, but there is no schema and no DropReason vocabulary for the
// "why didn't this taint propagate?" question. These exports give the iterate
// harness + per-language tests a stable diag surface to consume when
// `RunWorklistOptions.diagSink` is wired in. Zero overhead when diagSink is
// undefined — propagate-core only constructs DropRecords inside an
// `if (diagSink)` guard.
// ---------------------------------------------------------------------------

/**
 * Serialised form of TaintTrace for the diagnostic dump. Path nodes are
 * emitted verbatim; source.pattern + source.description carry enough to
 * identify which spec the trace originated from without serialising the full
 * FrameworkSource (which would bloat the NDJSON for no consumer benefit).
 */
export interface TraceJson {
  taint_kind: TaintKind;
  source_pattern: string;
  source_description: string;
  path: FlowNode[];
}

export function serializeTrace(trace: TaintTrace): TraceJson {
  return {
    taint_kind: trace.taint_kind,
    source_pattern: trace.source.pattern,
    source_description: trace.source.description,
    path: trace.path,
  };
}

/**
 * Short, kebab-case description of why a taint local was dropped or why a
 * loaded sink didn't fire. Free-text by design (per the plan's "promote to
 * enum once natural categories emerge" decision) — but `serializeTrace.test.ts`
 * walks `propagate-core.ts` for `reason:` literals and asserts the membership
 * list below stays stable. To add a new reason, edit BOTH this list AND the
 * propagator emission site in the same commit; the jest test will fail
 * otherwise.
 *
 * Established reasons:
 *   - 'source-no-match-no-receiver': source step text didn't match any spec
 *     pattern AND `receiverRoot()` returned no tainted local to fall back to.
 *   - 'assign-from-untainted': assign step's `from` was not in the local map.
 *   - 'call-internal-no-return-taint': internal callee resolved but did not
 *     publish a tainted return.
 *   - 'call-internal-callee-missing': callee referenced by ID was not in
 *     stateById (cross-language link drop).
 *   - 'call-external-no-arg-no-receiver': external/unresolved call with no
 *     tainted arg and no tainted receiver to pass through.
 *   - 'sink-loaded-no-tainted-arg': a spec sink matched the callee but none
 *     of the spec-required arg positions held tainted locals at this call.
 */
export type DropReason = string;

/** Stable membership list for `DropReason`. Read by the jest exhaustiveness test. */
export const KNOWN_DROP_REASONS = [
  'source-no-match-no-receiver',
  'assign-from-untainted',
  'call-internal-no-return-taint',
  'call-internal-callee-missing',
  'call-external-no-arg-no-receiver',
  'sink-loaded-no-tainted-arg',
] as const;

/** One emitted record per drop or sink-loaded-no-hit event. */
export interface DropRecord {
  reason: DropReason;
  step_kind: 'source' | 'assign' | 'call' | 'return';
  step_loc: { filePath: string; line: number; column: number };
  step_text: string;
  function_id: string;
  function_name: string;
  /** Trace of the local at the moment of drop, if any. */
  trace_at_drop?: TraceJson | null;
  /** For sink-miss records, which sink matched. */
  sink_pattern?: string;
}

/** Per-engine-run aggregate of diagnostic state, suitable for NDJSON or JSON dump. */
export interface DiagnosticRecord {
  /** Run-correlation string supplied by the caller (e.g. cveId). */
  correlation_id?: string;
  function_count: number;
  drops: DropRecord[];
  sinks_loaded: number;
  sinks_hit: number;
}

export function serializeDiagnosticRecord(opts: {
  correlationId?: string;
  functionCount: number;
  drops: DropRecord[];
  sinksLoaded: number;
  sinksHit: number;
}): DiagnosticRecord {
  return {
    correlation_id: opts.correlationId,
    function_count: opts.functionCount,
    drops: opts.drops,
    sinks_loaded: opts.sinksLoaded,
    sinks_hit: opts.sinksHit,
  };
}

/** Callback the propagator calls once per drop when `diagSink` is wired. */
export type DiagSink = (record: DropRecord) => void;
