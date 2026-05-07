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
