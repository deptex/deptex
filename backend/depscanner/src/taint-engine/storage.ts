/**
 * Persistence layer for the taint engine. Two responsibilities:
 *
 *   1. writeFlows() — insert engine output into project_reachable_flows with
 *      reachability_source = 'taint_engine'. The classifier
 *      (updateReachabilityLevels) is source-agnostic; once flows land, the
 *      next pipeline step picks them up unchanged. Atom rows and engine
 *      rows coexist at the same coords because phase23.4's source-aware
 *      UNIQUE keys osv_id+rule_id (both NULL for engine + atom; the
 *      remaining (project_id, run_id, purl, entry_file, entry_line,
 *      sink_method) coords still vary per-flow).
 *
 *   2. writeRun() — upsert a row into taint_engine_runs that captures
 *      per-extraction telemetry. The circuit breaker reads this table to
 *      decide whether to engage the killswitch on the next extraction.
 *      Status transitions: 'running' (initial insert at step start) →
 *      'completed' | 'failed' | 'aborted' | 'skipped'.
 *
 * Both helpers swallow per-row errors to keep telemetry write failures from
 * cascading into engine hard-failures (the engine has its own failure mode
 * tracked separately in the runs table); the caller logs warnings.
 */

import type { Storage } from '../storage';
import type { Flow } from './flow';
import type { FilterResult } from './fp-filter';

const FLOW_BATCH_SIZE = 100;

/** Same UNIQUE key Phase 3 reachability_rules.ts upserts on. */
const REACHABLE_FLOWS_CONFLICT_KEY =
  'project_id,extraction_run_id,purl,entry_point_file,entry_point_line,sink_method,osv_id,rule_id';

export interface WriteFlowsResult {
  attempted: number;
  written: number;
  errors: string[];
}

export interface WriteFlowsOptions {
  projectId: string;
  extractionRunId: string;
  flows: Flow[];
  /**
   * Resolver from a Flow's sink/entry locations to the dependency that owns
   * the sink. M4 ships without dependency resolution (engine doesn't know
   * which package the sink callee resolves to without callgraph→sbom
   * matching) — pass `() => null` and we'll write rows with purl='internal'
   * and dependency_id=null, so the classifier still picks them up but they
   * don't promote a specific PDV. M5+ will plumb real dep resolution.
   */
  resolveDep?: (flow: Flow) => { purl: string; dependencyId: string | null } | null;
  /**
   * Optional per-flow AI filter verdicts (M7). Embedded into the
   * flow_nodes JSONB so admins can see why a borderline flow survived
   * (or, for rejected flows, this map skips them entirely upstream and
   * we never see them here). Keyed by Flow.id.
   */
  filterVerdicts?: Map<string, FilterResult>;
}

/**
 * Convert engine Flow records to project_reachable_flows row shape and
 * upsert in chunks. Returns counts + per-chunk errors (not thrown).
 */
export async function writeFlows(
  storage: Storage,
  options: WriteFlowsOptions,
): Promise<WriteFlowsResult> {
  const { projectId, extractionRunId, flows } = options;
  const resolveDep = options.resolveDep ?? defaultResolveDep;
  const verdicts = options.filterVerdicts;
  const errors: string[] = [];

  const rows: Record<string, unknown>[] = [];
  for (const flow of flows) {
    const dep = resolveDep(flow);
    if (!dep) continue;
    // Embed AI filter verdict (M7.5) into the JSONB so admins can see why
    // a borderline flow survived. We append a synthetic node rather than
    // adding a top-level column (keeps the project_reachable_flows schema
    // identical between engine + atom + reachability_rules sources).
    const v = verdicts?.get(flow.id);
    let flowNodesWithVerdict: unknown = flow.flow_nodes;
    if (v) {
      flowNodesWithVerdict = [
        ...flow.flow_nodes,
        v.verdict === 'kept_on_error'
          ? {
              kind: 'ai_filter_verdict',
              verdict: 'kept_on_error',
              reasoning: v.reasoning,
              error_message: v.errorMessage,
            }
          : {
              kind: 'ai_filter_verdict',
              verdict: v.verdict,
              reasoning: v.reasoning,
              confidence: v.confidence,
              model: v.model,
            },
      ];
    }
    rows.push({
      project_id: projectId,
      extraction_run_id: extractionRunId,
      purl: dep.purl,
      dependency_id: dep.dependencyId,
      reachability_source: 'taint_engine',
      // osv_id/rule_id stay NULL — taint engine flows aren't keyed to a
      // single CVE the way reachability_rules taint flows are. Under the
      // phase23.4 NULLS NOT DISTINCT UNIQUE this means engine rows dedup
      // on coords alone (matches atom semantics).
      osv_id: null,
      rule_id: null,
      flow_nodes: flowNodesWithVerdict,
      entry_point_file: flow.entry_point_file,
      entry_point_method: flow.entry_point_method,
      entry_point_line: flow.entry_point_line,
      // entry_point_tag feeds EPD's heuristic classifier the same way
      // reachability_rules does: framework-input:<class>. The taint engine
      // doesn't yet split by request-handler class (M5 may), so we tag all
      // engine flows with PUBLIC_UNAUTH which matches the spec's source
      // patterns (req.body etc).
      entry_point_tag: 'framework-input:PUBLIC_UNAUTH',
      sink_file: flow.sink_file,
      sink_method: flow.sink_method,
      sink_line: flow.sink_line,
      sink_is_external: flow.sink_is_external,
      flow_length: flow.flow_length,
      llm_prompt: null,
    });
  }

  let written = 0;
  for (let i = 0; i < rows.length; i += FLOW_BATCH_SIZE) {
    const chunk = rows.slice(i, i + FLOW_BATCH_SIZE);
    const { error } = await storage
      .from('project_reachable_flows')
      .upsert(chunk, {
        onConflict: REACHABLE_FLOWS_CONFLICT_KEY,
        ignoreDuplicates: true,
      });
    if (error) {
      errors.push(`chunk ${Math.floor(i / FLOW_BATCH_SIZE)}: ${error.message}`);
    } else {
      written += chunk.length;
    }
  }
  return { attempted: rows.length, written, errors };
}

function defaultResolveDep(_flow: Flow): { purl: string; dependencyId: string | null } | null {
  // M4 ships without callgraph→SBOM matching; tag the row as internal so
  // the classifier's per-PDV roll-up keys it under the synthetic 'internal'
  // PURL bucket. M5 will replace this with a real resolver mapping sink
  // callee to dep.
  //
  // INVARIANT (verified 2026-04-30 critical-review):
  // updateReachabilityLevels() in src/reachability.ts joins
  // project_reachable_flows to project_dependency_vulnerabilities by exact
  // purl match. 'pkg:internal/taint-engine' will never appear as a real
  // SBOM purl (the 'internal' namespace is a private Deptex sentinel),
  // so no PDV's reachability_level can be promoted by an engine flow until
  // M5 lands the real resolver. Until then, engine output is a write-only
  // shadow signal that downstream classification ignores. Do NOT change
  // this PURL to a public-namespace string without reading reachability.ts
  // — a collision would silently promote unrelated vulnerabilities.
  return { purl: 'pkg:internal/taint-engine', dependencyId: null };
}

export type TaintEngineRunStatus = 'running' | 'completed' | 'failed' | 'aborted' | 'skipped';

export interface WriteRunOptions {
  projectId: string;
  organizationId: string;
  extractionRunId: string;
  status: TaintEngineRunStatus;
  callgraphBuildMs?: number;
  taintPropagationMs?: number;
  aiSpecInferenceMs?: number;
  aiFpFilterMs?: number;
  totalMs?: number;
  flowsEmitted?: number;
  flowsAfterAiFilter?: number;
  aiCostUsd?: number;
  frameworksDetected?: string[];
  isTypedJsProject?: boolean | null;
  typedFilesPct?: number | null;
  vulnClassesEvaluated?: string[];
  errorCode?: string | null;
  errorMessage?: string | null;
}

/**
 * Upsert the per-extraction telemetry row. Idempotent on
 * (project_id, extraction_run_id) so the pipeline can write 'running'
 * at step start and 'completed'/'failed' on exit without dance.
 */
export async function writeRun(
  storage: Storage,
  options: WriteRunOptions,
): Promise<{ ok: boolean; error?: string }> {
  const isTerminal = options.status !== 'running';
  const row: Record<string, unknown> = {
    project_id: options.projectId,
    organization_id: options.organizationId,
    extraction_run_id: options.extractionRunId,
    status: options.status,
    callgraph_build_ms: options.callgraphBuildMs ?? null,
    taint_propagation_ms: options.taintPropagationMs ?? null,
    ai_spec_inference_ms: options.aiSpecInferenceMs ?? null,
    ai_fp_filter_ms: options.aiFpFilterMs ?? null,
    total_ms: options.totalMs ?? null,
    flows_emitted: options.flowsEmitted ?? 0,
    flows_after_ai_filter: options.flowsAfterAiFilter ?? 0,
    ai_cost_usd: options.aiCostUsd ?? 0,
    frameworks_detected: options.frameworksDetected ?? [],
    is_typed_js_project: options.isTypedJsProject ?? null,
    typed_files_pct: options.typedFilesPct ?? null,
    vuln_classes_evaluated: options.vulnClassesEvaluated ?? [],
    error_code: options.errorCode ?? null,
    error_message: options.errorMessage ?? null,
    completed_at: isTerminal ? new Date().toISOString() : null,
  };
  const { error } = await storage
    .from('taint_engine_runs')
    .upsert(row, { onConflict: 'project_id,extraction_run_id' });
  if (error) return { ok: false, error: error.message };
  return { ok: true };
}
