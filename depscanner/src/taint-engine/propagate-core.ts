/**
 * Language-agnostic core of the worklist forward-propagation taint engine.
 *
 * Per-language drivers (TS in propagator.ts, Python in python/propagate.ts,
 * Java in java/propagate.ts, Go in go/propagate.ts) build the callgraph +
 * lowered IR for their language, then call `runWorklistAndAggregate` here.
 * The worklist algorithm + pattern matchers + flow aggregation are
 * identical across languages — extracted out to remove ~600 lines of
 * duplication and keep behaviour aligned.
 *
 * Algorithm:
 *   - Per-function state grows monotonically (paramTaints, returnTaint, sinkHits).
 *   - Worklist pops a function, runs its IR, propagates taint.
 *   - Convergence: state grows over a finite domain; bounded by maxIterations.
 *   - Aggregation: sink hits → Flow records, deduped by (source, sink, length, vuln class).
 */

import { createHash } from 'crypto';
import type {
  FrameworkSanitizer,
  FrameworkSink,
  FrameworkSource,
  FrameworkSpec,
} from './spec';
import type { DiagSink, DropRecord, Flow, FlowNode, SinkHit, TaintTrace } from './flow';
import { serializeTrace } from './flow';
import type { IrFunction, Step } from './ir';
import type { FunctionId, FunctionNode } from './types';

/** Per-function analysis state. Monotonically grown by the worklist. */
export interface FunctionState {
  funcNode: FunctionNode;
  ir: IrFunction;
  /** Externally seeded by callers: param index → taint trace. */
  paramTaints: Map<number, TaintTrace>;
  /** Published to callers; null = doesn't propagate taint to its return. */
  returnTaint: TaintTrace | null;
  /** Sinks hit during analysis; aggregated at the end. */
  sinkHits: SinkHit[];
  /** True if the function has been analyzed at least once with current state. */
  analyzed: boolean;
}

export interface RunWorklistOptions {
  stateById: Map<FunctionId, FunctionState>;
  callersByCallee: Map<FunctionId, Set<FunctionId>>;
  specs: FrameworkSpec[];
  /** Cap on flow path length for emitted Flows. Default 50. */
  maxPathLength?: number;
  /** Cap on worklist iterations as a runaway-loop safety net. Default: max(1000, 50× function count). */
  maxIterations?: number;
  onWarn?: (msg: string) => void;
  /**
   * Cancellation signal. Checked once per worklist iteration. When aborted,
   * the loop bails out after the current item finishes (no mid-pass aborts;
   * function analysis is sub-second so a clean iteration boundary is fine).
   * The result still carries the partial flows accumulated so far so the
   * caller can decide whether to surface them or discard.
   */
  signal?: AbortSignal;
  /**
   * Optional drop/sink-miss diagnostic emitter (Phase 1.2 of the
   * reachability-90-percent plan). When defined, the propagator emits one
   * `DropRecord` per (a) local-taint deletion and (b) spec-loaded sink that
   * matched the callee but found no tainted arg. Use the NDJSON writer in
   * `diag-writer.ts` to flush to disk, or pass an in-memory collector from
   * tests. Zero overhead when undefined — every emission site is guarded
   * by `if (diagSink)`.
   */
  diagSink?: DiagSink;
}

export interface RunWorklistResult {
  flows: Flow[];
  iterations: number;
  sourcesFound: number;
  sinksHit: number;
  stoppedEarly: boolean;
  /** True if the signal aborted mid-loop. flows[] is whatever had been aggregated so far. */
  aborted: boolean;
  propagationMs: number;
}

const SUBSUMED = Symbol('subsumed'); // sentinel for "no growth detected"

export function runWorklistAndAggregate(opts: RunWorklistOptions): RunWorklistResult {
  const maxPathLength = opts.maxPathLength ?? 50;
  const maxIterations = opts.maxIterations ?? Math.max(1000, opts.stateById.size * 50);
  const onWarn = opts.onWarn;
  const propStart = Date.now();

  const worklist = new Set<FunctionId>(opts.stateById.keys());
  let iterations = 0;
  let sourcesFound = 0;
  let stoppedEarly = false;
  let aborted = false;

  while (worklist.size > 0) {
    if (opts.signal?.aborted) {
      onWarn?.('taint propagator aborted via signal; stopping with partial state');
      aborted = true;
      stoppedEarly = true;
      break;
    }
    if (iterations >= maxIterations) {
      onWarn?.(`taint propagator hit maxIterations=${maxIterations}; stopping early`);
      stoppedEarly = true;
      break;
    }
    iterations++;
    const funcId = worklist.values().next().value as FunctionId;
    worklist.delete(funcId);
    const state = opts.stateById.get(funcId);
    if (!state) continue;

    const { changedReturn, sourcesAddedThisPass } = analyzeFunction({
      state,
      stateById: opts.stateById,
      specs: opts.specs,
      worklist,
      maxPathLength,
      diagSink: opts.diagSink,
    });
    sourcesFound += sourcesAddedThisPass;
    state.analyzed = true;
    if (changedReturn) {
      const callers = opts.callersByCallee.get(funcId);
      if (callers) {
        for (const c of callers) worklist.add(c);
      }
    }
  }
  if (stoppedEarly) onWarn?.('engine output may be incomplete due to early stop');

  const flows = aggregateFlows(opts.stateById, maxPathLength);

  return {
    flows,
    iterations,
    sourcesFound,
    sinksHit: countSinks(opts.stateById),
    stoppedEarly,
    aborted,
    propagationMs: Date.now() - propStart,
  };
}

interface AnalyzeArgs {
  state: FunctionState;
  stateById: Map<FunctionId, FunctionState>;
  specs: FrameworkSpec[];
  worklist: Set<FunctionId>;
  maxPathLength: number;
  diagSink?: DiagSink;
}

function emitDrop(
  diagSink: DiagSink | undefined,
  state: FunctionState,
  step: Step,
  reason: string,
  traceAtDrop: TaintTrace | null,
  sinkPattern?: string,
): void {
  if (!diagSink) return;
  let stepText: string;
  switch (step.kind) {
    case 'source':
      stepText = step.sourceText;
      break;
    case 'assign':
      stepText = `${step.target} = ${step.from ?? '?'}`;
      break;
    case 'call':
      stepText = step.callee.calleeText;
      break;
    case 'return':
      stepText = `return ${step.from ?? ''}`.trim();
      break;
  }
  const record: DropRecord = {
    reason,
    step_kind: step.kind,
    step_loc: { filePath: step.loc.filePath, line: step.loc.line, column: step.loc.column },
    step_text: stepText,
    function_id: String(state.funcNode.id),
    function_name: state.funcNode.name,
    trace_at_drop: traceAtDrop ? serializeTrace(traceAtDrop) : null,
    ...(sinkPattern ? { sink_pattern: sinkPattern } : {}),
  };
  diagSink(record);
}

interface AnalyzeOutcome {
  changedReturn: boolean;
  sourcesAddedThisPass: number;
}

function analyzeFunction(args: AnalyzeArgs): AnalyzeOutcome {
  const { state, stateById, specs, worklist, maxPathLength, diagSink } = args;
  const local = new Map<string, TaintTrace>();
  for (const [idx, trace] of state.paramTaints.entries()) {
    const name = state.ir.params[idx];
    if (name) local.set(name, trace);
  }

  let sourcesAddedThisPass = 0;
  // Track whether `return`-step taint grew this pass, but DO NOT bail out
  // mid-IR. The IR flattens branches into a straight-line list per design
  // (see ir.ts `walkStatement` — if/else/try/switch all flatten), so a
  // mid-body `return` step is regularly followed by post-return sinks,
  // sources, and calls from other branches. Bailing on the first growth
  // would silently drop those (bad FN). Convergence is still bounded by
  // worklist iterations + monotonic state growth.
  let changedReturn = false;

  for (const step of state.ir.steps) {
    switch (step.kind) {
      case 'source': {
        const matched = matchSourcePattern(step.sourceText, specs);
        if (matched) {
          local.set(step.target, makeTrace(matched, step));
          sourcesAddedThisPass++;
        } else if (step.weak) {
          // Weak source step (Ruby accessor-parity emission): only fire on
          // exact pattern match. Skip receiver-root fallback AND skip the
          // delete-on-no-match so the preceding `call` step's resolution
          // (sanitizer / sink / external fallback) is preserved. See the
          // `weak` field doc in ir.ts.
        } else {
          // No framework source matched. If the source text reads like a
          // field/index access on a known-tainted local (e.g. `q.name`,
          // `data[i]` where `q`/`data` was previously tainted), propagate
          // the receiver's taint forward instead of clearing — this is the
          // common case for handlers that bind an extractor to a local then
          // read its fields.
          const receiver = receiverRoot(step.sourceText);
          const trace = receiver ? local.get(receiver) : undefined;
          if (trace) {
            local.set(step.target, extendPath(trace, hopFromStep(step, 'source'), maxPathLength));
          } else {
            emitDrop(diagSink, state, step, 'source-no-match-no-receiver', local.get(step.target) ?? null);
            local.delete(step.target);
          }
        }
        break;
      }
      case 'assign': {
        if (step.from && local.has(step.from)) {
          const t = local.get(step.from)!;
          local.set(step.target, extendPath(t, hopFromStep(step, 'assign'), maxPathLength));
        } else {
          emitDrop(diagSink, state, step, 'assign-from-untainted', local.get(step.target) ?? null);
          local.delete(step.target);
        }
        break;
      }
      case 'call': {
        const callSourceMatch = matchCallSourcePattern(step.callee.calleeText, specs);
        if (callSourceMatch && step.target) {
          local.set(step.target, makeTraceFromCall(callSourceMatch, step));
          sourcesAddedThisPass++;
          break;
        }

        const sanMatch = matchSanitizerPattern(step.callee.calleeText, specs);
        if (sanMatch) {
          if (step.target) local.delete(step.target);
          break;
        }

        const sinkMatch = matchSinkPattern(step.callee.calleeText, specs);
        if (sinkMatch) {
          // Indices to check for taint at this call site.
          // - empty spec argument_indices → check every position (existing behaviour)
          // - non-empty + no kwargs → check the spec-declared positions only
          // - non-empty + kwargs present → ALSO check every kwarg position.
          //   This over-approximates when a Python (or other kwarg-supporting
          //   language) caller binds args by name, where the spec's positional
          //   indexing wouldn't otherwise line up. False positives here are
          //   caught by Gate 3 fixture round-trip in rule-generator validation;
          //   the engine prefers extra recall over missed flows.
          let idxs: number[];
          if (sinkMatch.argument_indices.length === 0) {
            idxs = step.args.map((_, i) => i);
          } else if (step.kwargIndices && step.kwargIndices.length > 0) {
            const widened = new Set<number>(sinkMatch.argument_indices);
            for (const k of step.kwargIndices) widened.add(k);
            idxs = Array.from(widened);
          } else {
            idxs = sinkMatch.argument_indices;
          }
          const seenArgs = new Set<string>();
          let anyHit = false;
          for (const i of idxs) {
            const argName = step.args[i];
            if (!argName) continue;
            // Dedup: with kwarg widening, a positional index and a kwarg index
            // could point at the same local var; emit one hit, not two.
            if (seenArgs.has(argName)) continue;
            const trace = local.get(argName);
            if (!trace) continue;
            seenArgs.add(argName);
            anyHit = true;
            const hit: SinkHit = {
              sink: sinkMatch,
              trace: extendPath(trace, hopFromStep(step, 'sink'), maxPathLength),
              hit_node: hopFromStep(step, 'sink'),
            };
            state.sinkHits.push(hit);
          }
          if (!anyHit) {
            // Spec sink matched the callee but none of the checked arg
            // positions held tainted locals. This is the dominant "engine
            // saw the sink but taint didn't reach it" diagnostic — emit one
            // record so the diag dump explains why the CVE didn't validate.
            emitDrop(diagSink, state, step, 'sink-loaded-no-tainted-arg', null, sinkMatch.pattern);
          }
        }

        if (step.callee.kind === 'internal') {
          const callee = stateById.get(step.callee.functionId);
          if (callee) {
            for (let i = 0; i < step.args.length; i++) {
              const argName = step.args[i];
              if (!argName) continue;
              const argTrace = local.get(argName);
              if (!argTrace) continue;
              const augmented = extendPath(argTrace, hopFromStep(step, 'call'), maxPathLength);
              const grew = mergeParamTaint(callee, i, augmented);
              if (grew) worklist.add(callee.funcNode.id);
            }
            if (step.target && callee.returnTaint) {
              local.set(
                step.target,
                extendPath(callee.returnTaint, hopFromStep(step, 'return'), maxPathLength),
              );
            } else if (step.target) {
              emitDrop(diagSink, state, step, 'call-internal-no-return-taint', null);
              local.delete(step.target);
            }
          } else if (step.target) {
            emitDrop(diagSink, state, step, 'call-internal-callee-missing', null);
            local.delete(step.target);
          }
          break;
        }

        // External / unresolved: over-approximate.
        if (step.target) {
          let firstTainted: TaintTrace | null = null;
          for (const a of step.args) {
            if (!a) continue;
            const t = local.get(a);
            if (t) {
              firstTainted = t;
              break;
            }
          }
          if (firstTainted) {
            local.set(
              step.target,
              extendPath(firstTainted, hopFromStep(step, 'call'), maxPathLength),
            );
          } else if (step.args.length === 0 && local.has(step.target)) {
            // 0-arg unresolved method call (e.g. Ruby `params.id` parsed as
            // a call, no args, sanitizer/sink didn't match). The Ruby
            // lowerer emits a *weak* source step right before this call
            // step to encode the accessor-read semantics — if that already
            // set target's taint, don't clobber it here. For non-Ruby
            // lowerers (which don't emit weak source steps), this branch is
            // unreachable because they don't seed target before the call.
            // Leave target's existing trace in place.
          } else {
            // Receiver-taint pass-through: when an unresolved/external call
            // takes the shape `recv.method(...)` (or `recv::method`, etc.)
            // and the receiver is a currently-tainted local, propagate that
            // taint to the call's return. Covers common pass-through chains
            // like `keyData.getBytes()`, `body.toString()`, `req.getReader()`
            // — none of which match a positional arg but all of which carry
            // the receiver's taint through to the result.
            //
            // Scoping (per the maven-recall-diagnosis 2026-05-12 design):
            //   - Only reached AFTER sink/sanitizer/source matches above
            //     have returned/break'd, so we never re-taint past a
            //     sanitizer or shadow a sink hit.
            //   - receiverRoot() returns null for literals / non-identifier
            //     receivers (`"foo".toString()` won't propagate; nothing to
            //     propagate from).
            //   - Receiver must be an existing tainted local — `String.valueOf(x)`
            //     where `String` is a class name is a no-op.
            const recv = receiverRoot(step.callee.calleeText);
            const recvTrace = recv ? local.get(recv) : undefined;
            if (recvTrace) {
              local.set(
                step.target,
                extendPath(recvTrace, hopFromStep(step, 'call'), maxPathLength),
              );
            } else {
              emitDrop(diagSink, state, step, 'call-external-no-arg-no-receiver', null);
              local.delete(step.target);
            }
          }
        }
        break;
      }
      case 'return': {
        const trace = step.from ? local.get(step.from) : null;
        if (trace) {
          const augmented = extendPath(trace, hopFromStep(step, 'return'), maxPathLength);
          if (subsumes(state.returnTaint, augmented) === SUBSUMED) {
            // already subsumed
          } else {
            state.returnTaint = augmented;
            changedReturn = true;
          }
        }
        break;
      }
    }
  }

  return { changedReturn, sourcesAddedThisPass };
}

function mergeParamTaint(callee: FunctionState, paramIdx: number, trace: TaintTrace): boolean {
  const existing = callee.paramTaints.get(paramIdx);
  if (subsumes(existing, trace) === SUBSUMED) return false;
  callee.paramTaints.set(paramIdx, trace);
  return true;
}

function subsumes(existing: TaintTrace | null | undefined, incoming: TaintTrace): typeof SUBSUMED | 'grew' {
  if (!existing) return 'grew';
  if (existing.taint_kind !== incoming.taint_kind) return 'grew';
  if (existing.source.pattern !== incoming.source.pattern) return 'grew';
  const e0 = existing.path[0];
  const i0 = incoming.path[0];
  if (!e0 || !i0) return 'grew';
  if (e0.filePath === i0.filePath && e0.line === i0.line) return SUBSUMED;
  return 'grew';
}

function makeTraceFromCall(source: FrameworkSource, step: Extract<Step, { kind: 'call' }>): TaintTrace {
  const node: FlowNode = {
    filePath: step.loc.filePath,
    line: step.loc.line,
    column: step.loc.column,
    label: step.callee.calleeText,
    kind: 'source',
  };
  return { taint_kind: source.taint_kind, source, path: [node] };
}

function makeTrace(source: FrameworkSource, step: Extract<Step, { kind: 'source' }>): TaintTrace {
  const node: FlowNode = {
    filePath: step.loc.filePath,
    line: step.loc.line,
    column: step.loc.column,
    label: step.sourceText,
    kind: 'source',
  };
  return { taint_kind: source.taint_kind, source, path: [node] };
}

function extendPath(trace: TaintTrace, hop: FlowNode, maxPathLength: number): TaintTrace {
  if (trace.path.length >= maxPathLength) return trace;
  const last = trace.path[trace.path.length - 1];
  if (last && last.filePath === hop.filePath && last.line === hop.line && last.kind === hop.kind) {
    return trace;
  }
  return { ...trace, path: [...trace.path, hop] };
}

function hopFromStep(step: Step, kind: FlowNode['kind']): FlowNode {
  let label: string;
  switch (step.kind) {
    case 'source':
      label = step.sourceText;
      break;
    case 'assign':
      label = `${step.target} = ${step.from ?? '?'}`;
      break;
    case 'call':
      label = step.callee.calleeText;
      break;
    case 'return':
      label = `return ${step.from ?? ''}`.trim();
      break;
  }
  return { filePath: step.loc.filePath, line: step.loc.line, column: step.loc.column, label, kind };
}

/**
 * Given a source-step text like `q.name`, `q[idx]`, `obj->prop`, or
 * `Class::field`, return the leading identifier (the "receiver") so
 * propagate-core can fall back to receiver-taint when no framework
 * source pattern matches.
 *
 * Returns null when the text is a single identifier (no field/index/scope
 * access) — in that case a source-step with no match means "this is just a
 * read of an untainted local", not "field access on tainted local".
 */
export function receiverRoot(text: string): string | null {
  const m = text.match(/^([A-Za-z_][A-Za-z0-9_]*)([.\[(]|->|::)/);
  return m ? m[1] : null;
}

function matchSourcePattern(text: string, specs: FrameworkSpec[]): FrameworkSource | null {
  for (const spec of specs) {
    for (const src of spec.sources) {
      if (src.pattern.endsWith('(*)')) continue;
      if (src.pattern.endsWith('.*')) {
        const prefix = src.pattern.slice(0, -2);
        if (text === prefix || text.startsWith(prefix + '.') || text.startsWith(prefix + '[')) {
          return src;
        }
      } else if (text === src.pattern) {
        return src;
      }
    }
  }
  return null;
}

function matchCallSourcePattern(calleeText: string, specs: FrameworkSpec[]): FrameworkSource | null {
  for (const spec of specs) {
    for (const src of spec.sources) {
      if (!src.pattern.endsWith('(*)')) continue;
      if (matchesCallPattern(src.pattern, calleeText)) return src;
    }
  }
  return null;
}

function matchSinkPattern(calleeText: string, specs: FrameworkSpec[]): FrameworkSink | null {
  for (const spec of specs) {
    for (const sink of spec.sinks) {
      if (matchesCallPattern(sink.pattern, calleeText)) return sink;
    }
  }
  return null;
}

function matchSanitizerPattern(calleeText: string, specs: FrameworkSpec[]): FrameworkSanitizer | null {
  for (const spec of specs) {
    for (const san of spec.sanitizers) {
      if (matchesCallPattern(san.pattern, calleeText)) return san;
    }
  }
  return null;
}

export function matchesCallPattern(pattern: string, calleeText: string): boolean {
  const p = pattern.endsWith('(*)') ? pattern.slice(0, -3) : pattern;
  // Wildcard receiver: `*.method`, `*->method`, `*::method` — match any receiver
  // calling `method` via the spec-declared separator. Languages emit calleeText
  // using their native separator (PHP/symfony uses `->`, Rust uses `::`, JS/Ruby/
  // Python use `.`), so the matcher honors whichever the YAML author wrote.
  if (p.startsWith('*.') || p.startsWith('*->') || p.startsWith('*::')) {
    const suffix = p.slice(1);
    return calleeText.endsWith(suffix);
  }
  if (calleeText === p) return true;
  const last = p.split('.').pop();
  if (last && calleeText === last) return true;
  return false;
}

function aggregateFlows(stateById: Map<FunctionId, FunctionState>, maxPathLength: number): Flow[] {
  const out: Flow[] = [];
  const seen = new Set<string>();
  for (const state of stateById.values()) {
    for (const hit of state.sinkHits) {
      const flow = sinkHitToFlow(hit, state.funcNode, maxPathLength);
      if (seen.has(flow.id)) continue;
      seen.add(flow.id);
      out.push(flow);
    }
  }
  return out;
}

function countSinks(stateById: Map<FunctionId, FunctionState>): number {
  let n = 0;
  for (const s of stateById.values()) n += s.sinkHits.length;
  return n;
}

function sinkHitToFlow(hit: SinkHit, sinkContainingFunc: FunctionNode, maxPathLength: number): Flow {
  const path0 = hit.trace.path[0];
  const sinkNode = hit.hit_node;
  const flowNodes = hit.trace.path.slice(0, maxPathLength);
  if (flowNodes.length === 0 || flowNodes[flowNodes.length - 1].kind !== 'sink') {
    flowNodes.push(sinkNode);
  }
  const idHash = createHash('sha1');
  idHash.update(`${path0.filePath}:${path0.line}|${sinkNode.filePath}:${sinkNode.line}|${flowNodes.length}|${hit.sink.vuln_class}`);

  return {
    id: idHash.digest('hex').slice(0, 16),
    vuln_class: hit.sink.vuln_class,
    taint_kind: hit.trace.taint_kind,
    entry_point_file: path0.filePath,
    entry_point_line: path0.line,
    entry_point_method: sinkContainingFunc.name,
    entry_point_pattern: hit.trace.source.pattern,
    sink_file: sinkNode.filePath,
    sink_line: sinkNode.line,
    sink_method: sinkNode.label,
    sink_pattern: hit.sink.pattern,
    sink_is_external: false,
    flow_nodes: flowNodes,
    flow_length: flowNodes.length,
    source_description: hit.trace.source.description,
    sink_description: hit.sink.description,
    engine_confidence: scoreEngineConfidence(hit, flowNodes),
    // Phase 6.5: stamp the CVE-targeted spec's osv_id onto the flow.
    // Undefined when the sink came from a framework-generic spec.
    osv_id: hit.sink.osv_id,
  };
}

/**
 * Heuristic confidence score for a flow ∈ [0,1]. Drives M7's per-flow AI
 * filter: flows below the org's configured threshold (default 0.7) are
 * routed to the LLM check; flows above are kept verbatim.
 *
 * The deterministic engine doesn't track aliasing or branching precisely,
 * so longer flows and wildcard / external sinks are noisier. Clamped to
 * [0.05, 0.99] so we never claim absolute certainty and never write a
 * literal 0 (which the threshold check would treat as an unconditional
 * kept-no-filter signal).
 */
function scoreEngineConfidence(hit: SinkHit, flowNodes: FlowNode[]): number {
  let score = 1.0;
  const hops = flowNodes.length;
  if (hops > 3) score -= Math.min(0.4, (hops - 3) * 0.1);
  if (hit.sink.pattern.startsWith('*.')) score -= 0.2;
  if (hit.hit_node.kind === 'sink' && /node_modules/.test(hit.hit_node.filePath)) {
    score -= 0.1;
  }
  if (score < 0.05) score = 0.05;
  if (score > 0.99) score = 0.99;
  return Number(score.toFixed(2));
}

/**
 * Helper: build a callers-by-callee index from a callgraph's edges. Every
 * language driver needs this same step before calling the worklist core.
 */
export function buildCallersByCallee(
  edges: Array<{ callerId: FunctionId; calleeId: FunctionId | null | undefined }>,
): Map<FunctionId, Set<FunctionId>> {
  const out = new Map<FunctionId, Set<FunctionId>>();
  for (const edge of edges) {
    if (!edge.calleeId) continue;
    let set = out.get(edge.calleeId);
    if (!set) {
      set = new Set();
      out.set(edge.calleeId, set);
    }
    set.add(edge.callerId);
  }
  return out;
}
