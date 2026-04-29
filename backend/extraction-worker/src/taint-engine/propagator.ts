/**
 * Worklist forward-propagation taint engine.
 *
 * Algorithm sketch:
 *   1. Build the callgraph + program (M1 substrate).
 *   2. Lower every function to IR (lazy, cached per FunctionId).
 *   3. Per-function analysis state grows monotonically:
 *        - paramTaints[funcId] : Map<paramIndex, TaintTrace> — externally seeded by callers
 *        - returnTaint[funcId] : TaintTrace | null — published to callers when grown
 *        - sinkHits[funcId]    : SinkHit[] — accumulated; deduped at flow emission
 *   4. Worklist pops a function, runs the per-step interpreter:
 *        - source step with target T, matching a FrameworkSource pattern
 *            → localTaints[T] = new TaintTrace anchored at this step
 *        - assign step T <- F → propagate localTaints[F] to T (or clear T)
 *        - call step (target T = callee(args))
 *            → callee is sanitizer:  T becomes clean
 *            → callee is sink:        emit SinkHit if any matched arg is tainted
 *            → callee is internal:    seed callee's paramTaints from arg taints,
 *                                     enqueue callee if grown; on return, T inherits
 *                                     callee's returnTaint augmented with this hop
 *            → callee is external/unresolved: conservatively taint T iff any arg tainted
 *        - return step → if returned var is tainted, grow funcId's returnTaint and
 *                       enqueue ALL callers (their assignment targets need re-derivation)
 *   5. Convergence: state only grows over a finite domain (#functions × #params ×
 *      taint kinds); the worklist drains. We additionally bound by maxPasses as a
 *      safety net for pathological IRs.
 *   6. Aggregation: SinkHits → Flows, deduped by (source loc, sink loc, path-shape hash).
 *
 * What M2 deliberately does NOT do:
 *   - Aliasing: assignment is by-name; `a = b; b.x = tainted` doesn't taint `a.x`.
 *   - Control-flow joins: branches are flattened (over-approximation, sound).
 *   - Async/promise modeling: `.then(h)` doesn't connect h's param to the promise's
 *     resolved value. `await fooReturningTainted()` IS handled (await unwraps).
 *   - Object-field taint: tainting `x` taints `x` only, not `x.foo`. The lowerer
 *     records property-access source patterns directly, so common request-body
 *     access still works.
 */

import { createHash } from 'crypto';
import * as path from 'path';
import * as ts from 'typescript';
import { buildCallgraphContext } from './callgraph';
import { lowerFunction, type IrFunction, type Step } from './ir';
import type { Callgraph, FunctionId, FunctionNode } from './types';
import type {
  FrameworkSanitizer,
  FrameworkSink,
  FrameworkSource,
  FrameworkSpec,
  TaintKind,
  VulnClass,
} from './spec';
import type { Flow, FlowNode, SinkHit, TaintTrace } from './flow';

export interface PropagateOptions {
  rootDir: string;
  specs: FrameworkSpec[];
  /** Cap on flow path length for emitted Flows. Default 50. */
  maxPathLength?: number;
  /** Cap on worklist iterations as a runaway-loop safety net. Default: 50× function count. */
  maxIterations?: number;
  onWarn?: (msg: string) => void;
}

export interface PropagateStats {
  functionsAnalyzed: number;
  worklistIterations: number;
  sourcesFound: number;
  sinksHit: number;
  flowsEmitted: number;
  callgraphMs: number;
  loweringMs: number;
  propagationMs: number;
  totalMs: number;
}

export interface PropagateResult {
  flows: Flow[];
  callgraph: Callgraph;
  stats: PropagateStats;
}

/**
 * Per-function analysis state. Monotonically grown.
 */
interface FunctionState {
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

const SUBSUMED = Symbol('subsumed'); // sentinel for "no growth detected"

export async function propagate(options: PropagateOptions): Promise<PropagateResult> {
  const t0 = Date.now();
  const maxPathLength = options.maxPathLength ?? 50;
  const onWarn = options.onWarn;

  // 1. Callgraph
  const cgStart = Date.now();
  const ctx = await buildCallgraphContext({ rootDir: options.rootDir, onWarn });
  const callgraphMs = Date.now() - cgStart;
  const { callgraph, program, declarationToNodeId, nodeIdToDeclaration } = ctx;

  // 2. Lower every function
  const loweringStart = Date.now();
  const checker = program.getTypeChecker();
  const stateById = new Map<FunctionId, FunctionState>();
  for (const node of callgraph.nodes) {
    const decl = nodeIdToDeclaration.get(node.id);
    if (!decl) continue;
    const sourceFile = decl.getSourceFile();
    const ir = lowerFunction(node.id, decl, {
      filePath: node.filePath,
      sourceFile,
      checker,
      declarationToNodeId,
      pickFunctionDecl: (sym) => pickFunctionDecl(sym),
    });
    stateById.set(node.id, {
      funcNode: node,
      ir,
      paramTaints: new Map(),
      returnTaint: null,
      sinkHits: [],
      analyzed: false,
    });
  }
  const loweringMs = Date.now() - loweringStart;

  // Index callers per callee (for return-taint propagation).
  const callersByCallee = new Map<FunctionId, Set<FunctionId>>();
  for (const edge of callgraph.edges) {
    if (!edge.calleeId) continue;
    let set = callersByCallee.get(edge.calleeId);
    if (!set) {
      set = new Set();
      callersByCallee.set(edge.calleeId, set);
    }
    set.add(edge.callerId);
  }

  // 3. Worklist propagation
  const propStart = Date.now();
  const worklist = new Set<FunctionId>(stateById.keys());
  const maxIterations = options.maxIterations ?? Math.max(1000, stateById.size * 50);
  let iterations = 0;
  let sourcesFound = 0;
  let stoppedEarly = false;

  while (worklist.size > 0) {
    if (iterations >= maxIterations) {
      onWarn?.(`taint propagator hit maxIterations=${maxIterations}; stopping early`);
      stoppedEarly = true;
      break;
    }
    iterations++;
    // Pop one. Set iteration order is insertion order; we just take the first.
    const funcId = worklist.values().next().value as FunctionId;
    worklist.delete(funcId);
    const state = stateById.get(funcId);
    if (!state) continue;

    const { changedReturn, sourcesAddedThisPass } = analyzeFunction({
      state,
      stateById,
      callersByCallee,
      specs: options.specs,
      worklist,
      maxPathLength,
    });
    sourcesFound += sourcesAddedThisPass;
    state.analyzed = true;
    if (changedReturn) {
      const callers = callersByCallee.get(funcId);
      if (callers) {
        for (const c of callers) worklist.add(c);
      }
    }
  }
  const propagationMs = Date.now() - propStart;
  if (stoppedEarly) {
    onWarn?.('engine output may be incomplete due to early stop');
  }

  // 4. Aggregate sinks → flows, dedupe.
  const flows = aggregateFlows(stateById, maxPathLength);

  return {
    flows,
    callgraph,
    stats: {
      functionsAnalyzed: stateById.size,
      worklistIterations: iterations,
      sourcesFound,
      sinksHit: countSinks(stateById),
      flowsEmitted: flows.length,
      callgraphMs,
      loweringMs,
      propagationMs,
      totalMs: Date.now() - t0,
    },
  };
}

function pickFunctionDecl(symbol: ts.Symbol): ts.Node | undefined {
  const decls = symbol.declarations;
  if (!decls || decls.length === 0) return undefined;
  for (const d of decls) {
    if (
      ts.isFunctionDeclaration(d) ||
      ts.isFunctionExpression(d) ||
      ts.isArrowFunction(d) ||
      ts.isMethodDeclaration(d) ||
      ts.isConstructorDeclaration(d) ||
      ts.isGetAccessorDeclaration(d) ||
      ts.isSetAccessorDeclaration(d) ||
      ts.isMethodSignature(d)
    ) {
      return d;
    }
  }
  for (const d of decls) {
    if (ts.isVariableDeclaration(d) && d.initializer) {
      const init = d.initializer;
      if (ts.isFunctionExpression(init) || ts.isArrowFunction(init)) return init;
    }
    if (ts.isPropertyAssignment(d)) {
      const init = d.initializer;
      if (ts.isFunctionExpression(init) || ts.isArrowFunction(init)) return init;
    }
    if (ts.isPropertyDeclaration(d) && d.initializer) {
      const init = d.initializer;
      if (ts.isFunctionExpression(init) || ts.isArrowFunction(init)) return init;
    }
  }
  return decls[0];
}

interface AnalyzeArgs {
  state: FunctionState;
  stateById: Map<FunctionId, FunctionState>;
  callersByCallee: Map<FunctionId, Set<FunctionId>>;
  specs: FrameworkSpec[];
  worklist: Set<FunctionId>;
  maxPathLength: number;
}

interface AnalyzeOutcome {
  changedReturn: boolean;
  sourcesAddedThisPass: number;
}

function analyzeFunction(args: AnalyzeArgs): AnalyzeOutcome {
  const { state, stateById, specs, worklist, maxPathLength } = args;
  const local = new Map<string, TaintTrace>();
  // Seed locals from incoming param taints.
  for (const [idx, trace] of state.paramTaints.entries()) {
    const name = state.ir.params[idx];
    if (name) local.set(name, trace);
  }

  let sourcesAddedThisPass = 0;

  for (const step of state.ir.steps) {
    switch (step.kind) {
      case 'source': {
        const matched = matchSourcePattern(step.sourceText, specs);
        if (matched) {
          local.set(step.target, makeTrace(matched, step));
          sourcesAddedThisPass++;
        } else {
          // Property/element access of an untainted root — the target becomes untainted.
          local.delete(step.target);
        }
        break;
      }
      case 'assign': {
        if (step.from && local.has(step.from)) {
          const t = local.get(step.from)!;
          local.set(step.target, extendPath(t, hopFromStep(step, 'assign'), maxPathLength));
        } else {
          local.delete(step.target);
        }
        break;
      }
      case 'call': {
        // Detect call-shape source: source patterns ending in `(*)` (e.g.
        // `request.json(*)`, `c.req.query(*)`, `searchParams.get(*)`) taint
        // the call's return value. This covers Next.js App Router /
        // Hono / standard Web API accessors that aren't property reads.
        // Sources win over the rest — if a call is a source, we don't
        // also try to match it as a sink/sanitizer.
        const callSourceMatch = matchCallSourcePattern(step.callee.calleeText, specs);
        if (callSourceMatch && step.target) {
          local.set(step.target, makeTraceFromCall(callSourceMatch, step));
          sourcesAddedThisPass++;
          break;
        }

        // Detect sanitizer: if callee matches a sanitizer pattern, the target
        // is clean (regardless of arg taint). Sanitizer wins over sink/internal.
        const sanMatch = matchSanitizerPattern(step.callee.calleeText, specs);
        if (sanMatch) {
          if (step.target) local.delete(step.target);
          break;
        }

        // Detect sink: if any arg in argument_indices (or any if list empty) is tainted, emit hit.
        const sinkMatch = matchSinkPattern(step.callee.calleeText, specs);
        if (sinkMatch) {
          const idxs = sinkMatch.argument_indices.length > 0
            ? sinkMatch.argument_indices
            : step.args.map((_, i) => i);
          for (const i of idxs) {
            const argName = step.args[i];
            if (!argName) continue;
            const trace = local.get(argName);
            if (!trace) continue;
            const hit: SinkHit = {
              sink: sinkMatch,
              trace: extendPath(trace, hopFromStep(step, 'sink'), maxPathLength),
              hit_node: hopFromStep(step, 'sink'),
            };
            state.sinkHits.push(hit);
          }
        }

        // Internal callee: propagate arg taints into its paramTaints; inherit returnTaint.
        if (step.callee.kind === 'internal') {
          const callee = stateById.get(step.callee.functionId);
          if (callee) {
            // Seed callee paramTaints from any tainted positional args.
            for (let i = 0; i < step.args.length; i++) {
              const argName = step.args[i];
              if (!argName) continue;
              const argTrace = local.get(argName);
              if (!argTrace) continue;
              const augmented = extendPath(argTrace, hopFromStep(step, 'call'), maxPathLength);
              const grew = mergeParamTaint(callee, i, augmented);
              if (grew) worklist.add(callee.funcNode.id);
            }
            // Inherit callee's published returnTaint into target var (if any).
            if (step.target && callee.returnTaint) {
              local.set(
                step.target,
                extendPath(callee.returnTaint, hopFromStep(step, 'return'), maxPathLength),
              );
            } else if (step.target) {
              local.delete(step.target);
            }
          } else if (step.target) {
            local.delete(step.target);
          }
          break;
        }

        // External / unresolved: over-approximate — if any tainted arg flows in,
        // taint the target. The trace records the strongest (first) tainted arg.
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
          } else {
            local.delete(step.target);
          }
        }
        break;
      }
      case 'return': {
        const trace = step.from ? local.get(step.from) : null;
        if (trace) {
          const augmented = extendPath(trace, hopFromStep(step, 'return'), maxPathLength);
          if (subsumes(state.returnTaint, augmented) === SUBSUMED) {
            // already subsumed, no-op
          } else {
            state.returnTaint = augmented;
            return { changedReturn: true, sourcesAddedThisPass };
          }
        }
        break;
      }
    }
  }

  return { changedReturn: false, sourcesAddedThisPass };
}

/** Merge a new trace into a callee's paramTaints; returns true if grew. */
function mergeParamTaint(callee: FunctionState, paramIdx: number, trace: TaintTrace): boolean {
  const existing = callee.paramTaints.get(paramIdx);
  if (subsumes(existing, trace) === SUBSUMED) return false;
  callee.paramTaints.set(paramIdx, trace);
  return true;
}

/**
 * Returns SUBSUMED if `incoming` carries no new taint beyond `existing`. Used
 * to decide whether to re-enqueue a callee or callers. Conservative: if either
 * the kind or the source location differs, we treat as growing.
 */
function subsumes(existing: TaintTrace | null | undefined, incoming: TaintTrace): typeof SUBSUMED | 'grew' {
  if (!existing) return 'grew';
  if (existing.taint_kind !== incoming.taint_kind) return 'grew';
  if (existing.source.pattern !== incoming.source.pattern) return 'grew';
  // Same source kind + pattern + first-hop file:line as the existing trace
  // means we'd just rediscover the same flow — subsumed.
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
  return {
    taint_kind: source.taint_kind,
    source,
    path: [node],
  };
}

function makeTrace(source: FrameworkSource, step: Extract<Step, { kind: 'source' }>): TaintTrace {
  const node: FlowNode = {
    filePath: step.loc.filePath,
    line: step.loc.line,
    column: step.loc.column,
    label: step.sourceText,
    kind: 'source',
  };
  return {
    taint_kind: source.taint_kind,
    source,
    path: [node],
  };
}

function extendPath(trace: TaintTrace, hop: FlowNode, maxPathLength: number): TaintTrace {
  if (trace.path.length >= maxPathLength) return trace;
  // Don't add a hop identical to the last one (avoids self-loops in trivial copies).
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
  return {
    filePath: step.loc.filePath,
    line: step.loc.line,
    column: step.loc.column,
    label,
    kind,
  };
}

function matchSourcePattern(text: string, specs: FrameworkSpec[]): FrameworkSource | null {
  for (const spec of specs) {
    for (const src of spec.sources) {
      // Call-shape source patterns (`request.json(*)`) only match call
      // expressions; they're checked separately in matchCallSourcePattern
      // and skipped here so the same pattern doesn't double-match a
      // property access whose text happens to share the prefix.
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

/**
 * Match call-shape source patterns (`request.json(*)`, `c.req.query(*)`,
 * `searchParams.get(*)`) against a call expression's callee text. The call's
 * return value is then treated as freshly tainted with the source's
 * taint_kind. Used by Next.js App Router + Hono + standard Web APIs that
 * don't expose request data via property access.
 */
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

function matchesCallPattern(pattern: string, calleeText: string): boolean {
  const p = pattern.endsWith('(*)') ? pattern.slice(0, -3) : pattern;
  // Wildcard receiver: `*.query` matches any callee ending in `.query`
  // (e.g. `pool.query`, `database.query`, `this.db.query`). Useful for
  // ORM/DB libs where the receiver name is the user's variable.
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // ".query"
    return calleeText.endsWith(suffix);
  }
  if (calleeText === p) return true;
  // Last-segment match: pattern `child_process.exec` also matches a callee
  // imported as the bare `exec` identifier — covers the common
  // `import { exec } from 'child_process'` shape since the lowerer doesn't
  // follow import bindings textually.
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
  // The hit_node was already appended into the trace by the propagator, so don't
  // duplicate it here. Final hop kind will be 'sink' from the trace tail.
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
    entry_point_method: sinkContainingFunc.name, // best-effort — refined in M4 with entry_point classifier
    entry_point_pattern: hit.trace.source.pattern,
    sink_file: sinkNode.filePath,
    sink_line: sinkNode.line,
    sink_method: sinkNode.label,
    sink_pattern: hit.sink.pattern,
    sink_is_external: false, // M4 sets this from the callgraph edge resolution
    flow_nodes: flowNodes,
    flow_length: flowNodes.length,
    source_description: hit.trace.source.description,
    sink_description: hit.sink.description,
  };
}

// path module is required by createHash usage in some bundlers; quiet unused-imports.
void path;
