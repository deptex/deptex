/**
 * Java driver for the taint engine's worklist propagator.
 *
 * Thin orchestrator: builds the Java callgraph + lowers each method to IR,
 * then hands off to the language-agnostic core in ../propagate-core.ts.
 */

import { lowerJavaMethod } from './ir';
import { buildJavaCallgraphContext, type JavaCallgraphContext } from './callgraph';
import { filterSpecsByLanguage, type FrameworkSpec } from '../spec';
import type { Flow } from '../flow';
import type { IrFunction } from '../ir';
import type { Callgraph, FunctionId } from '../types';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from '../propagate-core';

export interface PropagateJavaOptions {
  rootDir: string;
  specs: FrameworkSpec[];
  maxPathLength?: number;
  maxIterations?: number;
  onWarn?: (msg: string) => void;
  /** Forwarded to the worklist core; aborts cleanly between iterations. */
  signal?: AbortSignal;
}

export interface PropagateJavaStats {
  functionsAnalyzed: number;
  worklistIterations: number;
  sourcesFound: number;
  sinksHit: number;
  flowsEmitted: number;
  callgraphMs: number;
  loweringMs: number;
  propagationMs: number;
  totalMs: number;
  /** True when the worklist stopped at the iteration cap before the fixpoint
   *  — flows are PARTIAL. See PropagateResult.stats.stoppedEarly. */
  stoppedEarly?: boolean;
}

export interface PropagateJavaResult {
  flows: Flow[];
  callgraph: Callgraph;
  /** True when the worklist aborted mid-loop on the cancellation signal. */
  aborted: boolean;
  stats: PropagateJavaStats;
  /** See PropagateResult.irFunctions. */
  irFunctions?: IrFunction[];
}

export async function propagateJava(options: PropagateJavaOptions): Promise<PropagateJavaResult> {
  const t0 = Date.now();
  const onWarn = options.onWarn;
  const specs = filterSpecsByLanguage(options.specs, 'java');

  // 1. Callgraph (Java-specific)
  const cgStart = Date.now();
  const ctx: JavaCallgraphContext = await buildJavaCallgraphContext(options.rootDir);
  const callgraphMs = Date.now() - cgStart;
  const { callgraph, methodById } = ctx;

  // 2. Lower every method to IR (Java-specific)
  const loweringStart = Date.now();
  const stateById = new Map<FunctionId, FunctionState>();
  for (const node of callgraph.nodes) {
    if (node.isModuleInitializer) {
      // Java module-initializer nodes are typically empty; register an empty
      // IR so the state map matches the callgraph node set.
      stateById.set(node.id, {
        funcNode: node,
        ir: { id: node.id, params: [], steps: [] },
        paramTaints: new Map(),
        returnTaint: null,
        sinkHits: [],
        analyzed: false,
      });
      continue;
    }
    const entry = methodById.get(node.id);
    if (!entry) continue;
    const ir = lowerJavaMethod(entry.node, {
      ctx,
      fileIndex: entry.fileIndex,
      entry,
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

  // 3. Hand off to the language-agnostic core.
  const callersByCallee = buildCallersByCallee(callgraph.edges);
  const result = runWorklistAndAggregate({
    stateById,
    callersByCallee,
    specs,
    maxPathLength: options.maxPathLength,
    maxIterations: options.maxIterations,
    onWarn,
    signal: options.signal,
  });

  return {
    flows: result.flows,
    callgraph,
    aborted: result.aborted,
    stats: {
      functionsAnalyzed: stateById.size,
      worklistIterations: result.iterations,
      sourcesFound: result.sourcesFound,
      sinksHit: result.sinksHit,
      flowsEmitted: result.flows.length,
      callgraphMs,
      loweringMs,
      propagationMs: result.propagationMs,
      totalMs: Date.now() - t0,
      stoppedEarly: result.stoppedEarly,
    },
    irFunctions: Array.from(stateById.values()).map((s) => s.ir),
  };
}
