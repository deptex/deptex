/**
 * Rust driver for the taint engine's worklist propagator.
 *
 * Thin orchestrator: builds the Rust callgraph + lowers each function to IR,
 * then hands off to the language-agnostic core in ../propagate-core.ts.
 */

import { filterSpecsByLanguage, type FrameworkSpec } from '../spec';
import type { Flow } from '../flow';
import type { IrFunction } from '../ir';
import type { Callgraph, FunctionId } from '../types';
import { buildRustCallgraphContext, type RustFileContext } from './callgraph';
import { lowerRustFunction } from './ir';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from '../propagate-core';

export interface PropagateRustOptions {
  rootDir: string;
  specs: FrameworkSpec[];
  /** Cap on flow path length. Default 50. */
  maxPathLength?: number;
  /** Cap on worklist iterations. Default 50× function count. */
  maxIterations?: number;
  onWarn?: (msg: string) => void;
  /** Forwarded to the worklist core; aborts cleanly between iterations. */
  signal?: AbortSignal;
}

export interface PropagateRustResult {
  flows: Flow[];
  callgraph: Callgraph;
  /** True when the worklist aborted mid-loop on the cancellation signal. */
  aborted: boolean;
  stats: {
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
  };
  /** See PropagateResult.irFunctions. */
  irFunctions?: IrFunction[];
}

export async function propagateRust(
  options: PropagateRustOptions,
): Promise<PropagateRustResult> {
  const t0 = Date.now();
  const onWarn = options.onWarn;
  const specs = filterSpecsByLanguage(options.specs, 'rust');

  // 1. Callgraph (Rust-specific)
  const cgStart = Date.now();
  const ctx = await buildRustCallgraphContext({ rootDir: options.rootDir, onWarn });
  const callgraphMs = Date.now() - cgStart;
  const { callgraph, files, nodeIdToFunc } = ctx;

  // 2. Lower every function (Rust-specific)
  const loweringStart = Date.now();
  const stateById = new Map<FunctionId, FunctionState>();
  for (const node of callgraph.nodes) {
    const fnAst = nodeIdToFunc.get(node.id);
    if (!fnAst) continue;
    const fileContext: RustFileContext | undefined = files.get(node.filePath);
    if (!fileContext) continue;
    const ir = lowerRustFunction(node.id, fnAst, {
      filePath: node.filePath,
      fileContext,
      allFiles: files,
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
