/**
 * PHP driver for the taint engine's worklist propagator.
 *
 * Thin orchestrator: builds the PHP callgraph + lowers each function/method
 * to IR, then hands off to the language-agnostic core in ../propagate-core.ts.
 */

import { filterSpecsByLanguage, type FrameworkSpec } from '../spec';
import type { Flow } from '../flow';
import type { IrFunction } from '../ir';
import type { Callgraph, FunctionId } from '../types';
import { buildPhpCallgraphContext, type PhpFileContext } from './callgraph';
import { lowerPhpFunction } from './ir';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from '../propagate-core';

export interface PropagatePhpOptions {
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

export interface PropagatePhpResult {
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
  };
  /** See PropagateResult.irFunctions. */
  irFunctions?: IrFunction[];
}

export async function propagatePhp(
  options: PropagatePhpOptions,
): Promise<PropagatePhpResult> {
  const t0 = Date.now();
  const onWarn = options.onWarn;
  const specs = filterSpecsByLanguage(options.specs, 'php');

  // 1. Callgraph (PHP-specific)
  const cgStart = Date.now();
  const ctx = await buildPhpCallgraphContext({ rootDir: options.rootDir, onWarn });
  const callgraphMs = Date.now() - cgStart;
  const { callgraph, files, nodeIdToFunc, globalFunctionsByFqn, classFqnToFile } = ctx;

  // 2. Lower every function (PHP-specific)
  const loweringStart = Date.now();
  const stateById = new Map<FunctionId, FunctionState>();
  for (const node of callgraph.nodes) {
    const fnAst = nodeIdToFunc.get(node.id);
    if (!fnAst) continue;
    const fileContext: PhpFileContext | undefined = files.get(node.filePath);
    if (!fileContext) continue;
    const ir = lowerPhpFunction(node.id, fnAst, {
      filePath: node.filePath,
      fileContext,
      allFiles: files,
      globalFunctionsByFqn,
      classFqnToFile,
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
    },
    irFunctions: Array.from(stateById.values()).map((s) => s.ir),
  };
}
