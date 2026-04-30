/**
 * PHP driver for the taint engine's worklist propagator.
 *
 * Thin orchestrator: builds the PHP callgraph + lowers each function/method
 * to IR, then hands off to the language-agnostic core in ../propagate-core.ts.
 */

import { filterSpecsByLanguage, type FrameworkSpec } from '../spec';
import type { Flow } from '../flow';
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
}

export interface PropagatePhpResult {
  flows: Flow[];
  callgraph: Callgraph;
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
  });

  return {
    flows: result.flows,
    callgraph,
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
  };
}
