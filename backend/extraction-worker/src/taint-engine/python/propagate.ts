/**
 * Python driver for the taint engine's worklist propagator.
 *
 * Thin orchestrator: builds the Python callgraph + lowers each function to IR,
 * then hands off to the language-agnostic core in ../propagate-core.ts.
 */

import type { FrameworkSpec } from '../spec';
import type { Flow } from '../flow';
import type { Callgraph, FunctionId } from '../types';
import { buildPythonCallgraphContext, type PythonFileContext } from './callgraph';
import { lowerPythonFunction } from './ir';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from '../propagate-core';

export interface PropagatePythonOptions {
  rootDir: string;
  specs: FrameworkSpec[];
  /** Cap on flow path length. Default 50. */
  maxPathLength?: number;
  /** Cap on worklist iterations. Default 50× function count. */
  maxIterations?: number;
  onWarn?: (msg: string) => void;
}

export interface PropagatePythonResult {
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

export async function propagatePython(
  options: PropagatePythonOptions,
): Promise<PropagatePythonResult> {
  const t0 = Date.now();
  const onWarn = options.onWarn;

  // 1. Callgraph (Python-specific)
  const cgStart = Date.now();
  const ctx = await buildPythonCallgraphContext({ rootDir: options.rootDir, onWarn });
  const callgraphMs = Date.now() - cgStart;
  const { callgraph, files, nodeIdToFunc } = ctx;

  // 2. Lower every function (Python-specific)
  const loweringStart = Date.now();
  const stateById = new Map<FunctionId, FunctionState>();
  for (const node of callgraph.nodes) {
    const fnAst = nodeIdToFunc.get(node.id);
    if (!fnAst) continue;
    const fileContext: PythonFileContext | undefined = files.get(node.filePath);
    if (!fileContext) continue;
    const ir = lowerPythonFunction(node.id, fnAst, {
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
    specs: options.specs,
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
