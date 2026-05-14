/**
 * Go driver for the taint engine's worklist propagator.
 *
 * Thin orchestrator: builds the Go callgraph + call-expression resolution map +
 * lowers each function to IR, then hands off to the language-agnostic core in
 * ../propagate-core.ts.
 */

import { buildGoCallgraphContext } from './callgraph';
import type { GoCallgraphContext, GoFileEntry } from './callgraph';
import { lowerGoFunction } from './ir';
import type {
  Callgraph,
  CallEdge,
  FunctionId,
} from '../types';
import { filterSpecsByLanguage, type FrameworkSpec } from '../spec';
import type { Flow } from '../flow';
import type { IrFunction } from '../ir';
import type { Node } from 'web-tree-sitter';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from '../propagate-core';

export interface PropagateGoOptions {
  rootDir: string;
  specs: FrameworkSpec[];
  maxPathLength?: number;
  maxIterations?: number;
  onWarn?: (msg: string) => void;
  /** Forwarded to the worklist core; aborts cleanly between iterations. */
  signal?: AbortSignal;
}

export interface PropagateGoResult {
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
  /** See PropagateResult.irFunctions. */
  irFunctions?: IrFunction[];
}

export async function propagateGo(options: PropagateGoOptions): Promise<PropagateGoResult> {
  const t0 = Date.now();
  const onWarn = options.onWarn;
  const specs = filterSpecsByLanguage(options.specs, 'go');

  // 1. Build Go callgraph (Go-specific)
  const cgStart = Date.now();
  const ctx = await buildGoCallgraphContext({ rootDir: options.rootDir, onWarn });
  const callgraphMs = Date.now() - cgStart;
  const { callgraph } = ctx;

  // 2. Build per-call-expression resolution map (Go-specific quirk: edges are
  //    keyed by location, lowerer needs them by AST node id).
  const callExprToFuncId = buildCallExprResolution(ctx);

  // 3. Lower every function (Go-specific)
  const loweringStart = Date.now();
  const stateById = new Map<FunctionId, FunctionState>();
  for (const node of callgraph.nodes) {
    const decl = ctx.funcIdToDecl.get(node.id);
    if (!decl) continue;
    const ir = lowerGoFunction(decl.node, {
      filePath: decl.file.filePath,
      funcId: node.id,
      callExprToFuncId,
      isExternalCall: (fn) => isExternalCall(fn, decl.file),
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

  // 4. Hand off to the language-agnostic core.
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

// ---------------------------------------------------------------------------
// Go-specific callgraph helpers — kept here because they're tightly coupled
// to the Go callgraph context shape.
// ---------------------------------------------------------------------------

function buildCallExprResolution(ctx: GoCallgraphContext): Map<number, FunctionId> {
  // The callgraph emits edges keyed by file+line+column, not by tree-sitter
  // node id. Re-walk every file and keep a parallel map: call_expression
  // node id → resolved FunctionId.
  const map = new Map<number, FunctionId>();
  const edgeByLoc = new Map<string, CallEdge>();
  for (const e of ctx.callgraph.edges) {
    edgeByLoc.set(`${e.filePath}:${e.line}:${e.column}`, e);
  }
  for (const file of ctx.files) {
    walkFileForCallNodes(file, file.tree.rootNode, edgeByLoc, map);
  }
  return map;
}

function walkFileForCallNodes(
  file: GoFileEntry,
  node: Node,
  edgeByLoc: Map<string, CallEdge>,
  map: Map<number, FunctionId>,
): void {
  if (node.type === 'call_expression') {
    const startLine = node.startPosition.row + 1;
    const startCol = node.startPosition.column + 1;
    const key = `${file.filePath}:${startLine}:${startCol}`;
    const edge = edgeByLoc.get(key);
    if (edge && edge.calleeId) {
      map.set(node.id, edge.calleeId);
    }
  }
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c) walkFileForCallNodes(file, c, edgeByLoc, map);
  }
}

function isExternalCall(fnNode: Node, file: GoFileEntry): boolean {
  if (fnNode.type === 'selector_expression') {
    const operand = fnNode.childForFieldName('operand');
    if (operand?.type === 'identifier') {
      const operandName = operand.text;
      const importPath = file.importsByAlias.get(operandName);
      if (importPath) return true;
    }
  }
  return false;
}
