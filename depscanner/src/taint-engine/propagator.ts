/**
 * TS/JS driver for the worklist forward-propagation taint engine.
 *
 * This file is now a thin TS-specific orchestrator: it builds the TS callgraph
 * (via the TypeScript Compiler API), lowers each function to IR via the TS
 * lowerer, and hands a populated `stateById` map to `runWorklistAndAggregate`
 * in propagate-core.ts. The worklist algorithm itself + pattern matchers +
 * flow aggregation are language-agnostic and live in the core file, shared
 * with the Python / Java / Go drivers under `<lang>/propagate.ts`.
 *
 * Algorithm sketch lives in propagate-core.ts.
 *
 * What this engine deliberately does NOT do:
 *   - Aliasing: assignment is by-name; `a = b; b.x = tainted` doesn't taint `a.x`.
 *   - Control-flow joins: branches are flattened (over-approximation, sound).
 *   - Async/promise modeling: `.then(h)` doesn't connect h's param to the
 *     promise's resolved value. `await fooReturningTainted()` IS handled
 *     (await unwraps).
 *   - Object-field taint: tainting `x` taints `x` only, not `x.foo`. The
 *     lowerer records property-access source patterns directly, so common
 *     request-body access still works.
 */

import * as ts from 'typescript';
import { buildCallgraphContext } from './callgraph';
import { lowerFunction } from './ir';
import type { Callgraph, FunctionId } from './types';
import type { FrameworkSpec } from './spec';
import { filterSpecsByLanguage } from './spec';
import type { Flow } from './flow';
import type { IrFunction } from './ir';
import {
  buildCallersByCallee,
  runWorklistAndAggregate,
  type FunctionState,
} from './propagate-core';

export interface PropagateOptions {
  rootDir: string;
  specs: FrameworkSpec[];
  /** Cap on flow path length for emitted Flows. Default 50. */
  maxPathLength?: number;
  /** Cap on worklist iterations as a runaway-loop safety net. Default: 50× function count. */
  maxIterations?: number;
  onWarn?: (msg: string) => void;
  /** Forwarded to the worklist core; aborts cleanly between iterations. */
  signal?: AbortSignal;
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
  /**
   * True when the worklist aborted mid-loop because the cancellation signal
   * fired (the 30-min hard timeout). `flows` is then a PARTIAL set — the
   * pipeline must not treat absent flows as a clean unreachable verdict.
   */
  aborted: boolean;
  /**
   * Phase F4 — the lowered IR for every analysed function, keyed by
   * FunctionId. Consumers (Gate 2 in rule-generator/validate.ts) walk these
   * to extract `CallSite[]` for the non-taint detector regime. Optional so
   * callers that don't need it pay no marshaling cost.
   */
  irFunctions?: IrFunction[];
}

export async function propagate(options: PropagateOptions): Promise<PropagateResult> {
  const t0 = Date.now();
  const onWarn = options.onWarn;
  const specs = filterSpecsByLanguage(options.specs, 'js');

  // 1. Callgraph (TS-specific)
  const cgStart = Date.now();
  const ctx = await buildCallgraphContext({ rootDir: options.rootDir, onWarn });
  const callgraphMs = Date.now() - cgStart;
  const { callgraph, program, declarationToNodeId, nodeIdToDeclaration } = ctx;

  // 2. Lower every function (TS-specific)
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
      pickFunctionDecl,
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
