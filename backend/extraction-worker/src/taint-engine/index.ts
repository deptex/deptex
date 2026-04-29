/**
 * Public surface for the Deptex cross-file taint engine.
 *
 * M1: callgraph substrate (TypeScript Compiler API).
 * M2: forward-propagation taint engine + IR + YAML framework spec format.
 *
 * M3+ adds the hand-written framework specs (Express, Fastify, ...) and
 * the AI augmentation layer (spec inference + FP filter).
 */

export { buildCallgraph, buildCallgraphContext } from './callgraph';
export type { BuildCallgraphOptions, CallgraphContext } from './callgraph';
export type {
  Callgraph,
  CallEdge,
  CallEdgeKind,
  FileStats,
  FunctionId,
  FunctionKind,
  FunctionNode,
} from './types';

export { propagate } from './propagator';
export type { PropagateOptions, PropagateResult, PropagateStats } from './propagator';

export { loadSpec, validateSpec, SpecValidationError } from './spec-loader';
export type {
  FrameworkSpec,
  FrameworkSource,
  FrameworkSink,
  FrameworkSanitizer,
  TaintKind,
  VulnClass,
} from './spec';
export { ALL_VULN_CLASSES } from './spec';

export type { Flow, FlowNode, SinkHit, TaintTrace } from './flow';

export type { IrFunction, Step, LocalVar, SourceLocation, CalleeRef } from './ir';
export { lowerFunction } from './ir';

export { runEngine, shouldRunForRollout, shouldRunForOrg } from './runner';
export type { RunEngineOptions, RunEngineResult } from './runner';

export { writeFlows, writeRun } from './storage';
export type { WriteFlowsOptions, WriteFlowsResult, WriteRunOptions, TaintEngineRunStatus } from './storage';

export {
  checkCircuitBreaker,
  maybeEngageKillswitch,
  CIRCUIT_BREAKER_WINDOW_MINUTES,
  CIRCUIT_BREAKER_FAILURE_THRESHOLD_PCT,
  CIRCUIT_BREAKER_MIN_SAMPLE_SIZE,
} from './circuit-breaker';
export type { CircuitBreakerState } from './circuit-breaker';
