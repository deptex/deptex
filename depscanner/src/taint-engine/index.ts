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

export { loadSpec, loadSpecFromJson, validateSpec, SpecValidationError } from './spec-loader';
export type {
  FrameworkSpec,
  FrameworkSource,
  FrameworkSink,
  FrameworkSanitizer,
  RequiredArgument,
  TaintKind,
  VulnClass,
} from './spec';
export { ALL_VULN_CLASSES } from './spec';

export {
  detectSanitizerAbsence,
  extractCallSitesFromIr,
} from './non-taint-detector';
export type {
  CallSite,
  NonTaintFinding,
} from './non-taint-detector';

export {
  detectUnsafeRegexLiterals,
} from './regex-literal-detector';
export type {
  RegexLiteralFinding,
  DetectRegexLiteralsOptions,
} from './regex-literal-detector';

export {
  detectInsecureDefaults,
} from './insecure-default-detector';
export type {
  InsecureDefaultFinding,
  DetectInsecureDefaultsOptions,
} from './insecure-default-detector';

export { loadCveSpecsForExtraction } from './cve-specs';
export type { LoadCveSpecsOptions, LoadCveSpecsResult } from './cve-specs';

export type { Flow, FlowNode, SinkHit, TaintTrace } from './flow';

export {
  filterFlow,
  parseTriple,
  buildPrompt,
  buildCandidateSanitizers,
  validateSanitizerLine,
  wasTruncated,
  estimatePerFlowCostUsd,
  createUsageLogger,
  FP_FILTER_PROMPT_VERSION,
} from './fp-filter';
export type {
  FilterTriple,
  FilterErrorVerdict,
  TripleResult,
  ParsedTriple,
  SanitizationVerdict,
  EndpointVerdict,
  EndpointClassification,
  CandidateSanitizer,
  FilterFlowOptions,
  AiUsageLogger,
} from './fp-filter';

export {
  HIDE_BELOW,
  UNCERTAIN_UPPER,
  MAX_VOTE_THRESHOLD,
} from './confidence-thresholds';

export type { IrFunction, Step, LocalVar, SourceLocation, CalleeRef } from './ir';
export { lowerFunction } from './ir';

export { runEngine, runEngineCore, shouldRunForRollout, shouldRunForOrg } from './runner';
export type { RunEngineOptions, RunEngineResult, RunEngineCoreOptions, EngineCoreResult } from './runner';
export { runEngineCoreInWorker, EngineCoreTimeoutError } from './engine-worker-host';
export type { RunInWorkerOptions } from './engine-worker-host';

export {
  writeFlows,
  writeRun,
  createOsvIdResolver,
  fallbackUnresolvedResolveDep,
  computeFlowSignatureHash,
  canonicalRepoPath,
  computeEntryPointTag,
  isDetectorCoercedFlow,
} from './storage';

export {
  matchFlowToRoutes,
  parseEntryPointTag,
  tagForClass,
  TAG_UNMATCHED,
  TAG_LEGACY_PUBLIC,
} from './match-flow-to-routes';
export type { EntryPointAuthMap, FlowRouteMatch } from './match-flow-to-routes';
export type {
  WriteFlowsOptions,
  WriteFlowsResult,
  WriteRunOptions,
  TaintEngineRunStatus,
  ResolvedDep,
} from './storage';

export {
  checkCircuitBreaker,
  maybeEngageKillswitch,
  CIRCUIT_BREAKER_WINDOW_MINUTES,
  CIRCUIT_BREAKER_FAILURE_THRESHOLD_PCT,
  CIRCUIT_BREAKER_MIN_SAMPLE_SIZE,
} from './circuit-breaker';
export type { CircuitBreakerState } from './circuit-breaker';
