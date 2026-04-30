/**
 * Public surface for the M8 benchmark + retirement-gate harness.
 */

export { loadCorpus, validateCorpus, CorpusLoadError } from './corpus';
export type { BenchmarkCorpus, BenchmarkProject, ExpectedFinding } from './corpus';

export {
  flowToCandidate,
  compareProject,
  compareCorpus,
} from './compare';
export type { CandidateFlow, FindingMatch, ProjectRecall, CorpusRecall } from './compare';

export { buildReport, writeJsonReport, writeHtmlReport } from './report';
export type { BenchmarkReport, BuildReportInput } from './report';

export { runProject } from './runner';
export type { RunProjectOptions, RunProjectResult } from './runner';

export { evaluateRetirementGates } from './gates';
export type {
  RetirementGateInput,
  RetirementGateResult,
  GateOutcome,
  ShadowRunStats,
} from './gates';
