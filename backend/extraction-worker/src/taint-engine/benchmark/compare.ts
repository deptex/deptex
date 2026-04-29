/**
 * Per-CVE recall comparator for the M8 benchmark harness.
 *
 * Given (a) the set of expected findings for a corpus project and (b) two
 * sets of flows — one from atom (parsed from dep-scan's reachables.slices.json)
 * and one from the deterministic taint engine — this module decides, per
 * expected finding, whether each engine "recovered" it.
 *
 * Match rules (purposely lenient for atom A/B parity work):
 *   - vulnClass: if the corpus entry sets it, the candidate flow must match
 *     the same vuln_class. atom doesn't tag a vuln class, so atom matches
 *     are vuln-class-agnostic when comparing against atom flows.
 *   - sinkFile: when set, the candidate flow's sink_file must end with the
 *     given path (case-insensitive on Windows, normalized to forward slashes).
 *   - sinkPattern: when set, the candidate flow's sink_method or sink_pattern
 *     must contain the substring (case-insensitive).
 *
 * Recall is reported per finding (hit / miss) plus aggregated to per-project
 * + per-corpus totals.
 */

import type { Flow } from '../flow';
import type { BenchmarkCorpus, BenchmarkProject, ExpectedFinding } from './corpus';

/**
 * A flow shape we can match against expected findings. Both engines emit
 * flows in this normalized form — atom slices are converted by the runner
 * before being passed to the comparator.
 */
export interface CandidateFlow {
  vulnClass: string | null;
  sinkFile: string;
  sinkMethod: string;
  sinkPattern: string | null;
}

export function flowToCandidate(f: Flow): CandidateFlow {
  return {
    vulnClass: f.vuln_class,
    sinkFile: f.sink_file,
    sinkMethod: f.sink_method,
    sinkPattern: f.sink_pattern,
  };
}

export interface FindingMatch {
  finding: ExpectedFinding;
  matched: boolean;
  /** When matched, the candidate that triggered it (for the report). */
  via?: CandidateFlow;
}

export interface ProjectRecall {
  project: BenchmarkProject;
  expected: number;
  matched: number;
  /** Per-finding hit/miss detail. */
  findings: FindingMatch[];
}

export function compareProject(
  project: BenchmarkProject,
  candidates: CandidateFlow[],
  opts: { ignoreVulnClass?: boolean } = {},
): ProjectRecall {
  const findings = project.expectedFindings.map((f) => matchOne(f, candidates, opts));
  const matched = findings.filter((m) => m.matched).length;
  return {
    project,
    expected: project.expectedFindings.length,
    matched,
    findings,
  };
}

function matchOne(
  finding: ExpectedFinding,
  candidates: CandidateFlow[],
  opts: { ignoreVulnClass?: boolean },
): FindingMatch {
  for (const c of candidates) {
    if (matches(finding, c, opts)) {
      return { finding, matched: true, via: c };
    }
  }
  return { finding, matched: false };
}

function matches(
  finding: ExpectedFinding,
  candidate: CandidateFlow,
  opts: { ignoreVulnClass?: boolean },
): boolean {
  if (
    !opts.ignoreVulnClass &&
    finding.vulnClass &&
    candidate.vulnClass &&
    candidate.vulnClass !== finding.vulnClass
  ) {
    return false;
  }
  if (finding.sinkFile) {
    const norm = (p: string) => p.replace(/\\/g, '/').toLowerCase();
    if (!norm(candidate.sinkFile).endsWith(norm(finding.sinkFile))) return false;
  }
  if (finding.sinkPattern) {
    const needle = finding.sinkPattern.toLowerCase();
    const hay = `${candidate.sinkMethod ?? ''} ${candidate.sinkPattern ?? ''}`.toLowerCase();
    if (!hay.includes(needle)) return false;
  }
  return true;
}

export interface CorpusRecall {
  /** atom recall, ignoring vuln class (atom doesn't tag a class). */
  atom: { expected: number; matched: number; perProject: ProjectRecall[] };
  /** taint engine recall, full match including vuln_class. */
  taintEngine: { expected: number; matched: number; perProject: ProjectRecall[] };
  /** Findings the engine recovered that atom did NOT — the parity-plus story. */
  newDetections: Array<{ project: BenchmarkProject; finding: ExpectedFinding }>;
  /** Findings atom recovered that the engine missed — the regression list. */
  regressions: Array<{ project: BenchmarkProject; finding: ExpectedFinding }>;
}

export function compareCorpus(
  corpus: BenchmarkCorpus,
  resultsByProject: Map<string, { atom: CandidateFlow[]; engine: CandidateFlow[] }>,
): CorpusRecall {
  const atomPer: ProjectRecall[] = [];
  const enginePer: ProjectRecall[] = [];
  const newDetections: Array<{ project: BenchmarkProject; finding: ExpectedFinding }> = [];
  const regressions: Array<{ project: BenchmarkProject; finding: ExpectedFinding }> = [];

  for (const project of corpus.projects) {
    const r = resultsByProject.get(project.id) ?? { atom: [], engine: [] };
    const atomRecall = compareProject(project, r.atom, { ignoreVulnClass: true });
    const engineRecall = compareProject(project, r.engine);
    atomPer.push(atomRecall);
    enginePer.push(engineRecall);

    for (let i = 0; i < project.expectedFindings.length; i++) {
      const f = project.expectedFindings[i];
      const atomHit = atomRecall.findings[i].matched;
      const engineHit = engineRecall.findings[i].matched;
      if (engineHit && !atomHit) newDetections.push({ project, finding: f });
      if (atomHit && !engineHit) regressions.push({ project, finding: f });
    }
  }

  const atomTotal = atomPer.reduce(
    (acc, p) => ({ expected: acc.expected + p.expected, matched: acc.matched + p.matched }),
    { expected: 0, matched: 0 },
  );
  const engineTotal = enginePer.reduce(
    (acc, p) => ({ expected: acc.expected + p.expected, matched: acc.matched + p.matched }),
    { expected: 0, matched: 0 },
  );

  return {
    atom: { ...atomTotal, perProject: atomPer },
    taintEngine: { ...engineTotal, perProject: enginePer },
    newDetections,
    regressions,
  };
}
