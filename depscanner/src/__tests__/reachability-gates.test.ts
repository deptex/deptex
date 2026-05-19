/**
 * Reachability corpus acceptance-gate evaluator.
 *
 * `evaluateReachabilityGates` turns an oss-corpus report.json into the three
 * pass/fail gates the reachability noise-reduction feature ships against.
 * These tests pin the gate arithmetic without running a scan.
 */

import {
  evaluateReachabilityGates,
  checkBaselineLock,
  checkOracle,
  buildObservedMap,
  type CorpusReport,
} from '../../scripts/reachability-corpus';

function repo(name: string, ecosystem: string, matches: Array<[string, string, string]>) {
  // matches: [cve, expected_reachability, observed_reachability]
  return {
    name,
    ecosystem,
    status: 'ok',
    ground_truth_matched: matches.map(([cve, expected, observed]) => ({
      cve,
      observed: true,
      observed_reachability: observed,
      expected_reachability: expected,
    })),
  };
}

describe('evaluateReachabilityGates', () => {
  it('weights unreachable fully and module at half for noise reduction', () => {
    const report: CorpusReport = {
      results: [
        repo('r-npm', 'npm', [
          ['CVE-1', 'unreachable', 'unreachable'],
          ['CVE-2', 'module', 'module'],
          ['CVE-3', 'function', 'function'],
          ['CVE-4', 'confirmed', 'confirmed'],
        ]),
      ],
    };
    // (1 unreachable + 0.5*1 module) / 4 observed = 1.5/4 = 37.5%
    const g = evaluateReachabilityGates(report);
    expect(g.noiseReductionPct).toBe(37.5);
    expect(g.gate1Pass).toBe(false);
  });

  it('passes gate 1 when noise reduction clears 60%', () => {
    const report: CorpusReport = {
      results: [
        repo('r-npm', 'npm', [
          ['CVE-1', 'unreachable', 'unreachable'],
          ['CVE-2', 'unreachable', 'unreachable'],
          ['CVE-3', 'module', 'module'],
          ['CVE-4', 'function', 'function'],
        ]),
      ],
    };
    // (2 + 0.5) / 4 = 62.5%
    const g = evaluateReachabilityGates(report);
    expect(g.noiseReductionPct).toBe(62.5);
    expect(g.gate1Pass).toBe(true);
  });

  it('fails gate 2 when an ecosystem has zero unreachable findings', () => {
    const report: CorpusReport = {
      results: [
        repo('r-npm', 'npm', [['CVE-1', 'unreachable', 'unreachable']]),
        repo('r-gem', 'gem', [['CVE-2', 'module', 'module']]), // no unreachable
      ],
    };
    const g = evaluateReachabilityGates(report);
    expect(g.gate2Pass).toBe(false);
    expect(g.perEcosystemUnreachablePct.gem).toBe(0);
    expect(g.perEcosystemUnreachablePct.npm).toBe(100);
  });

  it('fails gate 3 and lists a CVE labelled reachable but scanned unreachable', () => {
    const report: CorpusReport = {
      results: [
        repo('r-pypi', 'pypi', [
          ['CVE-9', 'function', 'unreachable'], // false negative
          ['CVE-10', 'module', 'unreachable'], // module is NOT a strict reachable label
        ]),
      ],
    };
    const g = evaluateReachabilityGates(report);
    expect(g.gate3Pass).toBe(false);
    expect(g.falseNegatives).toEqual([{ repo: 'r-pypi', cve: 'CVE-9', expected: 'function' }]);
  });

  it('ignores unobserved CVEs and non-ok repos', () => {
    const report: CorpusReport = {
      results: [
        {
          name: 'r-skip',
          ecosystem: 'npm',
          status: 'scan_failed',
          ground_truth_matched: [
            { cve: 'CVE-X', observed: true, observed_reachability: 'unreachable', expected_reachability: 'module' },
          ],
        },
        {
          name: 'r-ok',
          ecosystem: 'npm',
          status: 'ok',
          ground_truth_matched: [
            { cve: 'CVE-Y', observed: false, observed_reachability: null, expected_reachability: 'function' },
            { cve: 'CVE-Z', observed: true, observed_reachability: 'unreachable', expected_reachability: 'module' },
          ],
        },
      ],
    };
    const g = evaluateReachabilityGates(report);
    // Only CVE-Z counts: the failed repo and the unobserved CVE-Y are excluded.
    expect(g.observedTotal).toBe(1);
    expect(g.unreachableCount).toBe(1);
  });

  it('reports no pass on an empty corpus (gate 2 needs at least one ecosystem)', () => {
    const g = evaluateReachabilityGates({ results: [] });
    expect(g.gate2Pass).toBe(false);
    expect(g.pass).toBe(false);
  });

  it('fails the recall floor and refuses a pass when a hand-labelled CVE is unobserved', () => {
    const report: CorpusReport = {
      results: [
        {
          name: 'r-npm',
          ecosystem: 'npm',
          status: 'ok',
          ground_truth_matched: [
            { cve: 'CVE-1', observed: true, observed_reachability: 'unreachable', expected_reachability: 'unreachable' },
            { cve: 'CVE-2', observed: true, observed_reachability: 'unreachable', expected_reachability: 'unreachable' },
            { cve: 'CVE-3', observed: false, observed_reachability: null, expected_reachability: 'module' },
          ],
        },
      ],
    };
    const g = evaluateReachabilityGates(report);
    // 2/2 observed are unreachable → gate 1 clears, but 1 of 3 CVEs unobserved.
    expect(g.recallPct).toBe(66.67);
    expect(g.recallFloorPass).toBe(false);
    expect(g.unobservedCves).toEqual([{ repo: 'r-npm', cve: 'CVE-3' }]);
    expect(g.pass).toBe(false);
  });

  it('reports the full-weight unreachable-only rate alongside the module-weighted one', () => {
    const report: CorpusReport = {
      results: [
        repo('r-npm', 'npm', [
          ['CVE-1', 'unreachable', 'unreachable'],
          ['CVE-2', 'module', 'module'],
          ['CVE-3', 'module', 'module'],
          ['CVE-4', 'function', 'function'],
        ]),
      ],
    };
    const g = evaluateReachabilityGates(report);
    expect(g.noiseReductionPct).toBe(50); // (1 + 0.5*2) / 4
    expect(g.unreachableOnlyPct).toBe(25); // 1 / 4
  });

  it('computes the informational all-findings number from by_reachability', () => {
    const report: CorpusReport = {
      results: [
        {
          name: 'r-npm',
          ecosystem: 'npm',
          status: 'ok',
          ground_truth_matched: [
            { cve: 'CVE-1', observed: true, observed_reachability: 'unreachable', expected_reachability: 'unreachable' },
          ],
          by_reachability: { unreachable: 6, module: 4, function: 10 },
        },
      ],
    };
    const g = evaluateReachabilityGates(report);
    expect(g.allFindingsTotal).toBe(20);
    expect(g.allFindingsNoiseReductionPct).toBe(40); // (6 + 0.5*4) / 20
  });
});

describe('checkBaselineLock', () => {
  const locked = {
    'CVE-A': 'unreachable',
    'CVE-B': 'function',
    'CVE-C': 'module',
  };

  it('passes when every frozen label still matches the live corpus', () => {
    const corpus = new Map([
      ['CVE-A', 'unreachable'],
      ['CVE-B', 'function'],
      ['CVE-C', 'module'],
      ['CVE-NEW', 'unreachable'], // a Layer-3 addition — not locked, allowed
    ]);
    const r = checkBaselineLock(corpus, locked);
    expect(r.ok).toBe(true);
    expect(r.violations).toEqual([]);
  });

  it('fails when a frozen label was relabelled in the corpus', () => {
    const corpus = new Map([
      ['CVE-A', 'module'], // was 'unreachable' — softened to flatter the metric
      ['CVE-B', 'function'],
      ['CVE-C', 'module'],
    ]);
    const r = checkBaselineLock(corpus, locked);
    expect(r.ok).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0]).toContain('CVE-A');
  });

  it('fails when a frozen CVE was removed from the corpus', () => {
    const corpus = new Map([
      ['CVE-A', 'unreachable'],
      ['CVE-C', 'module'],
    ]);
    const r = checkBaselineLock(corpus, locked);
    expect(r.ok).toBe(false);
    expect(r.violations).toHaveLength(1);
    expect(r.violations[0]).toContain('CVE-B');
  });
});

describe('checkOracle', () => {
  const verdicts = [
    { id: 'CVE-R', verdict: 'reachable' },
    { id: 'CVE-M', verdict: 'module' },
    { id: 'CVE-U', verdict: 'unreachable' },
  ];

  it('passes when the scan never observes an oracle-reachable CVE as unreachable', () => {
    const observed = new Map([
      ['CVE-R', 'function'],
      ['CVE-M', 'unreachable'], // module verdict — observed-unreachable is allowed
      ['CVE-U', 'unreachable'],
    ]);
    const r = checkOracle(verdicts, observed);
    expect(r.ok).toBe(true);
    expect(r.disagreements).toEqual([]);
  });

  it('fails when an oracle-reachable CVE was scanned unreachable', () => {
    const observed = new Map([
      ['CVE-R', 'unreachable'], // the classifier hid a vuln the oracle says runs
      ['CVE-M', 'module'],
      ['CVE-U', 'unreachable'],
    ]);
    const r = checkOracle(verdicts, observed);
    expect(r.ok).toBe(false);
    expect(r.disagreements).toEqual([{ cve: 'CVE-R', observed: 'unreachable' }]);
  });

  it('does not gate on a `module` oracle verdict observed unreachable', () => {
    const observed = new Map([['CVE-M', 'unreachable']]);
    expect(checkOracle(verdicts, observed).ok).toBe(true);
  });

  it('buildObservedMap collapses ground-truth matches across ok repos', () => {
    const report: CorpusReport = {
      results: [
        {
          name: 'r1', ecosystem: 'npm', status: 'ok',
          ground_truth_matched: [
            { cve: 'CVE-1', observed: true, observed_reachability: 'unreachable', expected_reachability: 'unreachable' },
            { cve: 'CVE-2', observed: false, observed_reachability: null, expected_reachability: 'module' },
          ],
        },
        {
          name: 'r2', ecosystem: 'npm', status: 'scan_failed',
          ground_truth_matched: [
            { cve: 'CVE-3', observed: true, observed_reachability: 'module', expected_reachability: 'module' },
          ],
        },
      ],
    };
    const m = buildObservedMap(report);
    expect(m.get('CVE-1')).toBe('unreachable');
    expect(m.has('CVE-2')).toBe(false); // unobserved — no reachability
    expect(m.has('CVE-3')).toBe(false); // non-ok repo excluded
  });
});
