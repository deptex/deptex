/**
 * Reachability corpus acceptance-gate evaluator.
 *
 * `evaluateReachabilityGates` turns an oss-corpus report.json into the three
 * pass/fail gates the reachability noise-reduction feature ships against.
 * These tests pin the gate arithmetic without running a scan.
 */

import { evaluateReachabilityGates, type CorpusReport } from '../../scripts/reachability-corpus';

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
