/**
 * Reachability corpus runner + acceptance gates.
 *
 * Scans the purpose-built, hand-labelled corpus (scripts/reachability-corpus.yaml)
 * by delegating to the existing oss-corpus harness, then evaluates the three
 * reachability acceptance gates against the per-CVE observed-vs-expected
 * reachability in its report.json:
 *
 *   Gate 1 — corpus-wide noise reduction >= 60%
 *            ((unreachable + 0.5*module) / observed CVEs)
 *   Gate 2 — every ecosystem in the corpus scores > 0% unreachable
 *   Gate 3 — zero CVEs hand-labelled reachable but scanned `unreachable`
 *            (the false-negative gate)
 *
 * Usage (from depscanner/):
 *   npm run test:reachability-corpus
 *   npm run test:reachability-corpus -- --report=<existing report.json>
 *
 * The second form skips the (Docker-bound, minutes-long) scan and just
 * re-evaluates the gates against an already-produced report — used by the
 * unit test and for fast local iteration.
 *
 * Exit codes: 0 = all gates pass · 1 = a gate failed · 2 = harness misconfigured.
 */

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// CVE tiers that mean "reachable" — the false-negative gate forbids any of
// these from being observed as `unreachable`.
const REACHABLE_TIERS = new Set(['confirmed', 'data_flow', 'function']);

export interface GroundTruthMatchLike {
  cve: string;
  observed: boolean;
  observed_reachability?: string | null;
  expected_reachability: string;
}

export interface RepoResultLike {
  name: string;
  ecosystem: string;
  status: string;
  ground_truth_matched?: GroundTruthMatchLike[];
}

export interface CorpusReport {
  results?: RepoResultLike[];
}

export interface GateReport {
  observedTotal: number;
  unreachableCount: number;
  moduleCount: number;
  /** (unreachable + 0.5*module) / observed, as a percentage. */
  noiseReductionPct: number;
  perEcosystemUnreachablePct: Record<string, number>;
  falseNegatives: Array<{ repo: string; cve: string; expected: string }>;
  gate1Pass: boolean;
  gate2Pass: boolean;
  gate3Pass: boolean;
  pass: boolean;
}

const round2 = (n: number): number => Math.round(n * 100) / 100;

/**
 * Pure gate evaluation over an oss-corpus-shaped report. Exported so the unit
 * test can exercise it without running a scan.
 */
export function evaluateReachabilityGates(report: CorpusReport): GateReport {
  let unreachableCount = 0;
  let moduleCount = 0;
  let observedTotal = 0;
  const perEco: Record<string, { unreachable: number; total: number }> = {};
  const falseNegatives: GateReport['falseNegatives'] = [];

  for (const repo of report.results ?? []) {
    if (repo.status !== 'ok') continue;
    const eco = repo.ecosystem || 'unknown';
    perEco[eco] ??= { unreachable: 0, total: 0 };
    for (const m of repo.ground_truth_matched ?? []) {
      // Only CVEs the scan actually found carry an observed reachability.
      // An unobserved CVE is a recall gap, not a reachability verdict.
      if (!m.observed || !m.observed_reachability) continue;
      observedTotal++;
      perEco[eco].total++;
      const obs = m.observed_reachability;
      if (obs === 'unreachable') {
        unreachableCount++;
        perEco[eco].unreachable++;
        if (REACHABLE_TIERS.has(m.expected_reachability)) {
          falseNegatives.push({ repo: repo.name, cve: m.cve, expected: m.expected_reachability });
        }
      } else if (obs === 'module') {
        moduleCount++;
      }
    }
  }

  const noiseReductionPct =
    observedTotal === 0 ? 0 : round2(((unreachableCount + 0.5 * moduleCount) / observedTotal) * 100);

  const perEcosystemUnreachablePct: Record<string, number> = {};
  let gate2Pass = Object.keys(perEco).length > 0;
  for (const [eco, c] of Object.entries(perEco)) {
    perEcosystemUnreachablePct[eco] = c.total === 0 ? 0 : round2((c.unreachable / c.total) * 100);
    if (c.total > 0 && c.unreachable === 0) gate2Pass = false;
  }

  const gate1Pass = noiseReductionPct >= 60;
  const gate3Pass = falseNegatives.length === 0;

  return {
    observedTotal,
    unreachableCount,
    moduleCount,
    noiseReductionPct,
    perEcosystemUnreachablePct,
    falseNegatives,
    gate1Pass,
    gate2Pass,
    gate3Pass,
    pass: gate1Pass && gate2Pass && gate3Pass,
  };
}

function printGateReport(g: GateReport): void {
  const mark = (ok: boolean) => (ok ? 'PASS' : 'FAIL');
  console.log('\n=== Reachability acceptance gates ===');
  console.log(`Observed CVEs: ${g.observedTotal} (unreachable=${g.unreachableCount}, module=${g.moduleCount})`);
  console.log(`Gate 1 — noise reduction >= 60%: ${mark(g.gate1Pass)} (${g.noiseReductionPct}%)`);
  console.log(`Gate 2 — every ecosystem > 0% unreachable: ${mark(g.gate2Pass)}`);
  for (const [eco, pct] of Object.entries(g.perEcosystemUnreachablePct)) {
    console.log(`         ${eco}: ${pct}% unreachable`);
  }
  console.log(`Gate 3 — zero reachable->unreachable false negatives: ${mark(g.gate3Pass)}`);
  for (const fn of g.falseNegatives) {
    console.log(`         FALSE NEGATIVE: ${fn.cve} in ${fn.repo} (labelled ${fn.expected}, scanned unreachable)`);
  }
  console.log(`\nResult: ${g.pass ? 'ALL GATES PASS' : 'GATES FAILED'}\n`);
}

function die(msg: string): never {
  console.error(`[reachability-corpus] ${msg}`);
  process.exit(2);
}

function main(): void {
  const depscannerRoot = path.resolve(__dirname, '..');
  const reportArg = process.argv.find((a) => a.startsWith('--report='));

  let reportPath: string;
  if (reportArg) {
    reportPath = path.resolve(reportArg.slice('--report='.length));
  } else {
    const corpusPath = path.join(depscannerRoot, 'scripts', 'reachability-corpus.yaml');
    if (!fs.existsSync(corpusPath)) die(`corpus file not found: ${corpusPath}`);
    const outputDir = fs.mkdtempSync(path.join(os.tmpdir(), 'reachability-corpus-'));
    console.log(`[reachability-corpus] scanning ${corpusPath} -> ${outputDir}`);
    const scan = spawnSync(
      'npx',
      ['tsx', 'scripts/oss-corpus.ts', `--repos=${corpusPath}`, `--output=${outputDir}`],
      { cwd: depscannerRoot, stdio: 'inherit', shell: process.platform === 'win32' },
    );
    if (scan.status !== 0) die(`oss-corpus scan failed (exit ${scan.status ?? 'signal'})`);
    reportPath = path.join(outputDir, 'report.json');
  }

  if (!fs.existsSync(reportPath)) die(`report.json not found: ${reportPath}`);
  let report: CorpusReport;
  try {
    report = JSON.parse(fs.readFileSync(reportPath, 'utf8')) as CorpusReport;
  } catch (e) {
    die(`failed to parse report.json: ${(e as Error).message}`);
  }

  const gates = evaluateReachabilityGates(report);
  printGateReport(gates);
  process.exit(gates.pass ? 0 : 1);
}

if (require.main === module) {
  main();
}
