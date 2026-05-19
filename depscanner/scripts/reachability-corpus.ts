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
import * as yaml from 'js-yaml';

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
  /** Reachability-level counts across all observed findings (set by oss-corpus). */
  by_reachability?: Record<string, number>;
}

export interface CorpusReport {
  results?: RepoResultLike[];
}

/** Minimum corpus recall below which Gate 1 cannot be reported as a pass —
 *  a shrinking observed set would otherwise silently flatter the metric. */
const RECALL_FLOOR_PCT = 90;

export interface GateReport {
  observedTotal: number;
  unreachableCount: number;
  moduleCount: number;
  /** (unreachable + 0.5*module) / observed, as a percentage. */
  noiseReductionPct: number;
  /** Full-weight unreachable-only rate (unreachable / observed) — the honest
   *  number, with no `module` half-credit. Reported alongside noiseReductionPct. */
  unreachableOnlyPct: number;
  perEcosystemUnreachablePct: Record<string, number>;
  falseNegatives: Array<{ repo: string; cve: string; expected: string }>;
  /** Hand-labelled CVEs the scan never found — a recall gap, not a verdict. */
  unobservedCves: Array<{ repo: string; cve: string }>;
  /** observed ground-truth CVEs / total ground-truth CVEs, as a percentage. */
  recallPct: number;
  /** Noise reduction over ALL observed findings, not just the hand-labelled
   *  allowlist. Informational, never gated — a large gap from noiseReductionPct
   *  flags allowlist selection bias. 0 when oss-corpus emitted no by_reachability. */
  allFindingsNoiseReductionPct: number;
  allFindingsTotal: number;
  gate1Pass: boolean;
  gate2Pass: boolean;
  gate3Pass: boolean;
  /** Recall >= floor AND zero unobserved CVEs — guards a shrinking denominator. */
  recallFloorPass: boolean;
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
  let groundTruthTotal = 0;
  const perEco: Record<string, { unreachable: number; total: number }> = {};
  const falseNegatives: GateReport['falseNegatives'] = [];
  const unobservedCves: GateReport['unobservedCves'] = [];
  let allUnreachable = 0;
  let allModule = 0;
  let allFindingsTotal = 0;

  for (const repo of report.results ?? []) {
    if (repo.status !== 'ok') continue;
    const eco = repo.ecosystem || 'unknown';
    perEco[eco] ??= { unreachable: 0, total: 0 };

    // All-findings tally — every observed finding, not just the allowlist.
    const byR = repo.by_reachability ?? {};
    allUnreachable += byR.unreachable ?? 0;
    allModule += byR.module ?? 0;
    for (const n of Object.values(byR)) allFindingsTotal += n;
    for (const m of repo.ground_truth_matched ?? []) {
      groundTruthTotal++;
      // Only CVEs the scan actually found carry an observed reachability.
      // An unobserved CVE is a recall gap, not a reachability verdict — it
      // is excluded from the noise-reduction math but tracked for the
      // recall floor so a shrinking observed set cannot flatter Gate 1.
      if (!m.observed || !m.observed_reachability) {
        unobservedCves.push({ repo: repo.name, cve: m.cve });
        continue;
      }
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
  const unreachableOnlyPct =
    observedTotal === 0 ? 0 : round2((unreachableCount / observedTotal) * 100);
  const recallPct =
    groundTruthTotal === 0 ? 0 : round2((observedTotal / groundTruthTotal) * 100);
  const allFindingsNoiseReductionPct =
    allFindingsTotal === 0
      ? 0
      : round2(((allUnreachable + 0.5 * allModule) / allFindingsTotal) * 100);

  const perEcosystemUnreachablePct: Record<string, number> = {};
  let gate2Pass = Object.keys(perEco).length > 0;
  for (const [eco, c] of Object.entries(perEco)) {
    perEcosystemUnreachablePct[eco] = c.total === 0 ? 0 : round2((c.unreachable / c.total) * 100);
    if (c.total > 0 && c.unreachable === 0) gate2Pass = false;
  }

  const gate1Pass = noiseReductionPct >= 60;
  const gate3Pass = falseNegatives.length === 0;
  // A pass is only meaningful over a corpus the scan actually found: low
  // recall, or any unobserved hand-labelled CVE, shrinks the denominator.
  const recallFloorPass = recallPct >= RECALL_FLOOR_PCT && unobservedCves.length === 0;

  return {
    observedTotal,
    unreachableCount,
    moduleCount,
    noiseReductionPct,
    unreachableOnlyPct,
    perEcosystemUnreachablePct,
    falseNegatives,
    unobservedCves,
    recallPct,
    allFindingsNoiseReductionPct,
    allFindingsTotal,
    gate1Pass,
    gate2Pass,
    gate3Pass,
    recallFloorPass,
    pass: gate1Pass && gate2Pass && gate3Pass && recallFloorPass,
  };
}

function printGateReport(g: GateReport): void {
  const mark = (ok: boolean) => (ok ? 'PASS' : 'FAIL');
  console.log('\n=== Reachability acceptance gates ===');
  console.log(`Observed CVEs: ${g.observedTotal} (unreachable=${g.unreachableCount}, module=${g.moduleCount})`);
  console.log(
    `Gate 1 — noise reduction >= 60%: ${mark(g.gate1Pass)} ` +
      `(${g.noiseReductionPct}% module-weighted | ${g.unreachableOnlyPct}% unreachable-only)`,
  );
  console.log(`Gate 2 — every ecosystem > 0% unreachable: ${mark(g.gate2Pass)}`);
  for (const [eco, pct] of Object.entries(g.perEcosystemUnreachablePct)) {
    console.log(`         ${eco}: ${pct}% unreachable`);
  }
  console.log(`Gate 3 — zero reachable->unreachable false negatives: ${mark(g.gate3Pass)}`);
  for (const fn of g.falseNegatives) {
    console.log(`         FALSE NEGATIVE: ${fn.cve} in ${fn.repo} (labelled ${fn.expected}, scanned unreachable)`);
  }
  console.log(
    `Recall floor — >= ${RECALL_FLOOR_PCT}% observed, zero unobserved: ` +
      `${mark(g.recallFloorPass)} (${g.recallPct}% recall)`,
  );
  for (const u of g.unobservedCves) {
    console.log(`         UNOBSERVED: ${u.cve} in ${u.repo} (hand-labelled but the scan never found it)`);
  }
  if (g.allFindingsTotal > 0) {
    console.log(
      `All-findings noise reduction (informational, not gated): ` +
        `${g.allFindingsNoiseReductionPct}% over ${g.allFindingsTotal} observed findings`,
    );
  }
  console.log(`\nResult: ${g.pass ? 'ALL GATES PASS' : 'GATES FAILED'}\n`);
}

function die(msg: string): never {
  console.error(`[reachability-corpus] ${msg}`);
  process.exit(2);
}

// ── Baseline lock ───────────────────────────────────────────────────────────
// Asserts no pre-feature `expected_reachability` label was silently changed.
// See scripts/reachability-corpus-baseline.lock.yaml for the rationale.

interface CorpusCveLike {
  id?: string;
  expected_reachability?: string;
}
interface CorpusRepoLike {
  ground_truth_cves?: CorpusCveLike[];
}
interface CorpusFileLike {
  repos?: CorpusRepoLike[];
}

/** CVE id → expected_reachability across every repo in the corpus YAML. */
export function loadCorpusCveLabels(corpusPath: string): Map<string, string> {
  const doc = yaml.load(fs.readFileSync(corpusPath, 'utf8')) as CorpusFileLike;
  const labels = new Map<string, string>();
  for (const repo of doc?.repos ?? []) {
    for (const cve of repo.ground_truth_cves ?? []) {
      if (cve?.id && cve.expected_reachability) labels.set(cve.id, cve.expected_reachability);
    }
  }
  return labels;
}

export interface BaselineLockResult {
  ok: boolean;
  /** Frozen CVEs whose live label changed or that were removed from the corpus. */
  violations: string[];
}

/**
 * Assert every frozen pre-feature label still matches the live corpus. A
 * changed label — or a deleted CVE — is a violation: the noise-reduction
 * number must not be flattered by quietly relabelling the baseline. Pure over
 * its two file inputs so the gate unit test can exercise it.
 */
export function checkBaselineLock(corpusLabels: Map<string, string>, lockedLabels: Record<string, string>): BaselineLockResult {
  const violations: string[] = [];
  for (const [cve, expected] of Object.entries(lockedLabels)) {
    const current = corpusLabels.get(cve);
    if (current === undefined) {
      violations.push(`${cve}: frozen label '${expected}' but the CVE is no longer in the corpus`);
    } else if (current !== expected) {
      violations.push(`${cve}: frozen label '${expected}' but the corpus now says '${current}'`);
    }
  }
  return { ok: violations.length === 0, violations };
}

function printBaselineResult(r: BaselineLockResult, lockedCount: number): void {
  const mark = r.ok ? 'PASS' : 'FAIL';
  console.log(`\nBaseline lock — ${lockedCount} frozen pre-feature labels unchanged: ${mark}`);
  for (const v of r.violations) {
    console.log(`         BASELINE DRIFT: ${v}`);
  }
}

function main(): void {
  const depscannerRoot = path.resolve(__dirname, '..');
  const corpusPath = path.join(depscannerRoot, 'scripts', 'reachability-corpus.yaml');
  const lockPath = path.join(depscannerRoot, 'scripts', 'reachability-corpus-baseline.lock.yaml');
  const reportArg = process.argv.find((a) => a.startsWith('--report='));

  // Baseline-lock check — static, independent of the scan. Runs in both the
  // scan and the --report= path so a relabelled baseline fails fast.
  if (!fs.existsSync(corpusPath)) die(`corpus file not found: ${corpusPath}`);
  if (!fs.existsSync(lockPath)) die(`baseline lock not found: ${lockPath}`);
  const lockedLabels =
    ((yaml.load(fs.readFileSync(lockPath, 'utf8')) as { labels?: Record<string, string> })?.labels) ?? {};
  const baseline = checkBaselineLock(loadCorpusCveLabels(corpusPath), lockedLabels);

  let reportPath: string;
  if (reportArg) {
    reportPath = path.resolve(reportArg.slice('--report='.length));
  } else {
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
  printBaselineResult(baseline, Object.keys(lockedLabels).length);

  process.exit(gates.pass && baseline.ok ? 0 : 1);
}

if (require.main === module) {
  main();
}
