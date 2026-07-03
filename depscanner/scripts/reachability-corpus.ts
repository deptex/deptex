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

// ── North-star silence score ─────────────────────────────────────────────────
// The gate math above weights `module` at half and only counts an observed
// `unreachable` as a false negative. But the PRODUCT auto-ignores BOTH
// `unreachable` AND `module` (phase48), so the user never sees either. This
// scores the silence decision the way the user actually experiences it:
//
//   VISIBLE  = {confirmed, data_flow, function}  — shown to the user
//   SILENCED = {unreachable, module}             — auto-ignored (depscore ~0)
//
// A reachable-labelled CVE observed as EITHER `unreachable` OR `module` is a
// SILENCE FALSE NEGATIVE — the worst failure (a real vuln hidden). The legacy
// Gate 3 misses the `module` half; this does not.

const VISIBLE_TIERS = new Set(['confirmed', 'data_flow', 'function']);
const SILENCED_TIERS = new Set(['unreachable', 'module']);

export interface SilenceScore {
  /** labelled CVEs the scan observed (carry an observed reachability). */
  labelledObserved: number;
  reachableShown: number; // reachable-labelled + shown (correct)
  reachableSilenced: number; // reachable-labelled but SILENCED — the north-star FNs
  unreachableSilenced: number; // unreachable/module-labelled + silenced (correct)
  unreachableShown: number; // unreachable/module-labelled but SHOWN — noise leak
  /** unreachableSilenced / all-silenced * 100. "When we silence, how often right."
   *  100 when nothing was silenced. */
  silencePrecisionPct: number;
  /** reachableSilenced / all-reachable * 100. THE NORTH STAR — fraction of
   *  truly-reachable vulns we wrongly hid. 0 when no reachable CVE was observed. */
  silenceFalseNegativeRatePct: number;
  /** all-silenced / labelledObserved * 100 — labelled-set noise reduction. */
  labelledNoiseReductionPct: number;
  /** unreachableShown / all-unreachable * 100 — should-be-silenced leaked as visible. */
  noiseLeakRatePct: number;
  /** product-faithful reduction over ALL observed findings:
   *  (unreachable + module) / total * 100 — the marketing headline. */
  allFindingsSilencedPct: number;
  allFindingsTotal: number;
  /** every reachable-labelled CVE that got silenced, with how (unreachable vs module). */
  falseNegatives: Array<{ repo: string; cve: string; expected: string; observed: string }>;
  perEcosystem: Record<
    string,
    { labelledObserved: number; silencedPct: number; falseNegatives: number }
  >;
  // ── App-shaped subset (excludes `shape: library` repos) ──────────────────
  // A LIBRARY repo (express/fastify) IS the framework — scanned standalone it
  // has no HTTP entry point, so its own runtime deps floor at `module`
  // correct-conservatively (they promote in a consuming APP). Reporting the
  // silence score over APP-shaped repos only is the product-faithful number:
  // "when a user scans their app, does the engine hide a reachable vuln?"
  appLabelledObserved: number;
  appReachableShown: number;
  appReachableSilenced: number;
  /** reachableSilenced / all-reachable over APP repos only — the product-faithful north star. */
  appSilenceFalseNegativeRatePct: number;
  /** unreachableSilenced / all-silenced over APP repos only. */
  appSilencePrecisionPct: number;
}

/**
 * Product-faithful silence scoring over an oss-corpus report. Pure over its
 * input so the gate unit test can exercise it without a scan. Complements
 * evaluateReachabilityGates (which stays byte-stable for the existing gates).
 */
export function evaluateSilenceScore(
  report: CorpusReport,
  libraryRepos: Set<string> = new Set(),
): SilenceScore {
  let reachableShown = 0;
  let reachableSilenced = 0;
  let unreachableSilenced = 0;
  let unreachableShown = 0;
  let allUnreachable = 0;
  let allModule = 0;
  let allFindingsTotal = 0;
  // App-shaped subset (excludes `shape: library` repos).
  let appReachableShown = 0;
  let appReachableSilenced = 0;
  let appUnreachableSilenced = 0;
  let appUnreachableShown = 0;
  const falseNegatives: SilenceScore['falseNegatives'] = [];
  const perEco: Record<string, { labelledObserved: number; silenced: number; falseNegatives: number }> = {};

  for (const repo of report.results ?? []) {
    if (repo.status !== 'ok') continue;
    const eco = repo.ecosystem || 'unknown';
    const isLibrary = libraryRepos.has(repo.name);
    perEco[eco] ??= { labelledObserved: 0, silenced: 0, falseNegatives: 0 };

    const byR = repo.by_reachability ?? {};
    allUnreachable += byR.unreachable ?? 0;
    allModule += byR.module ?? 0;
    for (const n of Object.values(byR)) allFindingsTotal += n;

    for (const m of repo.ground_truth_matched ?? []) {
      if (!m.observed || !m.observed_reachability) continue;
      const expectedVisible = VISIBLE_TIERS.has(m.expected_reachability);
      const observedSilenced = SILENCED_TIERS.has(m.observed_reachability);
      perEco[eco].labelledObserved++;
      if (observedSilenced) perEco[eco].silenced++;
      if (expectedVisible && observedSilenced) {
        reachableSilenced++;
        if (!isLibrary) appReachableSilenced++;
        perEco[eco].falseNegatives++;
        falseNegatives.push({
          repo: repo.name,
          cve: m.cve,
          expected: m.expected_reachability,
          observed: m.observed_reachability,
        });
      } else if (expectedVisible) {
        reachableShown++;
        if (!isLibrary) appReachableShown++;
      } else if (observedSilenced) {
        unreachableSilenced++;
        if (!isLibrary) appUnreachableSilenced++;
      } else {
        unreachableShown++;
        if (!isLibrary) appUnreachableShown++;
      }
    }
  }

  const labelledObserved = reachableShown + reachableSilenced + unreachableSilenced + unreachableShown;
  const totalSilenced = reachableSilenced + unreachableSilenced;
  const totalReachable = reachableShown + reachableSilenced;
  const totalUnreachable = unreachableShown + unreachableSilenced;
  const appLabelledObserved =
    appReachableShown + appReachableSilenced + appUnreachableSilenced + appUnreachableShown;
  const appTotalReachable = appReachableShown + appReachableSilenced;
  const appTotalSilenced = appReachableSilenced + appUnreachableSilenced;

  const perEcosystem: SilenceScore['perEcosystem'] = {};
  for (const [eco, c] of Object.entries(perEco)) {
    perEcosystem[eco] = {
      labelledObserved: c.labelledObserved,
      silencedPct: c.labelledObserved === 0 ? 0 : round2((c.silenced / c.labelledObserved) * 100),
      falseNegatives: c.falseNegatives,
    };
  }

  return {
    labelledObserved,
    reachableShown,
    reachableSilenced,
    unreachableSilenced,
    unreachableShown,
    silencePrecisionPct: totalSilenced === 0 ? 100 : round2((unreachableSilenced / totalSilenced) * 100),
    silenceFalseNegativeRatePct:
      totalReachable === 0 ? 0 : round2((reachableSilenced / totalReachable) * 100),
    labelledNoiseReductionPct:
      labelledObserved === 0 ? 0 : round2((totalSilenced / labelledObserved) * 100),
    noiseLeakRatePct: totalUnreachable === 0 ? 0 : round2((unreachableShown / totalUnreachable) * 100),
    allFindingsSilencedPct:
      allFindingsTotal === 0 ? 0 : round2(((allUnreachable + allModule) / allFindingsTotal) * 100),
    allFindingsTotal,
    falseNegatives,
    perEcosystem,
    appLabelledObserved,
    appReachableShown,
    appReachableSilenced,
    appSilenceFalseNegativeRatePct:
      appTotalReachable === 0 ? 0 : round2((appReachableSilenced / appTotalReachable) * 100),
    appSilencePrecisionPct:
      appTotalSilenced === 0 ? 100 : round2((appUnreachableSilenced / appTotalSilenced) * 100),
  };
}

function printSilenceScore(s: SilenceScore): void {
  console.log('\n=== Silence score (product-faithful: SILENCED = unreachable + module) ===');
  console.log(
    `Labelled+observed CVEs: ${s.labelledObserved} ` +
      `(reachable ${s.reachableShown} shown / ${s.reachableSilenced} SILENCED · ` +
      `unreachable ${s.unreachableSilenced} silenced / ${s.unreachableShown} shown)`,
  );
  console.log(
    `Noise reduction — all findings:  ${s.allFindingsSilencedPct}% silenced over ${s.allFindingsTotal} findings  <- headline`,
  );
  console.log(`Noise reduction — labelled set:  ${s.labelledNoiseReductionPct}%`);
  console.log(`Silence precision:               ${s.silencePrecisionPct}%  (when we hide, how often correct)`);
  console.log(
    `Silence FALSE-NEGATIVE rate:     ${s.silenceFalseNegativeRatePct}%  (all repos, incl. libraries)`,
  );
  console.log(
    `  App-shaped repos only:         silence-FN ${s.appSilenceFalseNegativeRatePct}% · ` +
      `precision ${s.appSilencePrecisionPct}% · over ${s.appLabelledObserved} labelled  <- NORTH STAR (product-faithful)`,
  );
  console.log(`Noise-leak rate:                 ${s.noiseLeakRatePct}%  (unreachable but shown)`);
  for (const fn of s.falseNegatives) {
    console.log(`   SILENCE FN: ${fn.cve} in ${fn.repo} — labelled ${fn.expected}, scanned ${fn.observed}`);
  }
  console.log('   Per-ecosystem:');
  for (const [eco, c] of Object.entries(s.perEcosystem)) {
    console.log(`      ${eco}: ${c.silencedPct}% silenced over ${c.labelledObserved} labelled, ${c.falseNegatives} FN`);
  }
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
  name?: string;
  shape?: string;
  ground_truth_cves?: CorpusCveLike[];
}
interface CorpusFileLike {
  repos?: CorpusRepoLike[];
}

/**
 * Repo names annotated `shape: library` in the corpus YAML. A library repo IS a
 * framework (express/fastify) — scanned standalone it has no HTTP entry point,
 * so its own runtime deps floor at `module` correct-conservatively (they promote
 * in a consuming app). The silence score excludes these from the product-faithful
 * app-shaped false-negative rate.
 */
export function loadLibraryRepos(corpusPath: string): Set<string> {
  const doc = yaml.load(fs.readFileSync(corpusPath, 'utf8')) as CorpusFileLike;
  const libs = new Set<string>();
  for (const repo of doc?.repos ?? []) {
    if (repo?.name && repo.shape === 'library') libs.add(repo.name);
  }
  return libs;
}

/**
 * CVE id → the SET of expected_reachability labels across every repo in the
 * corpus YAML. A single CVE legitimately carries DIFFERENT labels in different
 * apps — the same Spring/Tomcat/Rack CVE is `function` in an app that serves
 * static content (spring-petclinic) and `module`/`unreachable` in a REST API
 * that does not (spring-security-polls); two Rails apps (discourse+mastodon)
 * and two Go apps likewise share CVE ids at different reachability. Keying a
 * flat last-write-wins map broke the baseline lock the moment the corpus held
 * two apps of one framework, so this returns every observed label per CVE.
 */
export function loadCorpusCveLabels(corpusPath: string): Map<string, string[]> {
  const doc = yaml.load(fs.readFileSync(corpusPath, 'utf8')) as CorpusFileLike;
  const labels = new Map<string, string[]>();
  for (const repo of doc?.repos ?? []) {
    for (const cve of repo.ground_truth_cves ?? []) {
      if (!cve?.id || !cve.expected_reachability) continue;
      const arr = labels.get(cve.id) ?? [];
      if (!arr.includes(cve.expected_reachability)) arr.push(cve.expected_reachability);
      labels.set(cve.id, arr);
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
export function checkBaselineLock(corpusLabels: Map<string, string[]>, lockedLabels: Record<string, string>): BaselineLockResult {
  const violations: string[] = [];
  for (const [cve, expected] of Object.entries(lockedLabels)) {
    const current = corpusLabels.get(cve);
    if (current === undefined || current.length === 0) {
      violations.push(`${cve}: frozen label '${expected}' but the CVE is no longer in the corpus`);
    } else if (!current.includes(expected)) {
      // The frozen label must still exist in SOME app — a new app adding its own
      // app-specific label for the same CVE is fine; QUIETLY RELABELLING the
      // frozen app's CVE (so the frozen label survives nowhere) is the violation.
      violations.push(`${cve}: frozen label '${expected}' but the corpus now says '${current.join("', '")}'`);
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

// ── Independent oracle ──────────────────────────────────────────────────────
// Cross-checks the scan against an independent production-call-path verdict.
// See scripts/reachability-corpus-oracle.yaml for the rationale.

export interface OracleVerdict {
  id: string;
  /** reachable | module | unreachable — the production-call-path verdict. */
  verdict: string;
}

export interface OracleResult {
  ok: boolean;
  /** Oracle-`reachable` CVEs the scan observed `unreachable` — false negatives. */
  disagreements: Array<{ cve: string; observed: string }>;
}

/** cve → observed_reachability across every ok repo in the report. */
export function buildObservedMap(report: CorpusReport): Map<string, string> {
  const observed = new Map<string, string>();
  for (const repo of report.results ?? []) {
    if (repo.status !== 'ok') continue;
    for (const m of repo.ground_truth_matched ?? []) {
      if (m.observed && m.observed_reachability) observed.set(m.cve, m.observed_reachability);
    }
  }
  return observed;
}

/**
 * Cross-check the independent oracle against the scan. The oracle judges each
 * CVE on the production-call-path question alone; an oracle `reachable`
 * verdict for a CVE the scan observed `unreachable` is a false negative — the
 * classifier hid a vuln the oracle says runs — and fails the run. `module`
 * verdicts never gate (a module dep observed `unreachable` is an accepted
 * over-classification). Pure over its inputs so the gate test can exercise it.
 */
export function checkOracle(
  oracleVerdicts: OracleVerdict[],
  observed: Map<string, string>,
): OracleResult {
  const disagreements: OracleResult['disagreements'] = [];
  for (const v of oracleVerdicts) {
    if (v.verdict !== 'reachable') continue;
    const obs = observed.get(v.id);
    if (obs === 'unreachable') disagreements.push({ cve: v.id, observed: obs });
  }
  return { ok: disagreements.length === 0, disagreements };
}

function printOracleResult(r: OracleResult, verdictCount: number): void {
  const mark = r.ok ? 'PASS' : 'FAIL';
  console.log(`\nOracle agreement — ${verdictCount} independent verdicts, zero reachable->unreachable: ${mark}`);
  for (const d of r.disagreements) {
    console.log(`         ORACLE DISAGREEMENT: ${d.cve} judged reachable, scanned ${d.observed}`);
  }
}

function main(): void {
  const depscannerRoot = path.resolve(__dirname, '..');
  const corpusPath = path.join(depscannerRoot, 'scripts', 'reachability-corpus.yaml');
  const lockPath = path.join(depscannerRoot, 'scripts', 'reachability-corpus-baseline.lock.yaml');
  const oraclePath = path.join(depscannerRoot, 'scripts', 'reachability-corpus-oracle.yaml');
  const reportArg = process.argv.find((a) => a.startsWith('--report='));

  // Baseline-lock check — static, independent of the scan. Runs in both the
  // scan and the --report= path so a relabelled baseline fails fast.
  if (!fs.existsSync(corpusPath)) die(`corpus file not found: ${corpusPath}`);
  if (!fs.existsSync(lockPath)) die(`baseline lock not found: ${lockPath}`);
  if (!fs.existsSync(oraclePath)) die(`oracle file not found: ${oraclePath}`);
  const lockedLabels =
    ((yaml.load(fs.readFileSync(lockPath, 'utf8')) as { labels?: Record<string, string> })?.labels) ?? {};
  const baseline = checkBaselineLock(loadCorpusCveLabels(corpusPath), lockedLabels);
  const oracleVerdicts =
    ((yaml.load(fs.readFileSync(oraclePath, 'utf8')) as { verdicts?: OracleVerdict[] })?.verdicts) ?? [];

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
  const oracle = checkOracle(oracleVerdicts, buildObservedMap(report));
  const silence = evaluateSilenceScore(report, loadLibraryRepos(corpusPath));
  printGateReport(gates);
  printBaselineResult(baseline, Object.keys(lockedLabels).length);
  printOracleResult(oracle, oracleVerdicts.length);
  printSilenceScore(silence);

  // Persist the silence score next to the report so a baseline-vs-final compare
  // can diff the two numbers without re-deriving them from report.json.
  try {
    fs.writeFileSync(
      path.join(path.dirname(reportPath), 'silence-score.json'),
      JSON.stringify(silence, null, 2),
    );
  } catch {
    /* best-effort; the stdout print is the primary output */
  }

  process.exit(gates.pass && baseline.ok && oracle.ok ? 0 : 1);
}

if (require.main === module) {
  main();
}
