/**
 * Unit tests for the M8 atom A/B benchmark + retirement-gate harness.
 *
 * Covers:
 *   - corpus loader: valid + missing-required + bad-shape JSON
 *   - comparator: full hit, partial hit (sinkFile mismatch),
 *     vuln-class mismatch (engine), atom ignoreVulnClass, regressions, new detections
 *   - report builder: percentages, deltaPp, perProject + regressions/newDetections wired
 *   - HTML report: smoke check that renderHtml emits well-formed structure
 *   - gates evaluator: all-pass → GO, missing window → EXTEND_SHADOW, failing
 *     gate → NO_GO with blocker id
 *   - rollout override: env-var-only behavior is preserved when no override row
 *     exists; override=100 forces true; override=0 forces false
 *
 * Run: npx tsx test/taint-engine-benchmark.test.ts
 */
/* eslint-disable @typescript-eslint/no-explicit-any */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  CorpusLoadError,
  buildReport,
  compareCorpus,
  evaluateRetirementGates,
  loadCorpus,
  validateCorpus,
  writeHtmlReport,
  writeJsonReport,
  type BenchmarkCorpus,
  type BenchmarkReport,
  type CandidateFlow,
} from '../src/taint-engine/benchmark';
import { createPGLiteStorage } from '../src/storage';
import { shouldRunForOrg } from '../src/taint-engine/runner';

let failures = 0;
let passes = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passes++;
  }
}

function assertThrows(fn: () => unknown, expectedSubstr: RegExp | string, msg: string): void {
  try {
    fn();
    console.error(`  FAIL: ${msg} (no throw)`);
    failures++;
  } catch (err) {
    const m = (err as Error).message;
    if (typeof expectedSubstr === 'string') {
      if (m.includes(expectedSubstr)) {
        console.log(`  ok: ${msg}`);
        passes++;
      } else {
        console.error(`  FAIL: ${msg} (got: ${m})`);
        failures++;
      }
    } else if (expectedSubstr.test(m)) {
      console.log(`  ok: ${msg}`);
      passes++;
    } else {
      console.error(`  FAIL: ${msg} (got: ${m})`);
      failures++;
    }
  }
}

// ---------------------------------------------------------------------------
// Corpus loader
// ---------------------------------------------------------------------------

function testCorpusValidate() {
  console.log('\n[test] validateCorpus accepts a minimal valid shape');
  const minimal: BenchmarkCorpus = validateCorpus({
    name: 't1',
    projects: [
      {
        id: 'p1',
        ecosystem: 'npm',
        path: '/tmp/p1',
        expectedFindings: [{ cve: 'CVE-2021-1', vulnClass: 'sql_injection', sinkFile: 'src/index.js' }],
      },
    ],
  });
  assert(minimal.name === 't1', 'name parsed');
  assert(minimal.projects[0].id === 'p1', 'project id parsed');
  assert(minimal.projects[0].expectedFindings[0].cve === 'CVE-2021-1', 'finding cve parsed');

  console.log('\n[test] validateCorpus rejects missing fields');
  assertThrows(
    () => validateCorpus({ projects: [] }),
    /name/,
    'missing name throws',
  );
  assertThrows(
    () => validateCorpus({ name: 'x', projects: [] }),
    /non-empty array/,
    'empty projects throws',
  );
  assertThrows(
    () => validateCorpus({ name: 'x', projects: [{ id: 'a', ecosystem: 'npm', expectedFindings: [] }] }),
    /path.*git/,
    'project with neither path nor git throws',
  );
  assertThrows(
    () => validateCorpus({
      name: 'x',
      projects: [{ id: 'a', ecosystem: 'npm', path: '/x', git: 'g', expectedFindings: [] }],
    }),
    /exactly one/,
    'project with both path and git throws',
  );

  console.log('\n[test] loadCorpus reads + validates a file');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'm8-corpus-'));
  const corpusPath = path.join(tmp, 'corpus.json');
  fs.writeFileSync(corpusPath, JSON.stringify({
    name: 'tiny',
    projects: [{ id: 'a', ecosystem: 'npm', path: '/x', expectedFindings: [] }],
  }));
  const c = loadCorpus(corpusPath);
  assert(c.name === 'tiny', 'loadCorpus parsed JSON file');

  assertThrows(
    () => loadCorpus(path.join(tmp, 'missing.json')),
    /failed to read/,
    'loadCorpus throws CorpusLoadError on missing file',
  );

  fs.writeFileSync(corpusPath, '{ not json');
  assertThrows(
    () => loadCorpus(corpusPath),
    /not valid JSON/,
    'loadCorpus throws on malformed JSON',
  );

  fs.rmSync(tmp, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Comparator
// ---------------------------------------------------------------------------

function makeProject(id: string, findings: Array<{ cve: string; vulnClass?: string; sinkFile?: string; sinkPattern?: string }>): BenchmarkCorpus['projects'][number] {
  return {
    id,
    ecosystem: 'npm',
    path: `/tmp/${id}`,
    expectedFindings: findings,
  };
}

function makeFlow(overrides: Partial<CandidateFlow> = {}): CandidateFlow {
  return {
    vulnClass: 'sql_injection',
    sinkFile: 'src/server.js',
    sinkMethod: 'db.query',
    sinkPattern: '*.query',
    ...overrides,
  };
}

function testComparator() {
  console.log('\n[test] compareCorpus: matching engine flow → both engines hit (engine matches vuln class, atom ignores)');
  const corpus: BenchmarkCorpus = {
    name: 'c1',
    projects: [
      makeProject('p1', [
        { cve: 'CVE-1', vulnClass: 'sql_injection', sinkFile: 'src/server.js', sinkPattern: 'query' },
      ]),
    ],
  };
  const flowA = makeFlow();
  const recall = compareCorpus(corpus, new Map([['p1', { atom: [flowA], engine: [flowA] }]]));
  assert(recall.atom.matched === 1, 'atom matched=1');
  assert(recall.taintEngine.matched === 1, 'engine matched=1');
  assert(recall.newDetections.length === 0, 'no new detections when both hit');
  assert(recall.regressions.length === 0, 'no regressions when both hit');

  console.log('\n[test] compareCorpus: engine vuln class mismatch → engine miss, atom hit (regression)');
  const flowMismatch = makeFlow({ vulnClass: 'xss' });
  const r2 = compareCorpus(corpus, new Map([['p1', { atom: [flowMismatch], engine: [flowMismatch] }]]));
  assert(r2.atom.matched === 1, 'atom hit (vuln class ignored)');
  assert(r2.taintEngine.matched === 0, 'engine missed on vuln class mismatch');
  assert(r2.regressions.length === 1, 'regression recorded');

  console.log('\n[test] compareCorpus: engine-only hit when atom output is empty → newDetections');
  const r3 = compareCorpus(corpus, new Map([['p1', { atom: [], engine: [flowA] }]]));
  assert(r3.atom.matched === 0, 'atom missed (no candidates)');
  assert(r3.taintEngine.matched === 1, 'engine hit');
  assert(r3.newDetections.length === 1, 'newDetection recorded');

  console.log('\n[test] compareCorpus: sinkFile suffix mismatch → both miss');
  const corpusStrictPath: BenchmarkCorpus = {
    name: 'c2',
    projects: [makeProject('p2', [{ cve: 'CVE-2', sinkFile: 'src/exact.js' }])],
  };
  const flowDiffPath = makeFlow({ sinkFile: 'src/other.js' });
  const r4 = compareCorpus(corpusStrictPath, new Map([['p2', { atom: [flowDiffPath], engine: [flowDiffPath] }]]));
  assert(r4.atom.matched === 0, 'atom missed on sinkFile mismatch');
  assert(r4.taintEngine.matched === 0, 'engine missed on sinkFile mismatch');

  console.log('\n[test] compareCorpus: project absent from results map → both engines empty');
  const r5 = compareCorpus(corpus, new Map());
  assert(r5.atom.expected === 1 && r5.atom.matched === 0, 'atom expected=1 matched=0');
  assert(r5.taintEngine.matched === 0, 'engine matched=0');
}

// ---------------------------------------------------------------------------
// Report builder
// ---------------------------------------------------------------------------

function testReportBuilder() {
  console.log('\n[test] buildReport computes percentages and delta');
  const corpus: BenchmarkCorpus = {
    name: 'r1',
    projects: [
      makeProject('p1', [
        { cve: 'CVE-A', vulnClass: 'sql_injection' },
        { cve: 'CVE-B', vulnClass: 'xss' },
      ]),
    ],
  };
  const flowA = makeFlow();
  const flowXss = makeFlow({ vulnClass: 'xss' });
  const recall = compareCorpus(corpus, new Map([['p1', { atom: [flowA], engine: [flowA, flowXss] }]]));
  const report = buildReport({ corpus, recall });
  assert(report.recall.atom.expected === 2, 'expected=2');
  assert(report.recall.atom.matched === 2, 'atom matched both (ignoreVulnClass)');
  assert(report.recall.taintEngine.matched === 2, 'engine matched both with class match');
  assert(report.recall.atom.pct === 100, 'atom pct = 100');
  assert(report.recall.deltaPp === 0, 'deltaPp = 0 when both at 100');
  assert(report.perProject.length === 1, 'perProject has one row');
  assert(report.perProject[0].findings[0].atom === 'hit', 'p1 atom hit recorded');

  console.log('\n[test] writeJsonReport / writeHtmlReport produce files');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'm8-rpt-'));
  const jsonFile = writeJsonReport(tmp, report);
  const htmlFile = writeHtmlReport(tmp, report);
  assert(fs.existsSync(jsonFile), 'json file exists');
  assert(fs.existsSync(htmlFile), 'html file exists');
  const html = fs.readFileSync(htmlFile, 'utf8');
  assert(html.includes('<!doctype html>'), 'html has doctype');
  assert(html.includes('Taint Engine vs atom'), 'html has heading');
  assert(html.includes(report.recall.taintEngine.pct.toFixed(1)), 'html embeds engine pct');
  fs.rmSync(tmp, { recursive: true, force: true });
}

// ---------------------------------------------------------------------------
// Retirement gates
// ---------------------------------------------------------------------------

async function testGatesAllPass() {
  console.log('\n[test] evaluateRetirementGates: all gates pass → GO');
  const storage = await createPGLiteStorage();
  const orgId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
  const projectId = 'cccccccc-bbbb-cccc-dddd-eeeeeeeeeeee';
  await storage.from('organizations').insert({ id: orgId, name: 'gates-test', created_at: new Date().toISOString() });
  await storage.from('projects').insert({ id: projectId, organization_id: orgId, name: 'p', created_at: new Date().toISOString() });
  // Seed 50 successful runs, no failures, $0.05 cost each, 5000ms total_ms.
  const rows: any[] = [];
  for (let i = 0; i < 50; i++) {
    rows.push({
      project_id: projectId,
      organization_id: orgId,
      extraction_run_id: `run_${i}`,
      status: 'completed',
      ai_cost_usd: 0.05,
      total_ms: 5000,
      flows_emitted: 3,
      flows_after_ai_filter: 3,
      created_at: new Date().toISOString(),
    });
  }
  await storage.from('taint_engine_runs').insert(rows);

  const report: BenchmarkReport = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    corpus: { name: 'gates', projectCount: 1, ecosystems: ['npm'] },
    recall: {
      atom: { expected: 10, matched: 7, pct: 70 },
      taintEngine: { expected: 10, matched: 8, pct: 80 },
      deltaPp: 10,
    },
    perProject: [],
    newDetections: [],
    regressions: [],
  };

  const result = await evaluateRetirementGates({
    storage,
    shadowPeriodDays: 30,
    benchmarkReport: report,
  });
  assert(result.recommendation === 'GO', `recommendation=GO (got ${result.recommendation})`);
  assert(result.blockers.length === 0, `no blockers (got ${result.blockers.join(',')})`);
  assert(result.shadowStats.totalRuns === 50, 'totalRuns=50');
}

async function testGatesFailureRate() {
  console.log('\n[test] evaluateRetirementGates: high failure rate → NO_GO with reliability blocker');
  const storage = await createPGLiteStorage();
  const orgId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeefe';
  const projectId = 'cccccccc-bbbb-cccc-dddd-eeeeeeeeeefe';
  await storage.from('organizations').insert({ id: orgId, name: 'gates-fail', created_at: new Date().toISOString() });
  await storage.from('projects').insert({ id: projectId, organization_id: orgId, name: 'p', created_at: new Date().toISOString() });
  const rows: any[] = [];
  // 30 completed + 10 failed → 25% failure rate, way over 1%.
  for (let i = 0; i < 30; i++) {
    rows.push({
      project_id: projectId,
      organization_id: orgId,
      extraction_run_id: `ok_${i}`,
      status: 'completed',
      ai_cost_usd: 0.05,
      total_ms: 5000,
      created_at: new Date().toISOString(),
    });
  }
  for (let i = 0; i < 10; i++) {
    rows.push({
      project_id: projectId,
      organization_id: orgId,
      extraction_run_id: `fail_${i}`,
      status: 'failed',
      created_at: new Date().toISOString(),
    });
  }
  await storage.from('taint_engine_runs').insert(rows);

  const report: BenchmarkReport = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    corpus: { name: 'gates', projectCount: 1, ecosystems: ['npm'] },
    recall: {
      atom: { expected: 10, matched: 7, pct: 70 },
      taintEngine: { expected: 10, matched: 8, pct: 80 },
      deltaPp: 10,
    },
    perProject: [],
    newDetections: [],
    regressions: [],
  };

  const result = await evaluateRetirementGates({
    storage,
    shadowPeriodDays: 30,
    benchmarkReport: report,
  });
  assert(result.recommendation === 'NO_GO', `recommendation=NO_GO (got ${result.recommendation})`);
  assert(result.blockers.includes('reliability'), `blocker=reliability (got ${result.blockers.join(',')})`);
}

async function testGatesInsufficientWindow() {
  console.log('\n[test] evaluateRetirementGates: too few runs → EXTEND_SHADOW');
  const storage = await createPGLiteStorage();
  const orgId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeefea';
  const projectId = 'cccccccc-bbbb-cccc-dddd-eeeeeeeeefea';
  await storage.from('organizations').insert({ id: orgId, name: 'gates-few', created_at: new Date().toISOString() });
  await storage.from('projects').insert({ id: projectId, organization_id: orgId, name: 'p', created_at: new Date().toISOString() });
  // Only 5 runs (< MIN_SHADOW_RUNS_FOR_VERDICT=30) → reliability gate inconclusive.
  const rows: any[] = [];
  for (let i = 0; i < 5; i++) {
    rows.push({
      project_id: projectId,
      organization_id: orgId,
      extraction_run_id: `tiny_${i}`,
      status: 'completed',
      ai_cost_usd: 0.05,
      total_ms: 5000,
      created_at: new Date().toISOString(),
    });
  }
  await storage.from('taint_engine_runs').insert(rows);

  const report: BenchmarkReport = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    corpus: { name: 'gates', projectCount: 1, ecosystems: ['npm'] },
    recall: {
      atom: { expected: 10, matched: 7, pct: 70 },
      taintEngine: { expected: 10, matched: 7, pct: 70 },
      deltaPp: 0,
    },
    perProject: [],
    newDetections: [],
    regressions: [],
  };

  const result = await evaluateRetirementGates({
    storage,
    shadowPeriodDays: 30,
    benchmarkReport: report,
  });
  assert(result.recommendation === 'EXTEND_SHADOW', `recommendation=EXTEND_SHADOW (got ${result.recommendation})`);
  const reliability = result.gates.find((g) => g.id === 'reliability');
  assert(reliability?.outcome === 'inconclusive', `reliability inconclusive (got ${reliability?.outcome})`);
}

// ---------------------------------------------------------------------------
// Per-org rollout override
// ---------------------------------------------------------------------------

async function testRolloutOverride() {
  console.log('\n[test] shouldRunForOrg: override=100 → true; override=0 → false; null → env');
  const storage = await createPGLiteStorage();
  const orgIdOn = '11111111-aaaa-cccc-dddd-eeeeeeeeeeee';
  const orgIdOff = '22222222-aaaa-cccc-dddd-eeeeeeeeeeee';
  const orgIdDefault = '33333333-aaaa-cccc-dddd-eeeeeeeeeeee';
  await storage.from('organizations').insert([
    { id: orgIdOn, name: 'on', created_at: new Date().toISOString() },
    { id: orgIdOff, name: 'off', created_at: new Date().toISOString() },
    { id: orgIdDefault, name: 'default', created_at: new Date().toISOString() },
  ]);
  await storage.from('taint_engine_settings').insert([
    { organization_id: orgIdOn, rollout_pct_override: 100 },
    { organization_id: orgIdOff, rollout_pct_override: 0 },
    // orgIdDefault has no settings row → fall back to env-var path.
  ]);

  const onResult = await shouldRunForOrg(storage, orgIdOn, { DEPTEX_TAINT_ENGINE_ROLLOUT_PCT: '0', NODE_ENV: 'production' });
  assert(onResult === true, 'override=100 forces true even when env says 0');

  const offResult = await shouldRunForOrg(storage, orgIdOff, { DEPTEX_TAINT_ENGINE_ROLLOUT_PCT: '100', NODE_ENV: 'production' });
  assert(offResult === false, 'override=0 forces false even when env says 100');

  const defaultEnvOff = await shouldRunForOrg(storage, orgIdDefault, { DEPTEX_TAINT_ENGINE_ROLLOUT_PCT: '0', NODE_ENV: 'production' });
  assert(defaultEnvOff === false, 'no override → env says 0 → false');

  const defaultEnvOn = await shouldRunForOrg(storage, orgIdDefault, { DEPTEX_TAINT_ENGINE_ROLLOUT_PCT: '100', NODE_ENV: 'production' });
  assert(defaultEnvOn === true, 'no override → env says 100 → true');
}

// ---------------------------------------------------------------------------

async function main() {
  testCorpusValidate();
  testComparator();
  testReportBuilder();
  await testGatesAllPass();
  await testGatesFailureRate();
  await testGatesInsufficientWindow();
  await testRolloutOverride();

  console.log(`\n${passes} passed, ${failures} failed`);
  if (failures > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
