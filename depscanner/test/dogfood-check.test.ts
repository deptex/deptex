/**
 * Self-tests for the dogfood-check harness.
 *
 * Asserts the pure diff logic stays correct on the 8 mutation cases
 * specified in the dogfood plan (M1.7 Patch E). Uses the repo's tsx +
 * simple-assert convention instead of vitest (which isn't a dep).
 *
 * Run: `npx tsx test/dogfood-check.test.ts`
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  ActualFindings,
  ExpectedYaml,
  diffExpectedVsActual,
  findOsvMatch,
  loadExpected,
  matchesReachabilityBucket,
} from '../scripts/dogfood-check';

let failures = 0;

function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
  }
}

// --- shared shape for the golden case (used as a base by each mutation) ---

function goldenExpected(): ExpectedYaml {
  return {
    reachable_vulns: [
      {
        osv_id: 'CVE-2021-23337',
        aliases: ['GHSA-35jh-r3h4-6jhm'],
        reachability_bucket: 'reachable',
      },
    ],
    unreachable_vulns: [
      {
        osv_id: 'CVE-2020-28500',
        aliases: ['GHSA-29mw-wpgm-hmr9'],
        reachability_bucket: 'unreachable',
      },
    ],
    iac_findings: [{ rule_id: 'CKV_DOCKER_3', file: 'Dockerfile', line: 5 }],
    secrets: [{ rule_id: 'aws-secret-key', file: '.env.example', line: 3 }],
    semgrep_findings: [
      {
        rule_id: 'javascript.express.security.injection.tainted-sql-string',
        file: 'routes/api.js',
        line: 18,
      },
    ],
  };
}

function goldenActual(): ActualFindings {
  return {
    vulns: [
      {
        osv_id: 'CVE-2021-23337',
        aliases: ['GHSA-35jh-r3h4-6jhm'],
        reachability_level: 'confirmed',
      },
      {
        osv_id: 'CVE-2020-28500',
        aliases: ['GHSA-29mw-wpgm-hmr9'],
        reachability_level: 'unreachable',
      },
    ],
    iac: [{ rule_id: 'CKV_DOCKER_3', file_path: 'Dockerfile' }],
    container: [],
    secrets: [{ detector_type: 'aws-secret-key', file_path: '.env.example' }],
    malicious: [],
    semgrep: [
      {
        rule_id: 'javascript.express.security.injection.tainted-sql-string',
        file_path: 'routes/api.js',
      },
    ],
    dast: [],
  };
}

// --- Case (a): golden expected.yaml + matching findings → PASS ---

console.log('\n(a) golden → PASS');
{
  const diff = diffExpectedVsActual(goldenExpected(), goldenActual());
  assert(diff.ok, 'diff.ok should be true');
  assert(diff.missing.length === 0, 'no missing entries');
}

// --- Case (b): drop a required osv_id from findings → FAIL ---

console.log('\n(b) missing osv_id → FAIL');
{
  const actual = goldenActual();
  actual.vulns = actual.vulns.filter((v) => v.osv_id !== 'CVE-2021-23337');
  const diff = diffExpectedVsActual(goldenExpected(), actual);
  assert(!diff.ok, 'diff.ok should be false');
  assert(
    diff.missing.some(
      (m) => m.category === 'reachable_vulns' && m.detail.includes('CVE-2021-23337'),
    ),
    'missing entry cites CVE-2021-23337 under reachable_vulns',
  );
}

// --- Case (c): replace osv_id with a known alias from `aliases:` → PASS ---

console.log('\n(c) alias substitution → PASS');
{
  const actual = goldenActual();
  // Actual finding now reports the GHSA alias instead of the canonical CVE.
  actual.vulns[0] = {
    osv_id: 'GHSA-35jh-r3h4-6jhm',
    aliases: [],
    reachability_level: 'confirmed',
  };
  const diff = diffExpectedVsActual(goldenExpected(), actual);
  assert(diff.ok, 'alias-only match is still PASS');
}

// --- Case (d): replace osv_id with unrelated CVE → FAIL ---

console.log('\n(d) unrelated CVE substitution → FAIL');
{
  const actual = goldenActual();
  actual.vulns[0] = {
    osv_id: 'CVE-9999-99999',
    aliases: [],
    reachability_level: 'confirmed',
  };
  const diff = diffExpectedVsActual(goldenExpected(), actual);
  assert(!diff.ok, 'unrelated CVE does not satisfy expected');
  assert(
    diff.missing.some(
      (m) => m.category === 'reachable_vulns' && m.detail.includes('CVE-2021-23337'),
    ),
    'missing entry still cites the expected CVE',
  );
}

// --- Case (e): bump reachability from `confirmed` to `module` when bucket
//                is `reachable` → FAIL ---

console.log('\n(e) reachability drop confirmed→module when bucket=reachable → FAIL');
{
  const actual = goldenActual();
  actual.vulns[0].reachability_level = 'module';
  const diff = diffExpectedVsActual(goldenExpected(), actual);
  assert(!diff.ok, 'module level does not satisfy reachable bucket');
  assert(
    diff.missing.some((m) => m.detail.includes('bucket mismatch')),
    'missing entry calls out bucket mismatch',
  );
}

// --- Case (f): bump from `confirmed` to `data_flow` when bucket is
//                `reachable` → PASS ---

console.log('\n(f) reachability shift confirmed→data_flow when bucket=reachable → PASS');
{
  const actual = goldenActual();
  actual.vulns[0].reachability_level = 'data_flow';
  const diff = diffExpectedVsActual(goldenExpected(), actual);
  assert(diff.ok, 'data_flow still satisfies reachable bucket');
}

// --- Case (g): add extras to findings → PASS (subset semantics) ---

console.log('\n(g) extras present in actual → PASS (subset)');
{
  const actual = goldenActual();
  actual.vulns.push({
    osv_id: 'CVE-2030-12345',
    aliases: [],
    reachability_level: 'data_flow',
  });
  actual.iac.push({ rule_id: 'CKV_DOCKER_2', file_path: 'Dockerfile' });
  const diff = diffExpectedVsActual(goldenExpected(), actual);
  assert(diff.ok, 'extras do not fail subset-match');
  assert(
    diff.extras.some((e) => e.category === 'vulns' && e.detail.includes('CVE-2030-12345')),
    'extras log records the unexpected vuln',
  );
}

// --- Case (h): malformed YAML → loadExpected throws ---

console.log('\n(h) malformed expected.yaml → throws');
{
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dogfood-check-test-'));
  const fixtureDir = path.join(tmpDir, 'broken-fixture');
  fs.mkdirSync(path.join(fixtureDir, '.deptex'), { recursive: true });
  fs.writeFileSync(
    path.join(fixtureDir, '.deptex', 'expected.yaml'),
    'reachable_vulns:\n  - osv_id: CVE-2021-1\n  invalid : : indent\n',
    'utf-8',
  );
  let threw = false;
  try {
    loadExpected(fixtureDir);
  } catch {
    threw = true;
  }
  assert(threw, 'malformed YAML triggers loadExpected to throw');
  fs.rmSync(tmpDir, { recursive: true, force: true });
}

// --- bonus: findOsvMatch + matchesReachabilityBucket invariants ---

console.log('\nbonus: invariants');
{
  assert(
    findOsvMatch({ osv_id: 'GHSA-X' }, [
      { osv_id: 'CVE-1', aliases: ['GHSA-X'], reachability_level: null },
    ]) !== undefined,
    'findOsvMatch matches via alias on the actual side',
  );
  assert(
    findOsvMatch({ osv_id: 'CVE-1', aliases: ['GHSA-X'] }, [
      { osv_id: 'GHSA-X', aliases: [], reachability_level: null },
    ]) !== undefined,
    'findOsvMatch matches via alias on the expected side',
  );
  assert(matchesReachabilityBucket('any', 'unreachable'), 'bucket=any always passes');
  assert(matchesReachabilityBucket(undefined, null), 'undefined bucket is permissive');
  assert(
    !matchesReachabilityBucket('reachable', 'module'),
    'reachable bucket rejects module',
  );
  assert(
    matchesReachabilityBucket('unreachable', null),
    'unreachable bucket accepts null reachability',
  );
}

console.log(`\n${failures === 0 ? 'PASS' : 'FAIL'} — ${failures} failure(s)`);
process.exit(failures === 0 ? 0 : 1);
