/**
 * Meta-test for the snapshot runner itself.
 *
 * Three invariants — when these break, every other snapshot test gives a
 * false signal, so the runner needs its own regression coverage:
 *
 *   1. Bootstrap on missing snapshot dir: a fixture with no snapshots/
 *      directory at all auto-writes one and returns ok=true with a
 *      bootstrap message.
 *   2. Per-file bootstrap: a fixture with snapshots/ but a missing single
 *      file gets that file written (not flagged as a mismatch).
 *   3. Mismatch against an EXISTING snapshot is detected and returned as
 *      ok=false, with the path + before/after value in the message.
 *   4. Ignore-list entry: a field listed in DEFAULT_IGNORE_FIELDS or
 *      per-fixture snapshot-ignore.json never produces a diff even when
 *      the actual value changes.
 *   5. parseSnapshotArgs handles --max-diff non-integer correctly.
 *   6. truncateDiffLines truncates and labels overflow.
 *
 * Run: npx tsx test/snapshot-runner.test.ts
 *
 * This test does NOT invoke the CLI or Docker — it exercises diffSnapshots
 * directly against a synthetic results dir to keep the meta-test fast
 * (<1s) and independent of the heavy extraction pipeline. The end-to-end
 * "the CLI plus the runner together" path is exercised by the real
 * fixture snapshots (test-minimal-npm etc.).
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import {
  diffSnapshots,
  parseSnapshotArgs,
  truncateDiffLines,
  DEFAULT_MAX_DIFF,
} from './snapshot';

let failures = 0;

function check(name: string, cond: boolean, info?: string) {
  if (cond) {
    console.log(`  ok  ${name}`);
  } else {
    console.error(`  FAIL ${name}${info ? ` — ${info}` : ''}`);
    failures++;
  }
}

function makeTempDir(label: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), `snap-meta-${label}-`));
}

function writeJson(p: string, data: unknown): void {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function readJson(p: string): any {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function caseBootstrapMissingDir() {
  console.log('case: bootstrap when snapshots/ dir is absent');
  const resultDir = makeTempDir('result');
  const snapshotDir = path.join(makeTempDir('snap'), 'snapshots'); // does not exist yet
  writeJson(path.join(resultDir, 'deps.json'), [{ name: 'lodash', version: '4.17.20' }]);
  writeJson(path.join(resultDir, 'vulns.json'), []);
  const result = diffSnapshots(resultDir, snapshotDir, {
    update: false,
    diffOnly: false,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(),
  });
  check('returns ok=true', result.ok === true, `message: ${result.message}`);
  check('mentions bootstrap', /bootstrap/i.test(result.message));
  check('writes deps.json to snapshotDir', fs.existsSync(path.join(snapshotDir, 'deps.json')));
  check('writes vulns.json to snapshotDir', fs.existsSync(path.join(snapshotDir, 'vulns.json')));
}

function casePerFileBootstrap() {
  console.log('\ncase: per-file bootstrap (snapshots/ exists, one file missing)');
  const resultDir = makeTempDir('result');
  const workspace = makeTempDir('workspace');
  const snapshotDir = path.join(workspace, 'snapshots');
  fs.mkdirSync(snapshotDir, { recursive: true });
  // Existing snapshot for deps.json.
  writeJson(path.join(snapshotDir, 'deps.json'), [{ name: 'lodash', version: '4.17.20' }]);
  // No existing vulns.json snapshot.
  writeJson(path.join(resultDir, 'deps.json'), [{ name: 'lodash', version: '4.17.20' }]);
  writeJson(path.join(resultDir, 'vulns.json'), [{ osv_id: 'CVE-2020-28500' }]);

  const result = diffSnapshots(resultDir, snapshotDir, {
    update: false,
    diffOnly: false,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(),
  });
  check('returns ok=true', result.ok === true, `message: ${result.message}`);
  check('mentions bootstrapped 1 new', /bootstrapped 1 new/.test(result.message));
  check('mentions vulns.json by name', /vulns\.json/.test(result.message));
  check('vulns.json now exists in snapshotDir', fs.existsSync(path.join(snapshotDir, 'vulns.json')));
}

function caseMismatchAgainstExisting() {
  console.log('\ncase: mismatch against existing snapshot is detected');
  const resultDir = makeTempDir('result');
  const workspace = makeTempDir('workspace');
  const snapshotDir = path.join(workspace, 'snapshots');
  fs.mkdirSync(snapshotDir, { recursive: true });
  writeJson(path.join(snapshotDir, 'deps.json'), [{ name: 'lodash', version: '4.17.20' }]);
  writeJson(path.join(resultDir, 'deps.json'), [{ name: 'lodash', version: '4.17.21' }]);

  const result = diffSnapshots(resultDir, snapshotDir, {
    update: false,
    diffOnly: false,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(),
  });
  check('returns ok=false', result.ok === false, `message: ${result.message}`);
  check('mentions deps.json', /deps\.json/.test(result.message));
  check('mentions the diverging value (4.17.20)', /4\.17\.20/.test(result.message));
  check('mentions the new value (4.17.21)', /4\.17\.21/.test(result.message));
}

function caseIgnoreList() {
  console.log('\ncase: ignored fields do not produce diff even when values change');
  const resultDir = makeTempDir('result');
  const workspace = makeTempDir('workspace');
  const snapshotDir = path.join(workspace, 'snapshots');
  fs.mkdirSync(snapshotDir, { recursive: true });
  // DEFAULT_IGNORE_FIELDS includes 'epss_score' and 'cvss_score'.
  // The snapshot is already-stripped; the result row has the volatile fields
  // populated. Strip-on-read should make the diff a no-op.
  writeJson(path.join(snapshotDir, 'vulns.json'), [{ osv_id: 'CVE-1', severity: 'high' }]);
  writeJson(path.join(resultDir, 'vulns.json'), [
    { osv_id: 'CVE-1', severity: 'high', epss_score: '0.5', cvss_score: '7.5', cisa_kev: false },
  ]);

  const result = diffSnapshots(resultDir, snapshotDir, {
    update: false,
    diffOnly: false,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(),
  });
  check('returns ok=true', result.ok === true, `message: ${result.message}`);
  check('reports 1 file matched', /1 file\(s\) match/.test(result.message));
}

function casePerFixtureIgnore() {
  console.log('\ncase: per-fixture ignore list applies on top of default');
  const resultDir = makeTempDir('result');
  const workspace = makeTempDir('workspace');
  const snapshotDir = path.join(workspace, 'snapshots');
  fs.mkdirSync(snapshotDir, { recursive: true });
  // 'volatile_custom' is not in DEFAULT_IGNORE_FIELDS but the fixture-ignore
  // should suppress it.
  writeJson(path.join(snapshotDir, 'vulns.json'), [{ osv_id: 'CVE-1' }]);
  writeJson(path.join(resultDir, 'vulns.json'), [{ osv_id: 'CVE-1', volatile_custom: 'changed' }]);

  const result = diffSnapshots(resultDir, snapshotDir, {
    update: false,
    diffOnly: false,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(['volatile_custom']),
  });
  check('returns ok=true when per-fixture ignore matches', result.ok === true, `message: ${result.message}`);
}

function caseDiffOnlyDryRun() {
  console.log('\ncase: --diff-only never writes, returns intendedChanges');
  const resultDir = makeTempDir('result');
  const workspace = makeTempDir('workspace');
  const snapshotDir = path.join(workspace, 'snapshots');
  fs.mkdirSync(snapshotDir, { recursive: true });
  writeJson(path.join(snapshotDir, 'deps.json'), [{ name: 'lodash', version: '4.17.20' }]);
  writeJson(path.join(resultDir, 'deps.json'), [{ name: 'lodash', version: '4.17.21' }]);

  const before = readJson(path.join(snapshotDir, 'deps.json'));
  const result = diffSnapshots(resultDir, snapshotDir, {
    update: false,
    diffOnly: true,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(),
  });
  const after = readJson(path.join(snapshotDir, 'deps.json'));

  check('returns ok=true in diff-only', result.ok === true);
  check('intendedChanges = 1', result.intendedChanges === 1, `got ${result.intendedChanges}`);
  check('snapshot file untouched', JSON.stringify(before) === JSON.stringify(after));
}

function caseUpdateOverwrites() {
  console.log('\ncase: --update overwrites snapshots with stripped output');
  const resultDir = makeTempDir('result');
  const workspace = makeTempDir('workspace');
  const snapshotDir = path.join(workspace, 'snapshots');
  fs.mkdirSync(snapshotDir, { recursive: true });
  writeJson(path.join(snapshotDir, 'deps.json'), [{ name: 'lodash', version: '4.17.20' }]);
  writeJson(path.join(resultDir, 'deps.json'), [
    { name: 'lodash', version: '4.17.21', created_at: '2026-01-01' },
  ]);

  const result = diffSnapshots(resultDir, snapshotDir, {
    update: true,
    diffOnly: false,
    maxDiff: DEFAULT_MAX_DIFF,
    fixtureIgnore: new Set(),
  });
  const after = readJson(path.join(snapshotDir, 'deps.json'));
  check('returns ok=true after update', result.ok === true);
  check('snapshot reflects new version', after[0].version === '4.17.21');
  check('ignored field (created_at) is stripped from written snapshot', after[0].created_at === undefined);
}

function caseParseArgsRejectsNonInt() {
  console.log('\ncase: parseSnapshotArgs rejects non-integer --max-diff');
  let threw = false;
  try {
    parseSnapshotArgs(['--max-diff=oops']);
  } catch (e: any) {
    threw = true;
    check('error mentions max-diff', /max-diff/i.test(e.message));
  }
  check('throws on non-integer', threw);

  threw = false;
  try {
    parseSnapshotArgs(['--max-diff=-3']);
  } catch {
    threw = true;
  }
  check('rejects negative --max-diff', threw);
}

function caseTruncate() {
  console.log('\ncase: truncateDiffLines respects cap');
  const lines = Array.from({ length: 50 }, (_, i) => `line${i}`);
  const truncated = truncateDiffLines(lines, 10);
  check('returns 10 + overflow label', truncated.length === 11, `got ${truncated.length}`);
  check('last entry mentions "more"', /and 40 more/.test(truncated[truncated.length - 1]));

  const all = truncateDiffLines(lines, 0);
  check('maxDiff=0 returns all', all.length === 50);

  const underCap = truncateDiffLines(lines.slice(0, 3), 10);
  check('under-cap input untouched', underCap.length === 3);
}

function main() {
  caseBootstrapMissingDir();
  casePerFileBootstrap();
  caseMismatchAgainstExisting();
  caseIgnoreList();
  casePerFixtureIgnore();
  caseDiffOnlyDryRun();
  caseUpdateOverwrites();
  caseParseArgsRejectsNonInt();
  caseTruncate();

  console.log('');
  if (failures === 0) {
    console.log('PASS');
    process.exit(0);
  } else {
    console.error(`FAIL (${failures})`);
    process.exit(1);
  }
}

main();
