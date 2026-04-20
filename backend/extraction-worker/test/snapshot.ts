/**
 * Snapshot test runner for extraction fixtures.
 *
 * Runs the `deptex-scan` CLI against every fixture under `fixtures/`, then
 * diffs each JSON output file against the committed snapshot under
 * `fixtures/<name>/snapshots/`. Fails with a unified-ish diff on mismatch.
 *
 * Usage:
 *   tsx test/snapshot.ts                       run all fixtures
 *   tsx test/snapshot.ts --fixture=test-npm    run one fixture
 *   tsx test/snapshot.ts --update              regenerate snapshots
 *   tsx test/snapshot.ts --only=test-minimal-npm,test-empty   multiple
 *
 * Ignore-field policy: some fields change every run by design (timestamps,
 * generated UUIDs, extraction_run_id, absolute paths). The default ignore
 * list below strips those before diffing. Per-fixture
 * `fixtures/<name>/snapshot-ignore.json` (optional) can add more.
 *
 * This runner intentionally shells out to the CLI (via `npm run cli`)
 * rather than importing runScan directly — that matches how downstream
 * users invoke the tool and catches CLI-specific regressions (arg parsing,
 * exit codes, stdout format) alongside pipeline changes.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

import { parseArgs } from 'node:util';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

const FIXTURES_ROOT = path.resolve(__dirname, '../fixtures');
const WORKER_ROOT = path.resolve(__dirname, '..');

interface FixtureManifest {
  /** Directory name under fixtures/. */
  name: string;
  /** If true, running `deptex-scan run` should succeed with exit 0. */
  expectClean: boolean;
  /** Ecosystem to pass — omitted means "let auto-detect decide". */
  ecosystem?: string;
  /** Expected exit code when run without --fail-on. 0 means clean, 2 means the pipeline errored (e.g. empty fixture). */
  expectedExitCode: number;
  /** Skip this fixture in default runs (requires --fixture or --only to opt in). */
  slow?: boolean;
}

const FIXTURES: FixtureManifest[] = [
  { name: 'test-minimal-npm', expectClean: true, expectedExitCode: 0 },
  { name: 'test-empty', expectClean: false, expectedExitCode: 2 },
  { name: 'test-npm', expectClean: true, expectedExitCode: 0, slow: true },
  { name: 'test-python', expectClean: true, expectedExitCode: 0, slow: true },
  { name: 'test-java', expectClean: true, expectedExitCode: 0, slow: true },
  { name: 'test-go', expectClean: true, expectedExitCode: 0, slow: true },
];

const DEFAULT_IGNORE_FIELDS = new Set([
  'id',
  'project_id',
  'organization_id',
  'dependency_id',
  'dependency_version_id',
  'project_dependency_id',
  'extraction_run_id',
  'last_seen_extraction_run_id',
  'active_extraction_run_id',
  'previous_extraction_run_id',
  'created_at',
  'updated_at',
  'removed_at',
  'detected_at',
  'completed_at',
  'started_at',
  'heartbeat_at',
  'policy_evaluated_at',
  'ast_parsed_at',
  'last_vuln_check_at',
  'last_webhook_at',
  'duration_ms',
  'sla_due_at',
  'first_seen_at',
  'last_seen_at',
]);

async function main() {
  const parsed = parseArgs({
    args: process.argv.slice(2),
    options: {
      fixture: { type: 'string' },
      only: { type: 'string' },
      update: { type: 'boolean' },
      'include-slow': { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });

  if (parsed.values.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  const includeSlow = parsed.values['include-slow'] ?? false;
  const filter = parsed.values.fixture
    ? new Set([parsed.values.fixture])
    : parsed.values.only
      ? new Set(parsed.values.only.split(',').map((s) => s.trim()))
      : null;

  const targets = FIXTURES.filter((f) => {
    if (filter) return filter.has(f.name);
    if (f.slow && !includeSlow) return false;
    return true;
  });

  if (targets.length === 0) {
    process.stderr.write('no fixtures match the filter\n');
    process.exit(2);
  }

  console.log(`Running ${targets.length} fixture(s): ${targets.map((t) => t.name).join(', ')}`);
  console.log(parsed.values.update ? 'MODE: --update (snapshots will be overwritten)\n' : '');

  let failures = 0;

  for (const fixture of targets) {
    console.log(`\n=== ${fixture.name} ===`);
    const workspacePath = path.join(FIXTURES_ROOT, fixture.name);
    const resultDir = path.join(workspacePath, '.results');
    const snapshotDir = path.join(workspacePath, 'snapshots');

    // Clean previous run output so we diff deterministically.
    if (fs.existsSync(resultDir)) fs.rmSync(resultDir, { recursive: true, force: true });

    const exitCode = runCli(workspacePath, resultDir, fixture);

    if (exitCode !== fixture.expectedExitCode) {
      console.error(
        `  FAIL (exit): expected ${fixture.expectedExitCode}, got ${exitCode}`,
      );
      failures++;
      continue;
    }
    console.log(`  exit ${exitCode} as expected`);

    if (fixture.expectClean) {
      const result = diffSnapshots(resultDir, snapshotDir, {
        update: parsed.values.update ?? false,
        fixtureIgnore: loadFixtureIgnore(workspacePath),
      });
      if (!result.ok) {
        console.error(`  FAIL: ${result.message}`);
        failures++;
      } else {
        console.log(`  snapshots: ${result.message}`);
      }
    }
  }

  console.log('');
  if (failures === 0) {
    console.log(`PASS (${targets.length} fixture${targets.length === 1 ? '' : 's'})`);
    process.exit(0);
  } else {
    console.error(`FAIL (${failures} of ${targets.length} fixture${targets.length === 1 ? '' : 's'})`);
    process.exit(1);
  }
}

function runCli(
  workspacePath: string,
  outputDir: string,
  fixture: FixtureManifest,
): number {
  const args = ['run', 'cli', '--', 'run', workspacePath, `--output=${outputDir}`, '--quiet'];
  if (fixture.ecosystem) args.push(`--ecosystem=${fixture.ecosystem}`);
  const res = spawnSync('npm', args, {
    cwd: WORKER_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    shell: process.platform === 'win32',
  });
  if (res.stdout && res.stdout.trim()) {
    for (const line of res.stdout.trim().split(/\r?\n/).slice(-3)) {
      console.log(`    stdout: ${line}`);
    }
  }
  return res.status ?? 2;
}

interface DiffOptions {
  update: boolean;
  fixtureIgnore: Set<string>;
}

interface DiffResult {
  ok: boolean;
  message: string;
}

function diffSnapshots(resultDir: string, snapshotDir: string, opts: DiffOptions): DiffResult {
  if (!fs.existsSync(resultDir)) {
    return { ok: false, message: `no results dir at ${resultDir}` };
  }

  const outputs = fs
    .readdirSync(resultDir)
    .filter((f) => f.endsWith('.json'))
    .sort();

  if (opts.update) {
    fs.mkdirSync(snapshotDir, { recursive: true });
    for (const file of outputs) {
      const src = path.join(resultDir, file);
      const dst = path.join(snapshotDir, file);
      const redacted = stripIgnored(readJson(src), opts.fixtureIgnore);
      writeJson(dst, redacted);
    }
    return { ok: true, message: `updated ${outputs.length} snapshot(s)` };
  }

  if (!fs.existsSync(snapshotDir)) {
    return {
      ok: false,
      message: `no snapshot dir at ${snapshotDir} — run with --update to create it`,
    };
  }

  const mismatches: string[] = [];
  for (const file of outputs) {
    const actual = stripIgnored(
      readJson(path.join(resultDir, file)),
      opts.fixtureIgnore,
    );
    const expectedPath = path.join(snapshotDir, file);
    if (!fs.existsSync(expectedPath)) {
      mismatches.push(`  ${file}: new file (not in snapshot dir)`);
      continue;
    }
    const expected = readJson(expectedPath);
    const diff = diffJson(expected, actual);
    if (diff.length > 0) {
      mismatches.push(`  ${file}: ${diff.length} difference(s)`);
      for (const d of diff.slice(0, 10)) mismatches.push(`    ${d}`);
      if (diff.length > 10) mismatches.push(`    …and ${diff.length - 10} more`);
    }
  }

  if (mismatches.length > 0) {
    return {
      ok: false,
      message: `snapshot mismatches:\n${mismatches.join('\n')}`,
    };
  }
  return { ok: true, message: `${outputs.length} file(s) match snapshot` };
}

function loadFixtureIgnore(workspacePath: string): Set<string> {
  const ignorePath = path.join(workspacePath, 'snapshot-ignore.json');
  if (!fs.existsSync(ignorePath)) return new Set();
  try {
    const raw = JSON.parse(fs.readFileSync(ignorePath, 'utf8')) as {
      ignore_fields?: string[];
    };
    return new Set(raw.ignore_fields ?? []);
  } catch (e: any) {
    console.warn(`  warn: failed to parse ${ignorePath}: ${e.message}`);
    return new Set();
  }
}

function readJson(p: string): unknown {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function writeJson(p: string, data: unknown): void {
  fs.writeFileSync(p, JSON.stringify(data, null, 2) + '\n', 'utf8');
}

function stripIgnored(value: any, extraIgnore: Set<string>): any {
  const ignore = new Set([...DEFAULT_IGNORE_FIELDS, ...extraIgnore]);
  const walk = (v: any): any => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const out: any = {};
      for (const [k, val] of Object.entries(v)) {
        if (ignore.has(k)) continue;
        out[k] = walk(val);
      }
      return out;
    }
    return v;
  };
  return walk(value);
}

/** Simple recursive diff producing a flat list of `path: expected ≠ actual` strings. */
function diffJson(expected: any, actual: any, pathSoFar: string = '$'): string[] {
  if (expected === actual) return [];
  if (typeof expected !== typeof actual || expected === null || actual === null) {
    return [`${pathSoFar}: ${JSON.stringify(expected)} ≠ ${JSON.stringify(actual)}`];
  }
  if (Array.isArray(expected) || Array.isArray(actual)) {
    if (!Array.isArray(expected) || !Array.isArray(actual)) {
      return [`${pathSoFar}: type mismatch (array vs non-array)`];
    }
    if (expected.length !== actual.length) {
      return [`${pathSoFar}: length ${expected.length} ≠ ${actual.length}`];
    }
    const out: string[] = [];
    for (let i = 0; i < expected.length; i++) {
      out.push(...diffJson(expected[i], actual[i], `${pathSoFar}[${i}]`));
    }
    return out;
  }
  if (typeof expected === 'object') {
    const out: string[] = [];
    const keys = new Set([...Object.keys(expected), ...Object.keys(actual)]);
    for (const k of keys) {
      out.push(...diffJson(expected[k], actual[k], `${pathSoFar}.${k}`));
    }
    return out;
  }
  return [`${pathSoFar}: ${JSON.stringify(expected)} ≠ ${JSON.stringify(actual)}`];
}

const HELP = `Snapshot test runner for extraction fixtures.

Usage:
  tsx test/snapshot.ts                       run all fixtures
  tsx test/snapshot.ts --fixture=<name>      run one fixture
  tsx test/snapshot.ts --only=<n,n,...>      run multiple by name
  tsx test/snapshot.ts --update              regenerate snapshots
  tsx test/snapshot.ts --include-slow        include slow fixtures by default

Flags:
  --fixture=<name>      Only run one fixture (by dir name)
  --only=<names>        Comma-separated list of fixtures to run
  --update              Regenerate snapshot files (destructive)
  --include-slow        Run full-ecosystem fixtures that take minutes each
  -h, --help            This text

Exit codes:
  0 = all snapshots match
  1 = one or more snapshot mismatches
  2 = invalid arguments / runner error
`;

main().catch((e) => {
  console.error(`fatal: ${e?.stack ?? e?.message ?? e}`);
  process.exit(2);
});
