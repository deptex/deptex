/**
 * Snapshot test runner for extraction fixtures.
 *
 * Runs the `deptex-scan` CLI against every fixture under `fixtures/`, then
 * diffs each JSON output file against the committed snapshot under
 * `fixtures/<name>/snapshots/`. Fails with a unified-ish diff on mismatch.
 *
 * Bootstrap behavior: a missing snapshot file (or a fixture with no
 * `snapshots/` dir at all) is NOT treated as a failure. The runner writes
 * the file and reports it as a bootstrap; the contributor commits it in the
 * same PR. Subsequent runs compare against the now-committed snapshot and
 * fail on mismatch. Matches jest's `toMatchSnapshot()` / vitest's
 * `toMatchFileSnapshot()` UX. Only existing-snapshot mismatches fail.
 *
 * Usage:
 *   tsx test/snapshot.ts                       run all fixtures
 *   tsx test/snapshot.ts --fixture=test-npm    run one fixture
 *   tsx test/snapshot.ts --update              regenerate snapshots
 *   tsx test/snapshot.ts --diff-only           dry-run: print intended changes, never write
 *   tsx test/snapshot.ts --max-diff=500        raise per-file diff truncation (0 = unlimited)
 *   tsx test/snapshot.ts --only=test-minimal-npm,test-empty   multiple
 *
 * Ignore-field policy: some fields change every run by design (timestamps,
 * generated UUIDs, extraction_run_id, absolute paths). The default ignore
 * list below strips those before diffing. Per-fixture
 * `fixtures/<name>/snapshot-ignore.json` (optional) can add more.
 *
 * This runner intentionally shells out to the CLI (via `./bin/deptex-scan`,
 * the Docker wrapper) rather than importing runScan directly — that matches
 * how downstream users invoke the tool and catches CLI-specific regressions
 * (arg parsing, exit codes, stdout format) alongside pipeline changes.
 *
 * Prereq: the CLI image must be built first (`npm run docker:build`).
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
  // Volatile vuln fields fetched live from EPSS / NVD / CISA KEV APIs in
  // pipeline.ts. Values drift daily, so a contributor regenerating snapshots
  // a day after they were committed would diff-fail without these in the
  // ignore list. Stubbing via env-var was rejected — that introduces a
  // stale-mock failure mode the snapshot suite can't catch.
  'epss_score',
  'cvss_score',
  'cisa_kev',
  'published_at',
]);

/**
 * Default per-file diff truncation cap. Bumped from 10 → 200 because real
 * fixtures have hundreds of leaf paths (e.g. vulns.json with 26 rows × 40
 * fields ≈ 1000 paths) and 10 was too aggressive — contributors couldn't
 * see what was actually changing. 200 is enough to read most diffs without
 * flooding terminal output; pathological diffs (whole-file mismatch) should
 * use --max-diff explicitly.
 */
export const DEFAULT_MAX_DIFF = 200;

export interface SnapshotRunnerArgs {
  fixture: string | undefined;
  only: string | undefined;
  update: boolean;
  diffOnly: boolean;
  includeSlow: boolean;
  /** Per-file diff line cap. 0 = unlimited. */
  maxDiff: number;
  help: boolean;
}

/**
 * Parse argv for the snapshot runner. Exported for testing.
 *
 * Throws if `--max-diff` cannot be parsed as a non-negative integer.
 */
export function parseSnapshotArgs(argv: string[]): SnapshotRunnerArgs {
  const parsed = parseArgs({
    args: argv,
    options: {
      fixture: { type: 'string' },
      only: { type: 'string' },
      update: { type: 'boolean' },
      'diff-only': { type: 'boolean' },
      'include-slow': { type: 'boolean' },
      'max-diff': { type: 'string' },
      help: { type: 'boolean', short: 'h' },
    },
    allowPositionals: true,
  });

  let maxDiff = DEFAULT_MAX_DIFF;
  const rawMaxDiff = parsed.values['max-diff'];
  if (rawMaxDiff !== undefined) {
    const n = Number(rawMaxDiff);
    if (!Number.isInteger(n) || n < 0) {
      throw new Error(
        `--max-diff expects a non-negative integer, got ${JSON.stringify(rawMaxDiff)}`,
      );
    }
    maxDiff = n;
  }

  return {
    fixture: parsed.values.fixture,
    only: parsed.values.only,
    update: parsed.values.update ?? false,
    diffOnly: parsed.values['diff-only'] ?? false,
    includeSlow: parsed.values['include-slow'] ?? false,
    maxDiff,
    help: parsed.values.help ?? false,
  };
}

/**
 * Truncate a diff-line array to `maxDiff` entries, appending an
 * "…and N more" marker when entries are dropped. `maxDiff === 0` means
 * unlimited. Exported for testing.
 */
export function truncateDiffLines(lines: string[], maxDiff: number): string[] {
  if (maxDiff === 0 || lines.length <= maxDiff) return lines.slice();
  const head = lines.slice(0, maxDiff);
  head.push(`…and ${lines.length - maxDiff} more`);
  return head;
}

async function main() {
  let args: SnapshotRunnerArgs;
  try {
    args = parseSnapshotArgs(process.argv.slice(2));
  } catch (e: any) {
    process.stderr.write(`error: ${e.message}\n`);
    process.exit(2);
  }

  if (args.help) {
    process.stdout.write(HELP);
    process.exit(0);
  }

  // --diff-only wins over --update: dry-run is the safer choice when the
  // contributor accidentally combined them.
  if (args.diffOnly && args.update) {
    console.log('NOTE: --diff-only overrides --update; no snapshots will be written.\n');
  }

  const effectiveUpdate = args.update && !args.diffOnly;

  const includeSlow = args.includeSlow;
  const filter = args.fixture
    ? new Set([args.fixture])
    : args.only
      ? new Set(args.only.split(',').map((s) => s.trim()))
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
  if (args.diffOnly) {
    console.log('MODE: --diff-only (dry-run; intended changes printed, no snapshots written)\n');
  } else if (effectiveUpdate) {
    console.log('MODE: --update (snapshots will be overwritten)\n');
  }

  let failures = 0;
  let intendedChanges = 0;

  for (const fixture of targets) {
    console.log(`\n=== ${fixture.name} ===`);
    const workspacePath = path.join(FIXTURES_ROOT, fixture.name);
    // Output dir sits outside the workspace. Previously we used
    // `<workspace>/.results`, but the deptex-scan Docker wrapper mounts the
    // workspace and the output dir as separate bind mounts — when the output
    // dir is *inside* the workspace on the host, /workspace/.results in the
    // container is the same on-disk storage as /output, so TruffleHog and
    // Semgrep walk the CLI's own PGLite buckets + dep-scan reports as if they
    // were user code. Keep the dir inside the repo (gitignored) so Docker
    // Desktop's bind-mount permissions work on Windows.
    const resultDir = path.join(WORKER_ROOT, '.test-results', fixture.name);
    const snapshotDir = path.join(workspacePath, 'snapshots');

    // Clean previous run output so we diff deterministically.
    if (fs.existsSync(resultDir)) fs.rmSync(resultDir, { recursive: true, force: true });

    // The pipeline writes a handful of intermediate artifacts directly into
    // the workspace (SBOM, dep-scan reports, semgrep+trufflehog raw output).
    // On a fresh Fly.io machine they never exist at scan start, but local
    // re-runs leak them between invocations and TruffleHog/Semgrep then scan
    // their own previous output as if it were user code. Wipe them up front.
    for (const artifact of [
      'sbom.json',
      'sbom.json.map',
      'trufflehog.json',
      'semgrep.json',
      'depscan-reports',
      'deps.slices.json',
    ]) {
      const p = path.join(workspacePath, artifact);
      if (fs.existsSync(p)) fs.rmSync(p, { recursive: true, force: true });
    }

    // Move committed snapshots/ out of the workspace during the scan.
    // TruffleHog and Semgrep walk the entire workspace; without this, the
    // previous run's snapshot files get scanned and every finding appears to
    // duplicate on each re-run (and worse: TruffleHog emits duplicate rows
    // for the embedded secrets, which crashes the ON CONFLICT upsert and
    // drops every finding for the run). Park outside the workspace entirely
    // — a sibling path inside the workspace root is still walked.
    const snapshotParkDir = path.join(
      require('os').tmpdir(),
      `deptex-snapshot-${fixture.name}-${process.pid}`,
    );
    const hadSnapshotDir = fs.existsSync(snapshotDir);
    if (hadSnapshotDir) {
      if (fs.existsSync(snapshotParkDir)) {
        fs.rmSync(snapshotParkDir, { recursive: true, force: true });
      }
      fs.renameSync(snapshotDir, snapshotParkDir);
    }

    let exitCode: number;
    try {
      exitCode = runCli(workspacePath, resultDir, fixture);
    } finally {
      if (hadSnapshotDir) {
        // Restore regardless of scan outcome so CI failures leave the tree
        // in a clean state.
        if (fs.existsSync(snapshotDir)) {
          fs.rmSync(snapshotDir, { recursive: true, force: true });
        }
        fs.renameSync(snapshotParkDir, snapshotDir);
      }
    }

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
        update: effectiveUpdate,
        diffOnly: args.diffOnly,
        maxDiff: args.maxDiff,
        fixtureIgnore: loadFixtureIgnore(workspacePath),
      });
      if (args.diffOnly) {
        // In --diff-only mode the runner prints intended changes but never
        // counts them as failures; exit 0 unless an exit-code mismatch above
        // already incremented `failures`.
        if (result.intendedChanges) {
          intendedChanges += result.intendedChanges;
          console.log(`  WOULD CHANGE: ${result.message}`);
        } else {
          console.log(`  snapshots: ${result.message}`);
        }
      } else if (!result.ok) {
        console.error(`  FAIL: ${result.message}`);
        failures++;
      } else {
        console.log(`  snapshots: ${result.message}`);
      }
    }
  }

  console.log('');
  if (args.diffOnly) {
    if (intendedChanges === 0) {
      console.log(`PASS (${targets.length} fixture${targets.length === 1 ? '' : 's'}; no intended changes)`);
    } else {
      console.log(
        `DRY-RUN (${targets.length} fixture${targets.length === 1 ? '' : 's'}; ` +
        `${intendedChanges} intended change${intendedChanges === 1 ? '' : 's'} — ` +
        `re-run with --update to write)`,
      );
    }
    process.exit(failures === 0 ? 0 : 1);
  }
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
  const wrapper = path.join(WORKER_ROOT, 'bin', 'deptex-scan');
  const args = ['run', workspacePath, `--output=${outputDir}`, '--quiet'];
  if (fixture.ecosystem) args.push(`--ecosystem=${fixture.ecosystem}`);
  // On Windows the bash shebang isn't honored by spawn — invoke bash explicitly.
  const [cmd, cmdArgs] = process.platform === 'win32'
    ? ['bash', [wrapper, ...args]] as [string, string[]]
    : [wrapper, args] as [string, string[]];
  const res = spawnSync(cmd, cmdArgs, {
    cwd: WORKER_ROOT,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.stdout && res.stdout.trim()) {
    for (const line of res.stdout.trim().split(/\r?\n/).slice(-3)) {
      console.log(`    stdout: ${line}`);
    }
  }
  if (res.stderr && res.stderr.trim()) {
    for (const line of res.stderr.trim().split(/\r?\n/).slice(-5)) {
      console.log(`    stderr: ${line}`);
    }
  }
  return res.status ?? 2;
}

export interface DiffOptions {
  update: boolean;
  /** When true, print intended changes but never write to snapshotDir. */
  diffOnly: boolean;
  /** Per-file diff truncation cap. 0 = unlimited. */
  maxDiff: number;
  fixtureIgnore: Set<string>;
}

export interface DiffResult {
  ok: boolean;
  message: string;
  /** Count of files that differ in --diff-only mode (would-be writes). */
  intendedChanges?: number;
}

export function diffSnapshots(resultDir: string, snapshotDir: string, opts: DiffOptions): DiffResult {
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

  // Diff path (covers both default mode and --diff-only). The --diff-only
  // caller treats `intendedChanges > 0` as informational, not a failure.
  //
  // Bootstrap policy (matches jest's `toMatchSnapshot()` and vitest's
  // `toMatchFileSnapshot()`): a missing snapshot file (or missing snapshot
  // dir entirely) on a default-mode run is NOT a failure — we write the file
  // and report it as a bootstrap. The contributor commits the now-written
  // snapshot in the same PR, and subsequent runs compare against it. Only
  // mismatches against an EXISTING snapshot fail the run.
  //
  // --diff-only still behaves as a dry-run: bootstrap candidates are reported
  // as `intendedChanges` and the file is not written.
  if (!fs.existsSync(snapshotDir)) {
    if (opts.diffOnly) {
      // Treat as "everything is new" rather than a hard fail.
      return {
        ok: true,
        message: `no snapshot dir at ${snapshotDir} — would create with ${outputs.length} file(s)`,
        intendedChanges: outputs.length,
      };
    }
    // Auto-bootstrap: write every output as a snapshot and pass.
    fs.mkdirSync(snapshotDir, { recursive: true });
    for (const file of outputs) {
      const src = path.join(resultDir, file);
      const dst = path.join(snapshotDir, file);
      const redacted = stripIgnored(readJson(src), opts.fixtureIgnore);
      writeJson(dst, redacted);
    }
    return {
      ok: true,
      message: `bootstrapped ${outputs.length} snapshot(s) at ${snapshotDir} (commit them to lock the baseline)`,
    };
  }

  const mismatches: string[] = [];
  const bootstrapped: string[] = [];
  let changedFiles = 0;
  for (const file of outputs) {
    const actual = stripIgnored(
      readJson(path.join(resultDir, file)),
      opts.fixtureIgnore,
    );
    const expectedPath = path.join(snapshotDir, file);
    if (!fs.existsSync(expectedPath)) {
      // Per-file bootstrap: missing snapshot for a fixture that already has
      // a snapshots/ dir (e.g. a new output file was added to the pipeline).
      // In default mode, write it and continue. In --diff-only, count it as
      // an intended change without writing.
      if (opts.diffOnly) {
        mismatches.push(`  ${file}: new file (not in snapshot dir)`);
        changedFiles++;
      } else {
        writeJson(expectedPath, actual);
        bootstrapped.push(file);
      }
      continue;
    }
    const expected = readJson(expectedPath);
    const diff = diffJson(expected, actual);
    if (diff.length > 0) {
      changedFiles++;
      mismatches.push(`  ${file}: ${diff.length} difference(s)`);
      for (const line of truncateDiffLines(diff, opts.maxDiff)) {
        mismatches.push(`    ${line}`);
      }
    }
  }

  if (mismatches.length > 0) {
    if (opts.diffOnly) {
      return {
        ok: true,
        message: `intended changes:\n${mismatches.join('\n')}`,
        intendedChanges: changedFiles,
      };
    }
    return {
      ok: false,
      message: `snapshot mismatches:\n${mismatches.join('\n')}`,
    };
  }
  if (bootstrapped.length > 0) {
    const matched = outputs.length - bootstrapped.length;
    return {
      ok: true,
      message:
        `${matched} file(s) match snapshot; ` +
        `bootstrapped ${bootstrapped.length} new (${bootstrapped.join(', ')}) — commit them to lock the baseline`,
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
  tsx test/snapshot.ts --diff-only           dry-run: print intended changes
  tsx test/snapshot.ts --max-diff=<N>        per-file diff cap (default ${DEFAULT_MAX_DIFF}, 0 = unlimited)
  tsx test/snapshot.ts --include-slow        include slow fixtures by default

Flags:
  --fixture=<name>      Only run one fixture (by dir name)
  --only=<names>        Comma-separated list of fixtures to run
  --update              Regenerate snapshot files (destructive). Wraps as
                        \`npm run test:fixtures:update\`.
  --diff-only           Dry-run mode. Print what \`--update\` WOULD change,
                        but do not write. Combine with --update is safe;
                        --diff-only wins.
  --max-diff=<N>        Override per-file diff truncation cap (default
                        ${DEFAULT_MAX_DIFF}). Pass 0 for unlimited. Useful when
                        debugging large snapshot drift.
  --include-slow        Run full-ecosystem fixtures that take minutes each
  -h, --help            This text

Exit codes:
  0 = all snapshots match (or --diff-only completed without runner error)
  1 = one or more snapshot mismatches (default mode only)
  2 = invalid arguments / runner error
`;

// Only run main() when invoked directly (tsx test/snapshot.ts ...). When
// imported by tests we want the exported helpers (parseSnapshotArgs,
// truncateDiffLines, DEFAULT_MAX_DIFF) without the side effect.
if (require.main === module) {
  main().catch((e) => {
    console.error(`fatal: ${e?.stack ?? e?.message ?? e}`);
    process.exit(2);
  });
}
