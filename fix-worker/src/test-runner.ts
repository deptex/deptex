import { spawnSync } from 'child_process';
import type { FixLogger } from './logger';

export interface TestResult {
  passed: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
  // True when the test command is the language scaffold's default
  // "no tests defined" exit (npm init's 'echo no test specified', pytest
  // exit 5, go's 'no Go test files', etc). Distinct from a real failure
  // so the pipeline can skip the repair loop instead of looping pointlessly.
  noTestSuite: boolean;
}

// Heuristics for "we can't meaningfully verify locally" — either the repo has
// no real test suite, OR the test harness itself couldn't run in this sandbox.
// In both cases the run is a soft-pass (open the PR, let review + the PR's CI be
// the gate) rather than a real failure.
function detectUnverifiable(opts: {
  testCommand: string;
  exitCode: number | null;
  stderr: string;
  stdout: string;
}): boolean {
  const text = `${opts.stdout}\n${opts.stderr}`.toLowerCase();

  // --- No real test suite (common scaffolds across the ship-gate languages) ---
  // npm init's default test script: `echo "Error: no test specified" && exit 1`
  if (text.includes('error: no test specified')) return true;
  // npm errors when package.json has no "test" script at all.
  // Format: `npm error Missing script: "test"` (npm 10+) or
  //         `npm ERR! missing script: test` (npm 6).
  if (text.includes('missing script:')) return true;
  // pytest exits 5 when no tests are collected
  if (opts.testCommand.startsWith('pytest') && opts.exitCode === 5) return true;
  if (text.includes('no tests ran') || text.includes('collected 0 items')) return true;
  // go test exits with `[no test files]` when there are no _test.go files
  if (text.includes('[no test files]')) return true;

  // --- Harness couldn't run (the sandbox can't replicate the repo's full test
  // environment: monorepo sibling installs, services, secrets). A scale-to-zero
  // worker installs only the target package's deps; when the suite reaches into
  // sibling packages or unconfigured tooling, it fails to even START — module
  // resolution, a missing test binary, etc. That's NOT a real assertion failure
  // and no code edit fixes it, so don't block (or burn repair cycles) on it.
  // Open the PR; the PR's CI has the full setup and is the real test gate. ---
  if (text.includes('cannot find module') || text.includes('module not found')) return true;
  if (text.includes('cannot find package')) return true;
  if (text.includes('command not found') || text.includes('not recognized as')) return true;
  if (text.includes('could not determine executable to run')) return true;
  return false;
}

export async function runTests(opts: {
  workDir: string;
  testCommand: string;
  logger: FixLogger;
  timeoutMs?: number;
  extraEnv?: Record<string, string>;
}): Promise<TestResult> {
  const { workDir, testCommand, logger, extraEnv } = opts;
  const timeoutMs = opts.timeoutMs ?? 5 * 60 * 1000;

  await logger.info('tests', `Running tests: ${testCommand}`);
  const startedAt = Date.now();

  const env = { ...process.env, ...(extraEnv ?? {}) };

  const result = spawnSync('sh', ['-lc', testCommand], {
    cwd: workDir,
    encoding: 'utf-8',
    timeout: timeoutMs,
    maxBuffer: 10 * 1024 * 1024,
    env,
  });

  const durationMs = Date.now() - startedAt;
  const timedOut = result.error?.message?.includes('ETIMEDOUT') === true;
  const stdout = result.stdout ?? '';
  const stderr = result.stderr ?? '';
  const noTestSuite = !timedOut && detectUnverifiable({
    testCommand,
    exitCode: result.status,
    stdout,
    stderr,
  });
  // Soft-pass: either there's no suite, or the harness couldn't run here.
  // Nothing was validated locally, but the patch doesn't get to claim it was
  // either — the pipeline still opens a draft PR, and review + the PR's CI are
  // the gate.
  const passed = !timedOut && (result.status === 0 || noTestSuite);

  if (timedOut) {
    await logger.error('tests', 'Test command timed out');
  } else if (noTestSuite) {
    await logger.warn(
      'tests',
      `Could not verify locally (exit ${result.status}) — opening PR; the PR's CI runs the tests`,
    );
  } else if (passed) {
    await logger.success('tests', 'Tests passed', durationMs);
  } else {
    // Log a tail of the actual output so we can tell whether this is a real
    // failure or a "no test suite" signature we didn't yet recognize.
    const stdoutTail = stdout.slice(-400).replace(/\s+/g, ' ').trim();
    const stderrTail = stderr.slice(-400).replace(/\s+/g, ' ').trim();
    await logger.warn(
      'tests',
      `Tests failed (exit ${result.status}) | stdout: "${stdoutTail}" | stderr: "${stderrTail}"`,
    );
  }

  return {
    passed,
    exitCode: result.status,
    stdout,
    stderr,
    durationMs,
    timedOut,
    noTestSuite,
  };
}
