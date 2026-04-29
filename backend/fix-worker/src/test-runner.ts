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

// Heuristics for "the repo has no real test suite" — common scaffolds across
// the v1 ship-gate languages. If we match any of these, we treat the run as
// a pass-with-no-gate rather than a real failure.
function detectNoTestSuite(opts: {
  testCommand: string;
  exitCode: number | null;
  stderr: string;
  stdout: string;
}): boolean {
  const text = `${opts.stdout}\n${opts.stderr}`.toLowerCase();
  // npm init's default test script
  if (text.includes('error: no test specified')) return true;
  // pytest exits 5 when no tests collected
  if (opts.testCommand.startsWith('pytest') && opts.exitCode === 5) return true;
  if (text.includes('no tests ran') || text.includes('collected 0 items')) return true;
  // go test exits 0 with this message when there are no _test.go files; harmless
  // but worth flagging so we don't claim "tests passed" if a future change
  // makes the gate stricter
  if (text.includes('[no test files]')) return true;
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
  const noTestSuite = !timedOut && detectNoTestSuite({
    testCommand,
    exitCode: result.status,
    stdout,
    stderr,
  });
  // "No test suite" is a soft-pass: nothing to verify, but the editor's patch
  // doesn't get to claim it's been validated either. The pipeline still opens
  // a draft PR — review is the gate.
  const passed = !timedOut && (result.status === 0 || noTestSuite);

  if (timedOut) {
    await logger.error('tests', 'Test command timed out');
  } else if (noTestSuite) {
    await logger.warn(
      'tests',
      `No test suite detected (exit ${result.status}) — opening PR without test verification`,
    );
  } else if (passed) {
    await logger.success('tests', 'Tests passed', durationMs);
  } else {
    await logger.warn('tests', `Tests failed (exit ${result.status})`);
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
