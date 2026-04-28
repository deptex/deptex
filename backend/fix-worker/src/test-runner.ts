import { spawnSync } from 'child_process';
import type { FixLogger } from './logger';

export interface TestResult {
  passed: boolean;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
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
  const passed = !timedOut && result.status === 0;

  if (passed) {
    await logger.success('tests', 'Tests passed', durationMs);
  } else if (timedOut) {
    await logger.error('tests', 'Test command timed out');
  } else {
    await logger.warn('tests', `Tests failed (exit ${result.status})`);
  }

  return {
    passed,
    exitCode: result.status,
    stdout: result.stdout ?? '',
    stderr: result.stderr ?? '',
    durationMs,
    timedOut,
  };
}
