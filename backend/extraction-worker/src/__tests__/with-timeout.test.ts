import { withTimeout, StepTimeoutError, classifyError, logStepError } from '../with-timeout';

describe('withTimeout', () => {
  it('resolves with the fn result when under budget', async () => {
    const result = await withTimeout(async () => 'ok', 100, 'test_step');
    expect(result).toBe('ok');
  });

  it('rejects with StepTimeoutError when fn exceeds budget', async () => {
    const slow = () => new Promise<string>((r) => setTimeout(() => r('late'), 200));
    await expect(withTimeout(slow, 50, 'slow_step')).rejects.toBeInstanceOf(StepTimeoutError);
  });

  it('StepTimeoutError carries step name + budget + elapsed', async () => {
    const slow = () => new Promise<string>((r) => setTimeout(() => r('late'), 100));
    try {
      await withTimeout(slow, 20, 'my_step');
      fail('expected throw');
    } catch (e) {
      expect(e).toBeInstanceOf(StepTimeoutError);
      const err = e as StepTimeoutError;
      expect(err.step).toBe('my_step');
      expect(err.timeoutMs).toBe(20);
      expect(err.elapsedMs).toBeGreaterThanOrEqual(20);
      expect(err.message).toMatch(/timed out/);
    }
  });

  it('propagates fn errors unchanged (not as timeout)', async () => {
    const boom = async () => {
      throw new Error('real failure');
    };
    await expect(withTimeout(boom, 100, 'boom_step')).rejects.toThrow('real failure');
  });

  it('clears timer so the event loop does not hang', async () => {
    // Quick-finishing fn with a large budget — if we leaked the timer, the
    // process would stay alive for 10s. Jest's fake timers make this explicit.
    jest.useFakeTimers();
    try {
      const p = withTimeout(async () => 'done', 10_000, 'fast_step');
      await expect(p).resolves.toBe('done');
      // If timer leaked, getTimerCount would be >0 after await.
      expect(jest.getTimerCount()).toBe(0);
    } finally {
      jest.useRealTimers();
    }
  });

  it('aborts the passed AbortSignal when the timeout fires', async () => {
    let signalRef: AbortSignal | null = null;
    const slow = (signal: AbortSignal) => {
      signalRef = signal;
      return new Promise<string>((r) => setTimeout(() => r('late'), 500));
    };
    await expect(withTimeout(slow, 20, 'aborter')).rejects.toBeInstanceOf(StepTimeoutError);
    expect(signalRef).not.toBeNull();
    expect(signalRef!.aborted).toBe(true);
  });

  it('does not abort the signal when fn resolves under budget', async () => {
    let signalRef: AbortSignal | null = null;
    const fast = async (signal: AbortSignal) => {
      signalRef = signal;
      return 'ok';
    };
    await expect(withTimeout(fast, 500, 'non_aborter')).resolves.toBe('ok');
    expect(signalRef).not.toBeNull();
    expect(signalRef!.aborted).toBe(false);
  });
});

describe('classifyError', () => {
  it('classifies StepTimeoutError as timeout', () => {
    const err = new StepTimeoutError('s', 100, 200);
    expect(classifyError(err)).toMatchObject({ code: 'timeout' });
  });

  it('classifies OOM signatures as oom', () => {
    expect(classifyError(new Error('process killed: ENOMEM'))).toMatchObject({ code: 'oom' });
    expect(classifyError(new Error('JavaScript heap out of memory'))).toMatchObject({ code: 'oom' });
  });

  it('classifies network errors as network_error', () => {
    expect(classifyError(new Error('ECONNRESET during clone'))).toMatchObject({ code: 'network_error' });
    expect(classifyError(new Error('fetch failed: ETIMEDOUT'))).toMatchObject({ code: 'network_error' });
  });

  it('classifies subprocess failures as subprocess_failed', () => {
    expect(classifyError(new Error('cdxgen subprocess exited with code 1'))).toMatchObject({ code: 'subprocess_failed' });
  });

  it('falls back to unexpected for unmatched Error', () => {
    expect(classifyError(new Error('something weird'))).toMatchObject({
      code: 'unexpected',
      message: 'something weird',
    });
  });

  it('handles non-Error throws via String()', () => {
    expect(classifyError('plain string')).toMatchObject({ code: 'unexpected', message: 'plain string' });
    expect(classifyError(42)).toMatchObject({ code: 'unexpected', message: '42' });
  });
});

describe('logStepError', () => {
  it('inserts a structured row with all fields populated', async () => {
    const insert = jest.fn().mockResolvedValue({ error: null });
    const from = jest.fn().mockReturnValue({ insert });
    const storage = { from } as any;

    await logStepError(storage, {
      jobId: 'job-1',
      projectId: 'proj-1',
      step: 'clone',
      code: 'timeout',
      message: 'step "clone" timed out',
      stack: 'at foo ...',
      machineId: 'machine-abc',
      durationMs: 900_000,
      severity: 'error',
    });

    expect(from).toHaveBeenCalledWith('extraction_step_errors');
    expect(insert).toHaveBeenCalledWith({
      extraction_job_id: 'job-1',
      project_id: 'proj-1',
      step: 'clone',
      code: 'timeout',
      message: 'step "clone" timed out',
      stack: 'at foo ...',
      machine_id: 'machine-abc',
      duration_ms: 900_000,
      severity: 'error',
    });
  });

  it('defaults optional fields (stack/machineId/durationMs) to null and severity to error', async () => {
    const insert = jest.fn().mockResolvedValue({ error: null });
    const from = jest.fn().mockReturnValue({ insert });
    const storage = { from } as any;

    await logStepError(storage, {
      jobId: 'job-1',
      projectId: 'proj-1',
      step: 'semgrep',
      code: 'oom',
      message: 'ran out of memory',
    });

    expect(insert).toHaveBeenCalledWith(
      expect.objectContaining({
        stack: null,
        machine_id: null,
        duration_ms: null,
        severity: 'error',
      }),
    );
  });

  it('does not throw when the insert itself errors (logs to console instead)', async () => {
    const originalError = console.error;
    const consoleError = jest.fn();
    console.error = consoleError;
    try {
      const insert = jest.fn().mockResolvedValue({ error: { message: 'permission denied' } });
      const from = jest.fn().mockReturnValue({ insert });
      const storage = { from } as any;

      await expect(
        logStepError(storage, {
          jobId: 'job-1',
          projectId: 'proj-1',
          step: 'dep_scan',
          code: 'subprocess_failed',
          message: 'dep-scan failed',
        }),
      ).resolves.toBeUndefined();
      expect(consoleError).toHaveBeenCalledWith(
        expect.stringContaining('Failed to log step error'),
        'permission denied',
        expect.any(Object),
      );
    } finally {
      console.error = originalError;
    }
  });

  it('accepts severity=warn for graceful degradation', async () => {
    const insert = jest.fn().mockResolvedValue({ error: null });
    const from = jest.fn().mockReturnValue({ insert });
    const storage = { from } as any;

    await logStepError(storage, {
      jobId: 'job-1',
      projectId: 'proj-1',
      step: 'ast_import',
      code: 'timeout',
      message: 'ast parse slow — continuing without imports',
      severity: 'warn',
    });

    expect(insert).toHaveBeenCalledWith(expect.objectContaining({ severity: 'warn' }));
  });
});
