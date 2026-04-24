import type { Storage } from './storage';

/**
 * Thrown when a pipeline step exceeds its budget.
 * pipeline.ts catches it to decide whether to abort the whole run or mark
 * the step as a soft failure (severity=warn) and continue.
 */
export class StepTimeoutError extends Error {
  readonly step: string;
  readonly timeoutMs: number;
  readonly elapsedMs: number;

  constructor(step: string, timeoutMs: number, elapsedMs: number) {
    super(`Step "${step}" timed out after ${elapsedMs}ms (budget ${timeoutMs}ms)`);
    this.name = 'StepTimeoutError';
    this.step = step;
    this.timeoutMs = timeoutMs;
    this.elapsedMs = elapsedMs;
  }
}

/**
 * Runs `fn` with a timeout budget. If `fn` exceeds `timeoutMs`, rejects with
 * a StepTimeoutError. An AbortSignal is passed to `fn`; when the timeout fires,
 * the signal is aborted. Callers that spawn subprocesses should register
 * `signal.addEventListener('abort', () => child.kill('SIGTERM'))` so the child
 * actually stops — the Promise.race alone does not cancel in-flight work.
 *
 * Existing callers that take no arguments (`() => Promise<T>`) remain
 * compatible; TS allows passing a function that ignores its parameter.
 */
export async function withTimeout<T>(
  fn: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  step: string
): Promise<T> {
  const controller = new AbortController();
  const start = Date.now();
  let timer: NodeJS.Timeout | undefined;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new StepTimeoutError(step, timeoutMs, Date.now() - start));
    }, timeoutMs);
  });

  // Hold a reference to the wrapped promise so we can await it in finally.
  // Without this, Promise.race returning on timeout leaves the wrapped
  // promise orphaned — any later rejection becomes an UnhandledPromiseRejection
  // and any finally-block cleanup (temp dirs, handles) can race with callers
  // that assume the step is fully settled.
  const wrapped = fn(controller.signal);
  // Swallow rejections on the orphaned path — the race result is the real
  // return value; this only exists so we can await completion in finally.
  wrapped.catch(() => {});

  try {
    return await Promise.race([wrapped, timeoutPromise]);
  } finally {
    if (timer) clearTimeout(timer);
    // Best-effort: let the wrapped promise settle (subprocess exit, cleanup)
    // before returning control to the caller, even when timeout won the race.
    // Capped so a truly hung subprocess doesn't block the caller forever.
    // Clear the cap timer as soon as `wrapped` settles so fast-path callers
    // don't leak a pending setTimeout into the event loop.
    let capTimer: NodeJS.Timeout | undefined;
    const capPromise = new Promise<void>((r) => {
      capTimer = setTimeout(r, 15_000);
    });
    await Promise.race([wrapped.catch(() => {}), capPromise]);
    if (capTimer) clearTimeout(capTimer);
  }
}

export type StepErrorSeverity = 'warn' | 'error';

export interface LogStepErrorOptions {
  jobId: string;
  projectId: string;
  step: string;
  code: string;
  message: string;
  stack?: string;
  machineId?: string;
  durationMs?: number;
  severity?: StepErrorSeverity;
}

/**
 * Writes a structured per-step failure into extraction_step_errors.
 * severity=warn = pipeline continued (graceful degradation).
 * severity=error = pipeline halted.
 *
 * Surfaced in /admin/extraction-failures.
 */
export async function logStepError(
  supabase: Storage,
  opts: LogStepErrorOptions
): Promise<void> {
  const { error } = await supabase.from('extraction_step_errors').insert({
    extraction_job_id: opts.jobId,
    project_id: opts.projectId,
    step: opts.step,
    code: opts.code,
    message: opts.message,
    stack: opts.stack ?? null,
    machine_id: opts.machineId ?? null,
    duration_ms: opts.durationMs ?? null,
    severity: opts.severity ?? 'error',
  });

  if (error) {
    console.error('[EXTRACT] Failed to log step error:', error.message, {
      step: opts.step,
      code: opts.code,
    });
  }
}

/**
 * Classifies an arbitrary thrown value into a structured (code, message) pair
 * for extraction_step_errors. Recognizes StepTimeoutError; otherwise returns
 * 'unexpected' with the message from Error.message if available.
 */
export function classifyError(err: unknown): { code: string; message: string; stack?: string } {
  if (err instanceof StepTimeoutError) {
    return { code: 'timeout', message: err.message, stack: err.stack };
  }
  if (err instanceof Error) {
    const msg = err.message || 'unknown error';
    // Heuristic: recognize common subprocess / network failure shapes
    if (/ENOMEM|out of memory|heap/i.test(msg)) return { code: 'oom', message: msg, stack: err.stack };
    if (/ECONNRESET|ETIMEDOUT|ENOTFOUND|fetch failed/i.test(msg)) return { code: 'network_error', message: msg, stack: err.stack };
    if (/exited with code|subprocess/i.test(msg)) return { code: 'subprocess_failed', message: msg, stack: err.stack };
    return { code: 'unexpected', message: msg, stack: err.stack };
  }
  return { code: 'unexpected', message: String(err) };
}
