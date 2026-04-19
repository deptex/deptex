import { SupabaseClient } from '@supabase/supabase-js';

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
 * a StepTimeoutError. The underlying promise is NOT cancelled (Node has no
 * cancellation primitive) — it just loses the race and its result is ignored.
 *
 * Callers that spawn subprocesses should also wire `AbortSignal` into the
 * subprocess so the child actually stops. withTimeout alone is not enough
 * to reclaim OS resources.
 */
export async function withTimeout<T>(
  fn: () => Promise<T>,
  timeoutMs: number,
  step: string
): Promise<T> {
  const start = Date.now();
  let timer: NodeJS.Timeout | undefined;

  const timeoutPromise = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      reject(new StepTimeoutError(step, timeoutMs, Date.now() - start));
    }, timeoutMs);
  });

  try {
    return await Promise.race([fn(), timeoutPromise]);
  } finally {
    if (timer) clearTimeout(timer);
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
  supabase: SupabaseClient,
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
