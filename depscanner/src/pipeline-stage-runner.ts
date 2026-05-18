import type { Storage } from './storage';
import {
  withTimeout,
  logStepError,
  classifyError,
  type StepErrorSeverity,
} from './with-timeout';

/**
 * Logger interface used by stages — kept structural so tests can pass mocks
 * with no-op methods. Mirrors the shape pipeline.ts already constructs.
 */
export interface StageLogger {
  info: (step: string, msg: string, ...rest: unknown[]) => Promise<void> | void;
  warn: (step: string, msg: string, ...rest: unknown[]) => Promise<void> | void;
  error?: (step: string, msg: string, ...rest: unknown[]) => Promise<void> | void;
  success?: (step: string, msg: string, durationMs?: number, meta?: unknown) => Promise<void> | void;
}

/**
 * Parameters fed to the on-error hook so callers can preserve their bespoke
 * post-failure behavior (transform error to user-friendly message, call
 * setError, write bespoke telemetry rows, etc.) without re-implementing the
 * classify + logStepError boilerplate the runner already handles.
 */
export interface StageErrorContext {
  err: unknown;
  /** Result of classifyError(err). Already persisted to extraction_step_errors when jobId is present. */
  code: string;
  message: string;
  stack?: string;
  /** ms since runStage entered (i.e., the step duration up to the failure). */
  durationMs: number;
  /** True when the runner already persisted a row in extraction_step_errors. */
  persisted: boolean;
}

export interface RunStageOptions<T> {
  /** Step name. Used for withTimeout label, extraction_step_errors.step. */
  name: string;
  /**
   * Optional hard timeout. When omitted, the body runs without a withTimeout
   * wrap (matches existing call sites that delegate timeout management to the
   * body — e.g. rule-generation, iac, malicious, sbom-upload).
   */
  timeoutMs?: number;
  /**
   * Step body. Receives an AbortSignal when timeoutMs is set; receives
   * undefined otherwise. Existing zero-arg callbacks remain compatible.
   */
  fn: (signal?: AbortSignal) => Promise<T>;
  /** Storage handle for logStepError. */
  supabase: Storage;
  /** scan_jobs.id — when null/undefined, logStepError is skipped (matches existing behavior). */
  jobId: string | null | undefined;
  /** project_repositories.project_id — required by extraction_step_errors. */
  projectId: string;
  /** extraction_logs sink. */
  log: StageLogger;
  /**
   * Severity for the persisted extraction_step_errors row.
   *   - 'error' → rethrow after logging.
   *   - 'warn'  → swallow, return undefined.
   * The on-error hook can override either default by returning an explicit
   * { rethrow: boolean }.
   */
  severity?: StepErrorSeverity;
  /**
   * When true, the durationMs field is NOT written to extraction_step_errors
   * on failure. Matches a handful of existing call sites (rule_generation,
   * iac_container_scan) that historically only persisted code/message/stack.
   * Stage telemetry parity — adding a field where one wasn't before is still
   * a shape change for downstream queries.
   */
  omitDuration?: boolean;
  /**
   * Hook called after the runner has classified + persisted the failure.
   * Use it to: transform the error to a user-facing string, call setError,
   * decide bail-vs-continue (return { rethrow: true | false }), or emit a
   * bespoke log line. When the hook returns nothing, the default for the
   * chosen severity applies.
   *
   * If the hook itself throws, the thrown value replaces err in the rethrow.
   */
  onError?: (ctx: StageErrorContext) => Promise<{ rethrow?: boolean; throwAs?: unknown } | void> | { rethrow?: boolean; throwAs?: unknown } | void;
}

/**
 * Runs a single pipeline stage with the boilerplate that every step in
 * pipeline.ts repeats today: timeout-wrap (when budgeted), classify-error,
 * persist to extraction_step_errors with duration_ms + severity, log a
 * generic warn line for soft steps, and rethrow for hard steps. Bespoke
 * post-failure behavior plugs in via opts.onError so we never lose the
 * step-specific transforms (clone → classifyCloneError, sbom → setError +
 * userMsg, finalize → log.error 'Atomic commit failed', etc.).
 *
 * Returns the body's return value on success; returns undefined when the
 * step soft-failed (severity='warn' default or onError chose not to rethrow).
 */
export async function runStage<T>(opts: RunStageOptions<T>): Promise<T | undefined> {
  const startedAt = Date.now();
  const severity: StepErrorSeverity = opts.severity ?? 'error';

  try {
    if (opts.timeoutMs !== undefined) {
      // withTimeout already passes an AbortSignal — forward it.
      return await withTimeout(
        (signal) => opts.fn(signal),
        opts.timeoutMs,
        opts.name,
      );
    }
    return await opts.fn();
  } catch (err) {
    const { code, message, stack } = classifyError(err);
    const durationMs = Date.now() - startedAt;
    let persisted = false;

    if (opts.jobId) {
      try {
        await logStepError(opts.supabase, {
          jobId: opts.jobId,
          projectId: opts.projectId,
          step: opts.name,
          code,
          message,
          stack,
          ...(opts.omitDuration ? {} : { durationMs }),
          severity,
        });
        persisted = true;
      } catch {
        // logStepError already records a [LOGSTEPERROR_FALLBACK] line on its
        // own insert failure; we just guard the runner from a swallowed
        // throw breaking the on-error hook.
      }
    }

    let rethrow = severity === 'error';
    let throwAs: unknown = err;
    if (opts.onError) {
      try {
        const ret = await opts.onError({ err, code, message, stack, durationMs, persisted });
        if (ret) {
          if (typeof ret.rethrow === 'boolean') rethrow = ret.rethrow;
          if ('throwAs' in ret && ret.throwAs !== undefined) throwAs = ret.throwAs;
        }
      } catch (hookErr) {
        // Hook threw — honor it: rethrow what the hook produced.
        rethrow = true;
        throwAs = hookErr;
      }
    }

    if (rethrow) throw throwAs;
    return undefined;
  }
}
