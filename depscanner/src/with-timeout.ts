import type { Storage } from './storage';
import { spawn } from 'child_process';

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
    // Last-ditch structured marker: when Supabase is down, this is the only
    // record of the original error we were trying to persist. Operators can
    // grep `[LOGSTEPERROR_FALLBACK]` to recover the swallowed errors.
    console.error(
      '[LOGSTEPERROR_FALLBACK]',
      JSON.stringify({
        jobId: opts.jobId,
        projectId: opts.projectId,
        step: opts.step,
        code: opts.code,
        severity: opts.severity ?? 'error',
        originalErrorMessage: opts.message,
        insertFailureReason: error.message,
      }),
    );
  }
}

export interface ScannerSubprocessLogger {
  info: (step: string, msg: string) => Promise<void>;
  warn: (step: string, msg: string) => Promise<void>;
}

export interface ScannerSubprocessOptions {
  exe: string;
  args: string[];
  cwd?: string;
  logger?: ScannerSubprocessLogger;
  /** Step tag for verbose logs. Required when verboseLogStep is true. */
  verboseLogStep?: string;
  /** When true, stream stripped stdout to logger.info(verboseLogStep, ...). Mirrors DEPSCAN_VERBOSE_LOG. */
  verboseLog?: boolean;
  heartbeatIntervalMs?: number;
  onHeartbeat?: () => Promise<void> | void;
  /** External signal — when aborted, the child receives SIGTERM. */
  signal?: AbortSignal;
  /** Internal hard timeout. The shared withTimeout() typically supplies this via signal too;
   *  pass when the helper is used outside withTimeout (e.g. tests). */
  timeoutMs?: number;
  /** Extra env to merge over process.env. Used for DOCKER_AUTH_CONFIG, etc. */
  env?: Record<string, string | undefined>;
  /** Hard cap on stdout bytes — guards against a malicious scanner target
   *  emitting hundred-MB JSON that JSON.parse would OOM the worker on. When
   *  exceeded, the child is killed and the promise rejects with
   *  ScannerOutputTooLargeError. Default 64 MiB. */
  stdoutMaxBytes?: number;
}

export class ScannerOutputTooLargeError extends Error {
  readonly exe: string;
  readonly stdoutBytes: number;
  readonly limitBytes: number;
  constructor(exe: string, stdoutBytes: number, limitBytes: number) {
    super(`${exe} stdout exceeded ${limitBytes} bytes (got ${stdoutBytes})`);
    this.name = 'ScannerOutputTooLargeError';
    this.exe = exe;
    this.stdoutBytes = stdoutBytes;
    this.limitBytes = limitBytes;
  }
}

const DEFAULT_STDOUT_MAX_BYTES = 64 * 1024 * 1024;

/**
 * Spawn a scanner binary, collect stdout/stderr, run a heartbeat on a fixed
 * interval, kill the child on abort or timeout. Returns the raw streams; each
 * scanner module parses its own JSON.
 *
 * Logger and verbose-log behaviour mirror runDepScan's DEPSCAN_VERBOSE_LOG
 * pattern so per-scanner verbose env (e.g. DEPTEX_TRIVY_VERBOSE_LOG) can drop
 * subprocess output into extraction_logs for in-flight debugging.
 *
 * Heartbeat is interval-based (default 60s) and independent of stdout chunks,
 * so a long-running silent scanner still keeps the extraction-job heartbeat
 * alive.
 */
export function runScannerSubprocess(
  opts: ScannerSubprocessOptions
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const heartbeatIntervalMs = opts.heartbeatIntervalMs ?? 60_000;
  const verboseLog =
    opts.verboseLog === true && !!opts.logger && !!opts.verboseLogStep;

  return new Promise((resolve, reject) => {
    if (opts.signal?.aborted) {
      reject(new Error(`${opts.exe} aborted before start`));
      return;
    }

    const childEnv = opts.env
      ? { ...process.env, ...opts.env }
      : process.env;

    const child = spawn(opts.exe, opts.args, {
      cwd: opts.cwd,
      stdio: 'pipe',
      env: childEnv as NodeJS.ProcessEnv,
    });

    let stdout = '';
    let stderr = '';
    let stdoutBytes = 0;
    let stderrBytes = 0;
    const stdoutLimit = opts.stdoutMaxBytes ?? DEFAULT_STDOUT_MAX_BYTES;
    const stderrLimit = Math.min(4 * 1024 * 1024, stdoutLimit);
    let killedForOversizeOutput = false;

    child.stdout.on('data', (data: Buffer) => {
      stdoutBytes += data.length;
      if (stdoutBytes > stdoutLimit) {
        if (!killedForOversizeOutput) {
          killedForOversizeOutput = true;
          try { child.kill('SIGKILL'); } catch { /* already dead */ }
          reject(new ScannerOutputTooLargeError(opts.exe, stdoutBytes, stdoutLimit));
        }
        return;
      }
      const chunk = data.toString();
      stdout += chunk;
      if (verboseLog && opts.logger && opts.verboseLogStep) {
        const trimmed = chunk
          .replace(/\[[0-9;]*m/g, '')
          .trim();
        if (trimmed) {
          opts.logger.info(opts.verboseLogStep, trimmed).catch(() => {});
        }
      }
    });
    child.stderr.on('data', (data: Buffer) => {
      stderrBytes += data.length;
      if (stderrBytes > stderrLimit) {
        // Drop further chunks; stderr blow-up is usually a verbose tool,
        // not a memory exhaustion vector.
        return;
      }
      stderr += data.toString();
    });

    const heartbeatInterval = opts.onHeartbeat
      ? setInterval(async () => {
          try {
            await opts.onHeartbeat!();
          } catch {
            /* heartbeat failure is non-fatal */
          }
        }, heartbeatIntervalMs)
      : null;

    // A scanner may ignore SIGTERM; escalate to SIGKILL after a grace period so
    // the child can't outlive the step and have the workspace rm'd under it.
    // Cleared on close/error so a clean exit doesn't kill.
    let sigkillTimer: NodeJS.Timeout | undefined;
    const escalateKill = () => {
      try { child.kill('SIGTERM'); } catch { /* already dead */ }
      if (!sigkillTimer) {
        sigkillTimer = setTimeout(() => {
          try { child.kill('SIGKILL'); } catch { /* already dead */ }
        }, 5000);
      }
    };

    let internalTimeout: NodeJS.Timeout | null = null;
    if (opts.timeoutMs) {
      internalTimeout = setTimeout(() => {
        escalateKill();
        reject(
          new Error(
            `${opts.exe} timed out after ${opts.timeoutMs} ms (internal)`
          )
        );
      }, opts.timeoutMs);
    }

    // External abort: kill the child only. Don't reject — the outer withTimeout
    // owns the timeout error class. (Mirrors runDepScan rationale.)
    const onAbort = () => {
      escalateKill();
    };
    if (opts.signal) {
      opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    child.on('close', (code: number | null) => {
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (internalTimeout) clearTimeout(internalTimeout);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      opts.signal?.removeEventListener('abort', onAbort);
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });

    child.on('error', (err: Error) => {
      if (heartbeatInterval) clearInterval(heartbeatInterval);
      if (internalTimeout) clearTimeout(internalTimeout);
      if (sigkillTimer) clearTimeout(sigkillTimer);
      opts.signal?.removeEventListener('abort', onAbort);
      reject(err);
    });
  });
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
