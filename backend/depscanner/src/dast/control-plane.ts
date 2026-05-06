// Phase 24a (v2.1a): subprocess control-plane for the DAST runner.
//
// The pipeline can run a 25+ minute ZAP scan; we need three things the
// helper-script wrapper in runner.ts didn't give us:
//
//   1. A handle the pipeline can `abort()` from outside the spawn promise
//      (cancellation poll, loggedOut-indicator threshold, scan_timeout).
//   2. Group-kill semantics — ZAP forks Java + Firefox-for-AJAX-spider; a
//      lone SIGTERM to the parent leaves zombies. We spawn detached so the
//      child is its own process-group leader and the pipeline can issue
//      `process.kill(-pid, 'SIGTERM')` to cull the group.
//   3. A SIGTERM → 10s grace → SIGKILL escalation so abort() resolves the
//      child within a bounded window even if Java refuses SIGTERM.
//
// On Windows `process.kill(-pid, signal)` is unsupported. Production runs on
// Linux containers; the fallback is to kill the parent only (which is what
// `child.kill()` does). Tests can substitute a stub spawn impl.

import { spawn, type ChildProcess } from 'child_process';

export interface SpawnExternalOptions {
  command: string;
  args: string[];
  /** Hard timeout — auto-abort() at this elapsed ms. Defaults to 30 min. */
  timeoutMs?: number;
  /**
   * Stderr line callback. Called once per Buffer chunk (NOT per line);
   * pipeline-side parsing is the caller's job. Allowed to be a no-op.
   */
  onStderr?: (chunk: string) => void;
  /**
   * Stdout line callback. Same shape as onStderr.
   */
  onStdout?: (chunk: string) => void;
  /**
   * Test seam — substitute a fake `spawn` implementation. Production uses
   * the imported child_process.spawn.
   */
  spawnImpl?: typeof spawn;
}

export type AbortReason =
  | 'cancellation_requested'
  | 'auth_lost_threshold'
  | 'scan_timeout'
  | 'pipeline_error';

export interface SpawnExternalHandle {
  /** Underlying child for tests / direct stdio access; do NOT call .kill() — use abort(). */
  process: ChildProcess;
  /**
   * Abort the running subprocess and its entire process group. Idempotent —
   * second call after the child exits is a no-op. Bounded by SIGTERM_GRACE_MS
   * before SIGKILL escalates.
   */
  abort: (reason: AbortReason) => void;
  /**
   * Resolves when the child exits (cleanly OR via abort). Rejects only on
   * spawn error before the child PID is assigned. After resolution, callers
   * read `result.exitCode` / `aborted` / `abortReason` for branching.
   */
  done: Promise<SpawnExternalResult>;
}

export interface SpawnExternalResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  /** True if abort() was called before the child exited cleanly. */
  aborted: boolean;
  abortReason: AbortReason | null;
  durationMs: number;
}

export const DEFAULT_TIMEOUT_MS = 30 * 60_000;
export const SIGTERM_GRACE_MS = 10_000;

/**
 * Spawn a long-running subprocess and return a handle. The child is launched
 * detached so we can group-kill via `process.kill(-pid, signal)` — important
 * because ZAP forks Java + Firefox and a non-group SIGTERM leaves zombies.
 */
export function spawnExternal(opts: SpawnExternalOptions): SpawnExternalHandle {
  const startedAt = Date.now();
  const spawner = opts.spawnImpl ?? spawn;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  // detached: true + own stdio pipes so the child is its own process-group
  // leader. We do NOT call .unref() — the parent must wait on this child.
  const child = spawner(opts.command, opts.args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: process.platform !== 'win32',
  });

  let stdout = '';
  let stderr = '';
  let aborted = false;
  let abortReason: AbortReason | null = null;
  let killTimer: NodeJS.Timeout | null = null;

  child.stdout?.on('data', (b: Buffer) => {
    const s = b.toString('utf-8');
    stdout += s;
    opts.onStdout?.(s);
  });

  child.stderr?.on('data', (b: Buffer) => {
    const s = b.toString('utf-8');
    stderr += s;
    opts.onStderr?.(s);
  });

  function killGroup(signal: NodeJS.Signals): void {
    if (!child.pid) {
      try {
        child.kill(signal);
      } catch {
        /* already exited */
      }
      return;
    }
    if (process.platform === 'win32') {
      try {
        child.kill(signal);
      } catch {
        /* noop */
      }
      return;
    }
    try {
      // Negative PID targets the group whose leader is `child.pid`.
      process.kill(-child.pid, signal);
    } catch {
      // Race: child already exited and the group is gone.
    }
  }

  let settled = false;

  function abortFn(reason: AbortReason): void {
    if (aborted) return;
    aborted = true;
    abortReason = reason;
    killGroup('SIGTERM');
    killTimer = setTimeout(() => {
      if (settled) return;
      killGroup('SIGKILL');
    }, SIGTERM_GRACE_MS);
    killTimer.unref?.();
  }

  const done: Promise<SpawnExternalResult> = new Promise((resolve, reject) => {
    const timeoutTimer = setTimeout(() => {
      if (settled) return;
      abortFn('scan_timeout');
    }, timeoutMs);
    timeoutTimer.unref?.();

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      reject(err);
    });

    child.on('close', (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      resolve({
        exitCode: code,
        signal,
        stdout,
        stderr,
        aborted,
        abortReason,
        durationMs: Date.now() - startedAt,
      });
    });
  });

  return {
    process: child,
    abort: abortFn,
    done,
  };
}

// ---------------------------------------------------------------------------
// Auth-lost stderr watcher
// ---------------------------------------------------------------------------

/**
 * Per plan §Task 7: consecutive_lost_count gates on response status (only
 * 200/302/401, ignore 5xx + 4xx-other-than-401) and a 5-minute debounce
 * window with no successful indicator-clear in between. Threshold defaults
 * to 4 trips.
 *
 * The watcher inspects ZAP stderr for lines tagged by the AF replacer/scan
 * job when an HTTP response matches `loggedOutIndicator` AND the status code
 * is in the gate set. Real-world ZAP doesn't emit such tagged lines today;
 * this scaffolding lets the AF YAML's passive scan rule (added in v2.1b)
 * stream "AUTH_LOST status=200 url=..." sentinel lines we can latch onto.
 *
 * Until the AF rule lands, the watcher is dormant — pipeline still calls
 * `recordHit`, but nothing emits hits. That's the safe default: false
 * negatives until the upstream rule ships, never false positives.
 */
export interface AuthLostWatcherOptions {
  threshold?: number;
  windowMs?: number;
  gateStatusCodes?: ReadonlySet<number>;
  onThresholdReached: (state: AuthLostState) => void;
}

export interface AuthLostState {
  consecutiveLostCount: number;
  firstLostAt: string | null;
  lastLoggedOutUrl: string | null;
  lastLoggedOutAt: string | null;
}

export const DEFAULT_AUTH_LOST_THRESHOLD = 4;
export const DEFAULT_AUTH_LOST_WINDOW_MS = 5 * 60_000;
export const DEFAULT_AUTH_LOST_STATUS_GATE = new Set<number>([200, 302, 401]);

export function createAuthLostWatcher(opts: AuthLostWatcherOptions): {
  recordHit: (status: number, url: string) => void;
  recordIndicatorClear: () => void;
  state: () => AuthLostState;
} {
  const threshold = opts.threshold ?? DEFAULT_AUTH_LOST_THRESHOLD;
  const windowMs = opts.windowMs ?? DEFAULT_AUTH_LOST_WINDOW_MS;
  const gate = opts.gateStatusCodes ?? DEFAULT_AUTH_LOST_STATUS_GATE;
  let firedOnce = false;

  const state: AuthLostState = {
    consecutiveLostCount: 0,
    firstLostAt: null,
    lastLoggedOutUrl: null,
    lastLoggedOutAt: null,
  };

  return {
    recordHit(status: number, url: string): void {
      if (!gate.has(status)) return;
      const now = Date.now();
      const firstLostAtMs = state.firstLostAt ? Date.parse(state.firstLostAt) : null;
      if (firstLostAtMs && now - firstLostAtMs > windowMs) {
        // Window elapsed with no clear — reset rather than carry forward.
        state.consecutiveLostCount = 0;
        state.firstLostAt = null;
      }
      state.consecutiveLostCount += 1;
      if (!state.firstLostAt) state.firstLostAt = new Date(now).toISOString();
      state.lastLoggedOutUrl = url;
      state.lastLoggedOutAt = new Date(now).toISOString();
      if (!firedOnce && state.consecutiveLostCount >= threshold) {
        firedOnce = true;
        opts.onThresholdReached({ ...state });
      }
    },
    recordIndicatorClear(): void {
      state.consecutiveLostCount = 0;
      state.firstLostAt = null;
    },
    state(): AuthLostState {
      return { ...state };
    },
  };
}
