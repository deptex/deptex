/**
 * Main-thread host that runs the taint engine's CPU-bound core
 * (`runEngineCore`) inside a worker_thread.
 *
 * WHY THIS EXISTS — the production bug it fixes:
 * `runEngineCore` builds the whole-program callgraph. For JS/TS that is a
 * synchronous `ts.createProgram()` + TypeChecker walk that, on a large
 * codebase, runs for minutes and BLOCKS the Node event loop. The depscanner
 * worker's heartbeat is a main-thread `setInterval`, so a blocked loop freezes
 * the heartbeat → the backend's 5-minute stuck-detector reaps a worker that is
 * actually still working. (Observed: every scan of the Deptex Express/TS
 * backend failed here for days — `taint_engine_runs` stuck at `running`, no
 * `callgraph_build_ms`, scan never finalized.) The 30-min `withTimeout` that
 * was supposed to bound it is useless because its `setTimeout` lives on the
 * same blocked loop.
 *
 * THE FIX — run the core off-thread:
 *   - The main loop (and the heartbeat) stays free, so a legitimately long
 *     build is allowed to run to completion. `onKeepAlive` pulses the heartbeat
 *     + a progress log on a fixed interval so neither the worker's own stall
 *     watchdog nor the backend's stuck-detector reaps a still-working build.
 *   - A genuinely wedged build (one that exceeds the generous timeout) is the
 *     only thing terminated — that's the "slow ≠ stuck" line.
 *
 * The core is IO-free and returns only structured-cloneable data, so it crosses
 * the worker boundary cleanly. The AI fp-filter (the one IO stage — DB, Redis,
 * network) stays on the main thread in `runEngine()`.
 */

import { Worker } from 'worker_threads';
import * as path from 'path';
import * as fs from 'fs';
import type { EngineCoreResult, RunEngineCoreOptions } from './runner';

/**
 * Thrown when the engine core exceeds its wall-clock budget. The pipeline step
 * treats this as a SOFT failure: stamp `taint_engine_runs` aborted and continue
 * the extraction (reachability falls back to the heuristic classifier) instead
 * of failing the whole scan.
 */
export class EngineCoreTimeoutError extends Error {
  constructor(public readonly timeoutMs: number) {
    super(`taint engine core exceeded ${timeoutMs}ms budget`);
    this.name = 'EngineCoreTimeoutError';
  }
}

export interface RunInWorkerOptions {
  /**
   * Hard wall-clock budget. On expiry the worker is terminated and
   * `EngineCoreTimeoutError` is thrown. Generous by design — a big repo doing a
   * legit long build keeps running; this only fires when truly wedged.
   */
  timeoutMs: number;
  /**
   * Called on a fixed interval while the worker runs, with elapsed ms. Used to
   * pulse the heartbeat + emit a progress log so the build is never mistaken
   * for a stall. Errors are swallowed (a keepalive hiccup must not kill the run).
   */
  onKeepAlive?: (elapsedMs: number) => Promise<void> | void;
  /** Interval for `onKeepAlive`. Default 45s — comfortably under every stall window. */
  keepAliveMs?: number;
  /** Replays the warnings the worker collected (it can't call the live `onWarn`). */
  onWarn?: (msg: string) => void;
  /**
   * Inline fallback for when a worker can't be SPAWNED (dev/tsx, where only the
   * `.ts` entry exists, or `Worker` construction throws). Lets dev/CLI/tests run
   * the core directly. NOT used when a worker started then errored — re-running
   * a crashing core inline would just crash the main thread too.
   */
  inlineFallback: () => Promise<EngineCoreResult>;
}

// Compiled sibling in dist (`dist/taint-engine/engine-core-worker.js`). Absent
// in dev/tsx (only the `.ts` source exists) → we run inline there.
const WORKER_ENTRY = path.join(__dirname, 'engine-core-worker.js');

/** Strip the non-cloneable bits (AbortSignal, onWarn fn) before crossing the
 *  thread boundary. The worker aborts via `terminate()`, not the signal, and
 *  collects warnings into an array it posts back. */
function toWorkerData(opts: RunEngineCoreOptions) {
  return {
    workspaceRoot: opts.workspaceRoot,
    ecosystem: opts.ecosystem,
    maxIterations: opts.maxIterations,
    cveSpecs: opts.cveSpecs,
    projectFrameworks: opts.projectFrameworks,
  };
}

export async function runEngineCoreInWorker(
  coreOptions: RunEngineCoreOptions,
  opts: RunInWorkerOptions,
): Promise<EngineCoreResult> {
  // Dev/tsx: no compiled worker entry next to us → run inline.
  if (!fs.existsSync(WORKER_ENTRY)) {
    return opts.inlineFallback();
  }

  let worker: Worker;
  try {
    worker = new Worker(WORKER_ENTRY, { workerData: toWorkerData(coreOptions) });
  } catch {
    // Couldn't even start a worker — fall back to inline rather than fail.
    return opts.inlineFallback();
  }

  const start = Date.now();
  const keepAliveMs = opts.keepAliveMs ?? 45_000;
  let keepAlive: NodeJS.Timeout | null = null;
  if (opts.onKeepAlive) {
    keepAlive = setInterval(() => {
      // The main loop is free while the worker grinds, so this fires reliably —
      // that's the whole point. Swallow errors so a flaky heartbeat write never
      // takes the run down.
      void Promise.resolve(opts.onKeepAlive!(Date.now() - start)).catch(() => {});
    }, keepAliveMs);
    keepAlive.unref?.();
  }

  let timer: NodeJS.Timeout | null = null;

  try {
    return await new Promise<EngineCoreResult>((resolve, reject) => {
      timer = setTimeout(() => {
        void worker.terminate();
        reject(new EngineCoreTimeoutError(opts.timeoutMs));
      }, opts.timeoutMs);

      worker.once('message', (msg: unknown) => {
        const m = msg as { type?: string; result?: EngineCoreResult; message?: string; stack?: string; warnings?: unknown };
        if (m && Array.isArray(m.warnings) && opts.onWarn) {
          for (const w of m.warnings) opts.onWarn(String(w));
        }
        if (m && m.type === 'result' && m.result) {
          resolve(m.result);
        } else if (m && m.type === 'error') {
          const e = new Error(m.message ?? 'engine core worker error');
          if (m.stack) e.stack = m.stack;
          reject(e);
        } else {
          reject(new Error('engine core worker: malformed message'));
        }
      });
      worker.once('error', (err) => reject(err));
      worker.once('exit', (code) => {
        if (code !== 0) reject(new Error(`engine core worker exited with code ${code}`));
      });
    });
  } finally {
    if (keepAlive) clearInterval(keepAlive);
    if (timer) clearTimeout(timer);
    void worker.terminate();
  }
}
