import { Worker } from 'worker_threads';
import * as Sentry from '@sentry/node';

/**
 * Worker stall watchdog.
 *
 * The depscanner pipeline can wedge mid-step. When it does, the machine sits idle
 * (a 64GB box) until the *backend's* external 5-minute stuck detector SIGTERMs it
 * — and a CPU-blocked or alive-but-frozen worker may ignore SIGTERM entirely. This
 * watchdog makes the worker self-terminate FIRST. The timing check runs on a
 * dedicated worker_thread reading a SharedArrayBuffer, so it fires even when the
 * main event loop is fully blocked — a main-thread timer could not.
 *
 * Two independent stall signals, because hangs come in two shapes:
 *
 *   1. LIVENESS — updated on every heartbeat (the 30s liveness ping + subprocess
 *      pulses). Goes stale only when the event loop is blocked or the DB is
 *      wedged (a CPU-bound hang). Short window → fast kill. The graceful soft
 *      path usually can't run here (the loop is blocked), so it escalates to a
 *      hard SIGKILL.
 *
 *   2. PROGRESS — updated on real pipeline movement: every extraction-log write
 *      (every step emits them) + the subprocess heartbeat callback (legit long
 *      scanners pulse every ~60s). Goes stale when the pipeline is frozen even
 *      though the event loop is still alive — e.g. stuck on a network/DB `await`
 *      that never resolves. The bare 30s liveness ping keeps firing in that case,
 *      so LIVENESS alone would never catch it (the original gap). Longer,
 *      generous window so a legitimately slow-but-quiet step is never killed; the
 *      loop is alive here, so the graceful soft path (write a clean failure, then
 *      exit) does run.
 *
 * Extraction jobs arm BOTH signals. DAST jobs arm LIVENESS only — they don't feed
 * the extraction-log progress stream, so the progress signal would false-fire on a
 * legitimately long active scan.
 */

export interface WorkerWatchdog {
  /**
   * Begin watching. `withProgress` enables the second (pipeline-progress) signal;
   * pass false for jobs that don't feed markProgress (DAST), leaving only the
   * liveness signal.
   */
  arm(withProgress: boolean): void;
  /** Stop watching. Call when a job finishes / between jobs (idle poll). */
  disarm(): void;
  /** Liveness ping — call after every successful heartbeat write. */
  markLiveness(): void;
  /** Real pipeline progress — call on every log write + subprocess pulse. Implies liveness. */
  markProgress(): void;
  /**
   * Register the best-effort cleanup to run on a soft stall (e.g. mark the job
   * failed). Pass null to clear between jobs. Invoked at most once per stall,
   * under an internal time cap, after which the process exits 1.
   */
  onSoftStall(fn: (() => Promise<void>) | null): void;
  /** Tear down the watchdog thread (process shutdown). */
  stop(): void;
}

const LIVENESS_SLOT = 0;
const ARMED_SLOT = 1; // 0 = disarmed, 1 = liveness-only (DAST), 2 = liveness + progress + max-runtime (extraction)
const PROGRESS_SLOT = 2;
const ARMED_AT_SLOT = 3; // epoch ms the current job was armed — drives the absolute runtime cap

// Inline worker so there's no extra file to copy into the Docker image. It only
// reads the shared timestamps on a fixed interval and escalates; all policy
// (thresholds) is passed in via workerData.
const WATCHDOG_THREAD_SOURCE = `
const { parentPort, workerData } = require('worker_threads');
const view = new BigInt64Array(workerData.sab);
const { liveSoftMs, liveHardMs, progSoftMs, progHardMs, jobSoftMs, jobHardMs, checkMs } = workerData;
let softFired = false;
let lastLive = -1n, lastProg = -1n;
setInterval(() => {
  const armed = Atomics.load(view, ${ARMED_SLOT});
  if (armed === 0n) { softFired = false; return; }
  const live = Atomics.load(view, ${LIVENESS_SLOT});
  const prog = Atomics.load(view, ${PROGRESS_SLOT});
  if (live !== lastLive || prog !== lastProg) { lastLive = live; lastProg = prog; softFired = false; }
  const now = Date.now();
  const liveStall = now - Number(live);
  const progStall = armed === 2n ? (now - Number(prog)) : 0;
  // Absolute runtime cap (extraction only). The backstop for a job that keeps
  // BOTH the heartbeat and the progress signal fresh yet still runs far too long
  // — e.g. a scanner that fans out per-dependency on a huge repo, pulsing the
  // heartbeat from inside its loop the whole time. Neither stall signal catches
  // that, so cap total wall-clock since arm(). This is what actually guarantees
  // the machine stops.
  const jobAge = armed === 2n ? (now - Number(Atomics.load(view, ${ARMED_AT_SLOT}))) : 0;
  const hard = liveStall >= liveHardMs || progStall >= progHardMs || jobAge >= jobHardMs;
  if (hard) {
    const reason = jobAge >= jobHardMs ? 'max-runtime' : (liveStall >= liveHardMs ? 'liveness' : 'progress');
    try { console.error('[depscanner][watchdog] HARD ' + reason + ' (liveness=' + liveStall + 'ms, progress=' + progStall + 'ms, jobAge=' + jobAge + 'ms) — SIGKILL to release the machine'); } catch (e) {}
    try { process.kill(process.pid, 'SIGKILL'); } catch (e) {}
    return;
  }
  if (!softFired && (liveStall >= liveSoftMs || progStall >= progSoftMs || jobAge >= jobSoftMs)) {
    softFired = true;
    const reason = jobAge >= jobSoftMs ? 'max-runtime' : (liveStall >= liveSoftMs ? 'liveness' : 'progress');
    try { parentPort.postMessage({ type: 'soft-stall', reason: reason, liveMs: liveStall, progMs: progStall, jobAge: jobAge }); } catch (e) {}
  }
}, checkMs);
`;

function parseEnvMs(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const n = parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

export function startWorkerWatchdog(opts?: {
  livenessSoftMs?: number;
  livenessHardMs?: number;
  progressSoftMs?: number;
  progressHardMs?: number;
  maxJobMs?: number;
  checkIntervalMs?: number;
}): WorkerWatchdog {
  // Liveness (event-loop-block / DB-wedge): short, fast. Both under the external
  // 5-min detector.
  const liveSoftMs = opts?.livenessSoftMs ?? parseEnvMs('WORKER_STALL_SOFT_MS', 210_000);
  const liveHardMs = opts?.livenessHardMs ?? parseEnvMs('WORKER_STALL_HARD_MS', 255_000);
  // Progress (alive-but-frozen): generous, so a slow-but-quiet legit step is
  // never killed. The constraint is the rule_generation step — it's block-and-
  // wait, bounded by organization_reachability_settings.max_wait_seconds (default
  // 300s = 5 min) and emits few logs while it runs. 8 min soft clears that with
  // margin (and room for orgs that raise the cap); raise via the env override if
  // an org sets a very high max_wait_seconds. The bare liveness heartbeat stays
  // fresh during this kind of hang, so the external 5-min detector never fires
  // either — this window can exceed 5 min without conflict.
  const progSoftMs = opts?.progressSoftMs ?? parseEnvMs('WORKER_PROGRESS_STALL_SOFT_MS', 480_000);
  const progHardMs = opts?.progressHardMs ?? parseEnvMs('WORKER_PROGRESS_STALL_HARD_MS', 600_000);
  // Absolute per-job runtime cap (extraction) — a FAR runaway backstop, NOT a
  // routine limit. The progress signal already stops a genuinely stuck job
  // within minutes; a job that keeps making real progress is allowed to run as
  // long as it needs (a huge monorepo's malicious scan can legitimately take
  // the better part of an hour). This only catches a pathological job that
  // somehow keeps progress fresh for hours. Default 2h; env-tunable.
  const jobSoftMs = opts?.maxJobMs ?? parseEnvMs('WORKER_MAX_JOB_MS', 7_200_000); // 2 h
  const jobHardMs = jobSoftMs + 60_000;
  const checkMs = opts?.checkIntervalMs ?? 15_000;

  const sab = new SharedArrayBuffer(4 * BigInt64Array.BYTES_PER_ELEMENT);
  const view = new BigInt64Array(sab);
  const now = BigInt(Date.now());
  Atomics.store(view, LIVENESS_SLOT, now);
  Atomics.store(view, PROGRESS_SLOT, now);
  Atomics.store(view, ARMED_AT_SLOT, now);
  Atomics.store(view, ARMED_SLOT, 0n);

  let onStall: (() => Promise<void>) | null = null;
  let handling = false;
  let stopped = false;

  async function handleSoftStall(reason: string, liveMs: number, progMs: number): Promise<void> {
    console.error(
      `[depscanner][watchdog] soft ${reason} stall (liveness=${liveMs}ms, progress=${progMs}ms) — self-terminating to release the machine`,
    );
    try {
      Sentry.captureMessage(`depscanner worker stalled (${reason}, self-terminating)`, 'error');
    } catch {
      /* ignore */
    }
    try {
      if (onStall) {
        // Cap the best-effort cleanup so a stall caused by a wedged DB (where
        // these very writes would also hang) can't delay the exit.
        await Promise.race([onStall(), new Promise<void>((r) => setTimeout(r, 10_000))]);
      }
    } catch {
      /* best-effort */
    }
    try {
      await Sentry.close(2000);
    } catch {
      /* never block exit on flush */
    }
    process.exit(1);
  }

  let worker: Worker | null = null;
  try {
    worker = new Worker(WATCHDOG_THREAD_SOURCE, {
      eval: true,
      workerData: { sab, liveSoftMs, liveHardMs, progSoftMs, progHardMs, jobSoftMs, jobHardMs, checkMs },
    });
    // Never keep the process alive on the watchdog's account.
    worker.unref();
    worker.on('message', (msg: { type?: string; reason?: string; liveMs?: number; progMs?: number }) => {
      if (stopped || handling || !msg || msg.type !== 'soft-stall') return;
      handling = true;
      void handleSoftStall(msg.reason ?? 'unknown', msg.liveMs ?? 0, msg.progMs ?? 0);
    });
    worker.on('error', (e: Error) => {
      console.error('[depscanner][watchdog] thread error (continuing without watchdog):', e?.message ?? e);
    });
  } catch (e: any) {
    // A watchdog that fails to start must never take the worker down with it.
    console.error('[depscanner][watchdog] failed to start (continuing without watchdog):', e?.message ?? e);
  }

  return {
    arm(withProgress: boolean) {
      const t = BigInt(Date.now());
      Atomics.store(view, LIVENESS_SLOT, t);
      Atomics.store(view, PROGRESS_SLOT, t);
      Atomics.store(view, ARMED_AT_SLOT, t);
      Atomics.store(view, ARMED_SLOT, withProgress ? 2n : 1n);
    },
    disarm() {
      Atomics.store(view, ARMED_SLOT, 0n);
    },
    markLiveness() {
      Atomics.store(view, LIVENESS_SLOT, BigInt(Date.now()));
    },
    markProgress() {
      // Real progress also proves the loop is alive — bump both.
      const t = BigInt(Date.now());
      Atomics.store(view, LIVENESS_SLOT, t);
      Atomics.store(view, PROGRESS_SLOT, t);
    },
    onSoftStall(fn) {
      onStall = fn;
    },
    stop() {
      stopped = true;
      Atomics.store(view, ARMED_SLOT, 0n);
      if (worker) worker.terminate().catch(() => {});
    },
  };
}
