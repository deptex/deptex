import 'dotenv/config';
import './instrument';
import * as Sentry from '@sentry/node';
import { captureInfraError } from './observability/capture';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Storage } from './storage';
import { runPipeline } from './pipeline';
import { ScanFailedError } from './scan-errors';
import { runDastPipeline } from './dast/pipeline';
import { sweepStaleDastTmpDirs } from './dast/nuclei-runner';
import { ExtractionLogger } from './logger';
import {
  claimJob,
  updateJobStatus,
  sendHeartbeat,
  isJobCancelled,
  getSupportedJobTypes,
  type ExtractionJobRow,
} from './job-db';
import { postScanJobMeterEvent } from './lib/meter-event';
import { startWorkerWatchdog, type WorkerWatchdog } from './worker-watchdog';

const IDLE_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 5_000;
// 30s pulse vs the 5-minute stuck-recovery threshold: a few missed pulses
// (slow Supabase, a blocking synchronous step) no longer trip false recovery.
const HEARTBEAT_INTERVAL_MS = 30_000;

const MACHINE_ID = process.env.FLY_MACHINE_ID || `local-${process.pid}`;

// Stall watchdog (started in runWorker). Module-scoped so processJob /
// processExtractionJob can mark progress on every successful heartbeat without
// threading it through every call. Null in CLI / test paths that never run the
// worker loop.
let watchdog: WorkerWatchdog | null = null;

function getSupabase(): Storage {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key) as unknown as Storage;
}

async function processExtractionJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  const payload = job.payload as {
    repo_full_name: string;
    installation_id: string;
    default_branch: string;
    branch?: string;
    commit_sha?: string;
    package_json_path?: string;
    ecosystem?: string;
    provider?: string;
    integration_id?: string;
  };

  // onProgress feeds the watchdog's pipeline-progress signal: every log line
  // means the extraction just moved a step, which a frozen-but-alive hang
  // (event loop alive, pipeline stuck on a never-resolving await) would stop
  // emitting — the bare liveness heartbeat can't catch that.
  const logger = new ExtractionLogger(supabase, job.project_id, job.run_id, {
    onProgress: () => watchdog?.markProgress(),
  });

  await logger.info('cloning', 'Extraction started');

  let lastCancelledKnown = false;

  await runPipeline(
    {
      projectId: job.project_id,
      organizationId: job.organization_id,
      repo_full_name: payload.repo_full_name,
      installation_id: payload.installation_id,
      default_branch: payload.default_branch,
      branch: payload.branch,
      commit_sha: payload.commit_sha,
      package_json_path: payload.package_json_path,
      ecosystem: payload.ecosystem,
      provider: payload.provider,
      integration_id: payload.integration_id,
      jobId: job.id,
    },
    logger,
    async () => {
      lastCancelledKnown = await isJobCancelled(supabase, job.id, lastCancelledKnown);
      return lastCancelledKnown;
    },
    async () => { await sendHeartbeat(supabase, job.id, MACHINE_ID, job.run_id); watchdog?.markProgress(); }
  );

  if (await isJobCancelled(supabase, job.id, lastCancelledKnown)) {
    await logger.warn('complete', 'Extraction cancelled by user');
    // Guarded write: only flip to failed if THIS machine+run still owns the
    // job. A 0-row result means it was already cancelled/recovered out from
    // under us — do not overwrite a finalized row.
    const claimed = await updateJobStatus(supabase, job.id, MACHINE_ID, job.run_id, 'failed', 'Cancelled by user');
    if (!claimed) {
      console.warn(`[ext-${job.id}] Claim revoked before cancel finalize — not overwriting`);
    }
  } else {
    await logger.success('complete', 'Extraction complete');
    const claimed = await updateJobStatus(supabase, job.id, MACHINE_ID, job.run_id, 'completed');
    if (!claimed) {
      // Job was cancelled or recovered (run_id rotated) mid-flight; the
      // successful run no longer owns the row. Do NOT clobber it to failed.
      console.warn(`[ext-${job.id}] Claim revoked before completion finalize — not overwriting`);
    }
  }
}

async function processDastJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  // The pipeline owns its own scan_jobs UPDATE on success (status='completed',
  // findings_count, duration_seconds, completed_at). On thrown error the
  // outer processJob catch flips status='failed'.
  await runDastPipeline(job, supabase);
}

async function processJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  const isDast = job.type === 'dast' || job.type === 'dast_zap' || job.type === 'dast_nuclei' || job.type === 'dast_zap_dry_run';
  const tag = isDast ? `[dast-${job.id}]` : `[ext-${job.id}]`;
  console.log(`${tag} Dispatching ${job.type} job for project ${job.project_id}`);
  const jobStartedAt = Date.now();

  // Arm the stall watchdog so the worker self-terminates on a stall instead of
  // idling until the backend's external 5-min detector SIGTERMs it. Extraction
  // arms BOTH the liveness signal (event-loop-block / DB-wedge, fed by the
  // heartbeats below) and the pipeline-progress signal (frozen-but-alive, fed by
  // log writes + subprocess pulses). DAST arms liveness only — it doesn't feed
  // the extraction-log progress stream, so the progress signal would false-fire
  // on a legitimately long active scan.
  watchdog?.arm(job.type === 'extraction');
  watchdog?.onSoftStall(async () => {
    // Best-effort: record a clean failure so the user sees "worker stalled"
    // immediately rather than waiting for the external crash detector. Runs
    // under the watchdog's own time cap.
    if (job.type === 'extraction') {
      try {
        const stallLogger = new ExtractionLogger(supabase, job.project_id, job.run_id);
        await stallLogger.error(
          'complete',
          'Extraction failed — the worker stalled and stopped responding. Re-sync from project settings to try again.',
        );
      } catch {
        /* best-effort */
      }
    }
    try {
      await updateJobStatus(
        supabase,
        job.id,
        MACHINE_ID,
        job.run_id,
        'failed',
        'The worker stalled and self-terminated (a scan step stopped responding).',
      );
    } catch {
      /* best-effort */
    }
  });

  // Send one explicit heartbeat right after the claim — the first interval
  // pulse is otherwise HEARTBEAT_INTERVAL_MS away. This is a LIVENESS ping only
  // (it fires on a timer regardless of pipeline movement), so it must NOT mark
  // pipeline progress — otherwise a frozen-but-alive hang would look healthy.
  try {
    await sendHeartbeat(supabase, job.id, MACHINE_ID, job.run_id);
    watchdog?.markLiveness();
  } catch {
    // non-fatal
  }

  // Single shared heartbeat regardless of type. Liveness-only, for the same
  // reason as above. The pipeline-specific code marks real PROGRESS separately
  // (log writes + subprocess pulses at step boundaries).
  const heartbeatInterval = setInterval(async () => {
    try {
      await sendHeartbeat(supabase, job.id, MACHINE_ID, job.run_id);
      watchdog?.markLiveness();
    } catch {
      // non-fatal
    }
  }, HEARTBEAT_INTERVAL_MS);

  try {
    if (job.type === 'extraction') {
      await processExtractionJob(supabase, job);
    } else if (job.type === 'dast' || job.type === 'dast_zap' || job.type === 'dast_nuclei' || job.type === 'dast_zap_dry_run') {
      // All 'dast*' types share one pipeline; runDastPipeline dispatches to the
      // ZAP or Nuclei engine internally based on scan_jobs.type (v2.1c). The
      // 'dast_zap_dry_run' type routes to the Test-login probe branch
      // (v2.1d). Old workers don't advertise this type — claim_scan_job will
      // skip them so a stale worker can't accidentally run a real scan in
      // place of a probe.
      await processDastJob(supabase, job);
    } else {
      const message = `Unsupported scan type: ${job.type}`;
      console.error(`${tag} ${message}`);
      await updateJobStatus(supabase, job.id, MACHINE_ID, job.run_id, 'failed', message);
    }
  } catch (e: any) {
    const message = e.message || 'Unknown error';
    console.error(`${tag} Job failed: ${message}`);
    // A ScanFailedError is an EXPECTED, handled scan outcome (e.g. an
    // unresolvable manifest) — recorded on scan_jobs.error + the admin failures
    // page + surfaced to the user. That's a project error, not a worker bug, so
    // don't page Sentry on it. Unexpected errors (real crashes) still alert.
    if (!(e instanceof ScanFailedError)) {
      Sentry.captureException(e, {
        tags: { component: 'depscanner', job_type: job.type },
        user: { id: job.organization_id },
        contexts: { job: { id: job.id, type: job.type, project_id: job.project_id, attempts: job.attempts } },
      });
    }
    if (job.type === 'extraction') {
      const logger = new ExtractionLogger(supabase, job.project_id, job.run_id);
      await logger.error('complete', `Extraction failed: ${message}`, e);
    }
    const claimed = await updateJobStatus(supabase, job.id, MACHINE_ID, job.run_id, 'failed', message);
    if (!claimed) {
      console.warn(`${tag} Claim revoked before failure finalize — not overwriting`);
    }
  } finally {
    clearInterval(heartbeatInterval);
    // Disarm the watchdog the moment the job settles, so the idle poll loop (up
    // to IDLE_TIMEOUT_MS with no heartbeat by design) is never flagged as a stall.
    watchdog?.disarm();
    watchdog?.onSoftStall(null);
    // Emit worker_minutes meter event for billing. Best-effort: failures
    // are logged + retried inside postScanJobMeterEvent. We don't gate
    // worker completion on the meter event; the reconcile script catches
    // any drops.
    try {
      await postScanJobMeterEvent({
        jobId: job.id,
        orgId: job.organization_id,
        projectId: job.project_id,
        type: job.type,
        startedAtMs: jobStartedAt,
      });
    } catch (err) {
      console.warn(`${tag} meter-event emit failed`, err);
    }
  }
}

async function runWorker(): Promise<void> {
  const supabase = getSupabase();
  // Startup probe: derive supported types ONCE so DAST is gated off cleanly
  // when DAST_CREDENTIAL_KEY is absent. Per plan §Task 7 — silent-anonymous-
  // fallback is the non-negotiable invariant; if the key is missing we want
  // queue backpressure, not per-job hard-fails.
  const supportedTypes = getSupportedJobTypes();
  const dastEnabled = supportedTypes.some((t) => t.startsWith('dast'));
  console.log(
    `[depscanner] Worker starting, machine: ${MACHINE_ID}, supported_types=${supportedTypes.join(',')}${dastEnabled ? '' : ' (DAST disabled — DAST_CREDENTIAL_KEY missing)'}`,
  );

  // Clear any dast-nuclei-* credential dirs orphaned by a hard crash that
  // skipped runNuclei's finally cleanup. Best-effort, never throws.
  sweepStaleDastTmpDirs();

  // Stall watchdog: armed per-job inside processJob. Self-terminates the worker
  // (and so stops the machine) when a job wedges, instead of waiting on the
  // backend's external 5-min stuck detector.
  watchdog = startWorkerWatchdog();

  let lastJobTime = Date.now();

  while (true) {
    try {
      const job = await claimJob(supabase, MACHINE_ID, supportedTypes);

      if (job) {
        lastJobTime = Date.now();
        const isDast = job.type === 'dast' || job.type === 'dast_zap' || job.type === 'dast_nuclei' || job.type === 'dast_zap_dry_run';
        const tag = isDast ? `[dast-${job.id}]` : `[ext-${job.id}]`;
        console.log(`${tag} Claimed for project ${job.project_id} (attempt ${job.attempts})`);

        try {
          await processJob(supabase, job);
          console.log(`${tag} Done`);
        } catch (e: any) {
          console.error(`${tag} Failed: ${e.message}`);
          Sentry.captureException(e, {
            tags: { component: 'depscanner', phase: 'process-escape' },
            user: { id: job.organization_id },
            contexts: { job: { id: job.id, type: job.type } },
          });
        }

        continue;
      }

      if (Date.now() - lastJobTime > IDLE_TIMEOUT_MS) {
        console.log('[depscanner] No jobs for 60s, shutting down');
        process.exit(0);
      }

      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    } catch (e: any) {
      console.error('[depscanner] Worker error:', e.message);
      captureInfraError(e, 'depscanner', { phase: 'claim' });
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }
}

// Flush Sentry then exit. Never let a slow/failing flush block shutdown:
// Sentry.close has its own internal timeout, and we swallow any rejection so
// process.exit always runs even if close() rejects (Fly sends SIGINT on
// scale-to-zero with a 5-min grace, so 2s is comfortably within budget).
async function flushSentryAndExit(code: number): Promise<void> {
  try {
    watchdog?.stop();
  } catch {
    /* never block exit on watchdog teardown */
  }
  try {
    await Sentry.close(2000);
  } catch {
    /* never block exit on flush */
  }
  process.exit(code);
}

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down');
  void flushSentryAndExit(0);
});
process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down');
  void flushSentryAndExit(0);
});

// No global handlers existed before — a stray rejection or uncaught exception
// would crash with no trace (Node's default is to crash on both). Capture to
// Sentry first, then exit non-zero so the machine restarts clean rather than
// limping on in a half-broken/zombie state (restores the prior crash default).
process.on('unhandledRejection', (reason) => {
  console.error('[depscanner] Unhandled rejection:', reason);
  Sentry.captureException(reason, { tags: { component: 'depscanner', kind: 'unhandledRejection' } });
  void flushSentryAndExit(1);
});
process.on('uncaughtException', (err) => {
  console.error('[depscanner] Uncaught exception:', err);
  Sentry.captureException(err, { tags: { component: 'depscanner', kind: 'uncaughtException' } });
  void flushSentryAndExit(1);
});

const memoryWatcher = setInterval(() => {
  const usage = process.memoryUsage();
  const heapUsedMB = Math.round(usage.heapUsed / 1024 / 1024);
  const rssMB = Math.round(usage.rss / 1024 / 1024);
  if (rssMB > 51200) {
    console.warn(`[depscanner] High memory usage: RSS=${rssMB}MB, Heap=${heapUsedMB}MB (>80% of 64GB)`);
  }
}, 30_000);
memoryWatcher.unref();

runWorker().catch((e) => {
  console.error('Fatal:', e);
  Sentry.captureException(e, { tags: { component: 'depscanner', kind: 'fatal' } });
  void flushSentryAndExit(1);
});
