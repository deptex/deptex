import 'dotenv/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Storage } from './storage';
import { runPipeline } from './pipeline';
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

const IDLE_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 5_000;
// 30s pulse vs the 5-minute stuck-recovery threshold: a few missed pulses
// (slow Supabase, a blocking synchronous step) no longer trip false recovery.
const HEARTBEAT_INTERVAL_MS = 30_000;

const MACHINE_ID = process.env.FLY_MACHINE_ID || `local-${process.pid}`;

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
    package_json_path?: string;
    ecosystem?: string;
    provider?: string;
    integration_id?: string;
  };

  const logger = new ExtractionLogger(supabase, job.project_id, job.run_id);

  await logger.info('cloning', 'Extraction started');

  let lastCancelledKnown = false;

  await runPipeline(
    {
      projectId: job.project_id,
      organizationId: job.organization_id,
      repo_full_name: payload.repo_full_name,
      installation_id: payload.installation_id,
      default_branch: payload.default_branch,
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
    async () => { await sendHeartbeat(supabase, job.id, MACHINE_ID, job.run_id); }
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

  // Send one explicit heartbeat right after the claim — the first interval
  // pulse is otherwise HEARTBEAT_INTERVAL_MS away.
  try {
    await sendHeartbeat(supabase, job.id, MACHINE_ID, job.run_id);
  } catch {
    // non-fatal
  }

  // Single shared heartbeat regardless of type. The pipeline-specific code below
  // also pulses heartbeat at step boundaries inside long-running subprocesses.
  const heartbeatInterval = setInterval(async () => {
    try {
      await sendHeartbeat(supabase, job.id, MACHINE_ID, job.run_id);
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
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }
}

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down');
  process.exit(0);
});
process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down');
  process.exit(0);
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
  process.exit(1);
});
