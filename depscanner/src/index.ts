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

const IDLE_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 60_000;

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
    async () => isJobCancelled(supabase, job.id),
    async () => { await sendHeartbeat(supabase, job.id); }
  );

  if (await isJobCancelled(supabase, job.id)) {
    await logger.warn('complete', 'Extraction cancelled by user');
    await updateJobStatus(supabase, job.id, 'failed', 'Cancelled by user');
  } else {
    await logger.success('complete', 'Extraction complete');
    await updateJobStatus(supabase, job.id, 'completed');
  }
}

async function processDastJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  // The pipeline owns its own scan_jobs UPDATE on success (status='completed',
  // findings_count, duration_seconds, completed_at). On thrown error the
  // outer processJob catch flips status='failed'.
  await runDastPipeline(job, supabase);
}

async function processJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  const isDast = job.type === 'dast' || job.type === 'dast_zap' || job.type === 'dast_nuclei';
  const tag = isDast ? `[dast-${job.id}]` : `[ext-${job.id}]`;
  console.log(`${tag} Dispatching ${job.type} job for project ${job.project_id}`);

  // Single shared heartbeat regardless of type. The pipeline-specific code below
  // also pulses heartbeat at step boundaries inside long-running subprocesses.
  const heartbeatInterval = setInterval(async () => {
    try {
      await sendHeartbeat(supabase, job.id);
    } catch {
      // non-fatal
    }
  }, HEARTBEAT_INTERVAL_MS);

  try {
    if (job.type === 'extraction') {
      await processExtractionJob(supabase, job);
    } else if (job.type === 'dast' || job.type === 'dast_zap' || job.type === 'dast_nuclei') {
      // v2.1a routes all 'dast*' types through the same pipeline. The
      // dast_zap / dast_nuclei split lands in v2.1c (engine column on
      // findings, separate runner dispatchers). For now the worker treats
      // them as aliases of 'dast'.
      await processDastJob(supabase, job);
    } else {
      const message = `Unsupported scan type: ${job.type}`;
      console.error(`${tag} ${message}`);
      await updateJobStatus(supabase, job.id, 'failed', message);
    }
  } catch (e: any) {
    const message = e.message || 'Unknown error';
    console.error(`${tag} Job failed: ${message}`);
    if (job.type === 'extraction') {
      const logger = new ExtractionLogger(supabase, job.project_id, job.run_id);
      await logger.error('complete', `Extraction failed: ${message}`, e);
    }
    await updateJobStatus(supabase, job.id, 'failed', message);
  } finally {
    clearInterval(heartbeatInterval);
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
        const isDast = job.type === 'dast' || job.type === 'dast_zap' || job.type === 'dast_nuclei';
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
