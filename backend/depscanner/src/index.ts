import 'dotenv/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import type { Storage } from './storage';
import { runPipeline } from './pipeline';
import { ExtractionLogger } from './logger';
import {
  claimJob,
  updateJobStatus,
  sendHeartbeat,
  isJobCancelled,
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

// PR 2 stub. The real DAST pipeline (ZAP runner + cross-link + route-matcher) lands
// in PR 3 — see `.cursor/plans/dast.plan.md` Tasks 7-10. Stub fails fast so PR 2 can
// validate the claim → dispatch path end-to-end without queueing actual scans.
async function processDastJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  const message = 'DAST pipeline not yet implemented (ships in PR 3)';
  console.warn(`[DAST] ${message} — failing job ${job.id}`);
  await updateJobStatus(supabase, job.id, 'failed', message);
}

async function processJob(supabase: Storage, job: ExtractionJobRow): Promise<void> {
  const tag = job.type === 'dast' ? `[dast-${job.id}]` : `[ext-${job.id}]`;
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
    } else if (job.type === 'dast') {
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
  console.log(`[depscanner] Worker starting, machine: ${MACHINE_ID}`);

  let lastJobTime = Date.now();

  while (true) {
    try {
      const job = await claimJob(supabase, MACHINE_ID);

      if (job) {
        lastJobTime = Date.now();
        const tag = job.type === 'dast' ? `[dast-${job.id}]` : `[ext-${job.id}]`;
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
