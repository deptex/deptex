import 'dotenv/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
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

function getSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key);
}

async function processJob(supabase: SupabaseClient, job: ExtractionJobRow): Promise<void> {
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

  const heartbeatInterval = setInterval(async () => {
    try {
      await sendHeartbeat(supabase, job.id);
    } catch {
      // non-fatal
    }
  }, HEARTBEAT_INTERVAL_MS);

  try {
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
      },
      logger,
      async () => isJobCancelled(supabase, job.id)
    );

    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('complete', 'Extraction cancelled by user');
      await updateJobStatus(supabase, job.id, 'failed', 'Cancelled by user');
    } else {
      await logger.success('complete', 'Extraction complete');
      await updateJobStatus(supabase, job.id, 'completed');
    }
  } catch (e: any) {
    const message = e.message || 'Unknown error';
    await logger.error('complete', `Extraction failed: ${message}`, e);
    await updateJobStatus(supabase, job.id, 'failed', message);
  } finally {
    clearInterval(heartbeatInterval);
  }
}

async function runWorker(): Promise<void> {
  const supabase = getSupabase();
  console.log(`[EXTRACT] Worker starting, machine: ${MACHINE_ID}`);

  let lastJobTime = Date.now();

  while (true) {
    try {
      const job = await claimJob(supabase, MACHINE_ID);

      if (job) {
        lastJobTime = Date.now();
        console.log(`[EXTRACT] Claimed job ${job.id} for project ${job.project_id} (attempt ${job.attempts})`);

        try {
          await processJob(supabase, job);
          console.log(`[EXTRACT] Job ${job.id} complete`);
        } catch (e: any) {
          console.error(`[EXTRACT] Job ${job.id} failed:`, e.message);
        }

        continue;
      }

      if (Date.now() - lastJobTime > IDLE_TIMEOUT_MS) {
        console.log('[EXTRACT] No jobs for 60s, shutting down');
        process.exit(0);
      }

      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    } catch (e: any) {
      console.error('[EXTRACT] Worker error:', e.message);
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
    console.warn(`[EXTRACT] High memory usage: RSS=${rssMB}MB, Heap=${heapUsedMB}MB (>80% of 64GB)`);
  }
}, 30_000);
memoryWatcher.unref();

runWorker().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
