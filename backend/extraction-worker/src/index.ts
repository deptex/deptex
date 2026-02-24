import 'dotenv/config';
import { Redis } from '@upstash/redis';
import { runPipeline } from './pipeline';

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

if (!redisUrl || !redisToken) {
  throw new Error('UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN must be set');
}

const redis = new Redis({ url: redisUrl, token: redisToken });
const QUEUE_NAME =
  process.env.EXTRACTION_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'extraction-jobs' : 'extraction-jobs-local');

// Diagnostics: backend and worker must use same Redis + same queue name (check NODE_ENV matches)
console.log(`[EXTRACT] NODE_ENV=${process.env.NODE_ENV ?? '(not set)'} → queue: ${QUEUE_NAME}`);
console.log(`[EXTRACT] Redis URL: ${redisUrl.substring(0, 50)}...`);

interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  package_json_path?: string;
  ecosystem?: string;
}

async function processJob(job: ExtractionJob): Promise<void> {
  await runPipeline(job);
}

async function runWorker(): Promise<void> {
  console.log(`[EXTRACT] Worker starting, queue: ${QUEUE_NAME}`);
  let pollCount = 0;

  while (true) {
    try {
      pollCount++;
      const raw = await redis.lpop(QUEUE_NAME);
      if (raw) {
        let job: ExtractionJob;
        if (typeof raw === 'string') {
          job = JSON.parse(raw) as ExtractionJob;
        } else if (typeof raw === 'object' && raw !== null) {
          job = raw as ExtractionJob;
        } else {
          console.error('[EXTRACT] Unexpected job format');
          continue;
        }
        console.log(`[EXTRACT] Processing job for project ${job.projectId}, repo ${job.repo_full_name}`);
        try {
          await processJob(job);
          console.log(`[EXTRACT] Job complete for project ${job.projectId}`);
        } catch (e: any) {
          console.error(`[EXTRACT] Job failed for project ${job.projectId}:`, e.message);
        }
      } else {
        await new Promise((r) => setTimeout(r, 5000));
      }
    } catch (e: any) {
      console.error('[EXTRACT] Worker error:', e);
      await new Promise((r) => setTimeout(r, 5000));
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

runWorker().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
