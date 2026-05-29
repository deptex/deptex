/**
 * BullMQ implementation of JobQueue for self-hosted deploys.
 *
 * Design:
 *   - One BullMQ Queue per flow-control key. Queue with concurrency=1 gives
 *     us "parallelism=1 per key" (QStash equivalent). Jobs without a
 *     flow-control key land in the shared "deptex-default" queue.
 *   - The worker processor performs fetch POST to the destination URL with
 *     an X-Internal-Api-Key header. Route handlers in backend/src/routes/
 *     already accept this header as an alternative to the QStash signature.
 *
 * Enable with JOB_QUEUE_BACKEND=bullmq and REDIS_URL=redis://localhost:6379.
 *
 * BullMQ and ioredis are loaded lazily so deploys without self-hosting never
 * pay the dependency cost (e.g., Vercel cold-start on the cloud backend).
 */

import type {
  JobQueue,
  PublishMessage,
  PublishOpts,
  PublishResult,
} from './types';
import { isValidInternalKey } from '../../middleware/internal-key';

const DEFAULT_QUEUE = 'deptex-default';
const QUEUE_PREFIX = 'deptex-fc-';

let initialized = false;
const queues = new Map<string, any>();
const workers = new Map<string, any>();
let connectionConfig: { connection: any } | null = null;

type BullMQ = typeof import('bullmq');
let bullmq: BullMQ | null = null;

async function getBullMQ(): Promise<BullMQ> {
  if (bullmq) return bullmq;
  // Lazy import so the cloud build doesn't bundle it.
  bullmq = await import('bullmq');
  return bullmq;
}

async function getConnection() {
  if (connectionConfig) return connectionConfig;
  const url = process.env.REDIS_URL;
  if (!url) throw new Error('REDIS_URL is required when JOB_QUEUE_BACKEND=bullmq');
  // ioredis is a peer dep of bullmq and must be importable.
  const IORedis = (await import('ioredis')).default;
  const connection = new IORedis(url, {
    maxRetriesPerRequest: null, // required by BullMQ
  });
  connectionConfig = { connection };
  return connectionConfig;
}

function queueNameFor(flowControlKey?: string): string {
  if (!flowControlKey) return DEFAULT_QUEUE;
  // Flow-control key may contain characters BullMQ dislikes in Redis keys; normalize.
  return QUEUE_PREFIX + flowControlKey.replace(/[^a-zA-Z0-9_\-]/g, '_');
}

async function getQueue(name: string) {
  let q = queues.get(name);
  if (q) return q;
  const { Queue } = await getBullMQ();
  const conn = await getConnection();
  q = new Queue(name, conn);
  queues.set(name, q);
  await ensureWorker(name);
  return q;
}

async function processJob(job: { data: { url: string; body: unknown } }): Promise<void> {
  const key = process.env.INTERNAL_API_KEY;
  if (!key) {
    throw new Error('INTERNAL_API_KEY is required for self-hosted job processing');
  }
  const res = await fetch(job.data.url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Internal-Api-Key': key,
    },
    body: JSON.stringify(job.data.body ?? {}),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`job POST ${job.data.url} failed ${res.status}: ${text.slice(0, 500)}`);
  }
}

async function ensureWorker(name: string) {
  if (workers.has(name)) return;
  // Workers run in-process by default (single-process self-host). Set
  // DEPTEX_SKIP_WORKERS=1 on the API process if you want to run a dedicated
  // worker node separately.
  if (process.env.DEPTEX_SKIP_WORKERS === '1') return;
  const { Worker } = await getBullMQ();
  const conn = await getConnection();
  const concurrency = name === DEFAULT_QUEUE ? 5 : 1; // flow-control queues serialize
  const worker = new Worker(name, processJob, { ...conn, concurrency });
  worker.on('failed', (job: any, err: Error) => {
    console.error(`[job-queue:bullmq] job ${job?.id} on ${name} failed:`, err.message);
  });
  workers.set(name, worker);
}

function optsToBullMQ(opts: PublishOpts | undefined) {
  const out: any = {};
  if (opts?.delayMs) out.delay = opts.delayMs;
  if (opts?.retries !== undefined) out.attempts = Math.max(1, opts.retries + 1);
  // Exponential backoff starting at 10s — roughly mirrors QStash defaults.
  if (opts?.retries) out.backoff = { type: 'exponential', delay: 10_000 };
  return out;
}

export const bullmqAdapter: JobQueue = {
  name: 'bullmq',

  isConfigured() {
    return !!process.env.REDIS_URL;
  },

  async publish(url, body, opts) {
    try {
      if (!initialized) initialized = true;
      const queue = await getQueue(queueNameFor(opts?.flowControlKey));
      const job = await queue.add('deliver', { url, body }, optsToBullMQ(opts));
      return { messageId: String(job.id) };
    } catch (e) {
      console.error('[job-queue:bullmq] publish error', e);
      return null;
    }
  },

  async publishBatch(messages: PublishMessage[]): Promise<Array<PublishResult | null>> {
    const results: Array<PublishResult | null> = new Array(messages.length).fill(null);
    // Group by queue so we can use addBulk where possible.
    const groups = new Map<string, Array<{ idx: number; m: PublishMessage }>>();
    for (let i = 0; i < messages.length; i++) {
      const m = messages[i];
      const qn = queueNameFor(m.opts?.flowControlKey);
      if (!groups.has(qn)) groups.set(qn, []);
      groups.get(qn)!.push({ idx: i, m });
    }
    for (const [qn, entries] of groups) {
      try {
        const queue = await getQueue(qn);
        const bulk = entries.map((e) => ({
          name: 'deliver',
          data: { url: e.m.url, body: e.m.body },
          opts: optsToBullMQ(e.m.opts),
        }));
        const added = await queue.addBulk(bulk);
        for (let i = 0; i < added.length; i++) {
          results[entries[i].idx] = { messageId: String(added[i].id) };
        }
      } catch (e) {
        console.error(`[job-queue:bullmq] batch error on queue ${qn}`, e);
        // leave those slots null
      }
    }
    return results;
  },

  async verifyRequest(headers) {
    if (!process.env.INTERNAL_API_KEY) {
      console.error('[job-queue:bullmq] INTERNAL_API_KEY not set — rejecting all job requests');
      return false;
    }
    const presented = headers['x-internal-api-key'];
    const presentedStr = Array.isArray(presented) ? presented[0] : presented;
    return isValidInternalKey(presentedStr);
  },
};

/** Close all queues/workers. Exposed for graceful shutdown + tests. */
export async function shutdownBullMQ(): Promise<void> {
  for (const w of workers.values()) await w.close().catch(() => {});
  for (const q of queues.values()) await q.close().catch(() => {});
  workers.clear();
  queues.clear();
  if (connectionConfig?.connection) {
    await connectionConfig.connection.quit().catch(() => {});
  }
  connectionConfig = null;
}
