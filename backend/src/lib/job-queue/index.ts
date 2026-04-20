/**
 * Job queue factory. Resolves JOB_QUEUE_BACKEND to an adapter:
 *
 *   explicit:  JOB_QUEUE_BACKEND=qstash | bullmq | noop
 *   auto:      QSTASH_TOKEN set         -> qstash
 *              REDIS_URL set            -> bullmq
 *              otherwise                 -> noop (warns + drops jobs)
 *
 * Lazy — resolved on first call so dotenv has loaded.
 */

import type { JobQueue } from './types';
import { qstashAdapter } from './qstash-adapter';
import { bullmqAdapter } from './bullmq-adapter';
import { noopAdapter } from './noop-adapter';

export type { JobQueue, PublishMessage, PublishOpts, PublishResult } from './types';
export { shutdownBullMQ } from './bullmq-adapter';

let cached: JobQueue | null = null;

export function getJobQueue(): JobQueue {
  if (cached) return cached;
  const explicit = (process.env.JOB_QUEUE_BACKEND || '').toLowerCase().trim();
  if (explicit === 'qstash') cached = qstashAdapter;
  else if (explicit === 'bullmq') cached = bullmqAdapter;
  else if (explicit === 'noop') cached = noopAdapter;
  else if (qstashAdapter.isConfigured()) cached = qstashAdapter;
  else if (bullmqAdapter.isConfigured()) cached = bullmqAdapter;
  else cached = noopAdapter;
  console.log(`[job-queue] backend = ${cached.name}`);
  return cached;
}

/** Reset the cached backend. Test-only. */
export function resetJobQueueForTests() {
  cached = null;
}
