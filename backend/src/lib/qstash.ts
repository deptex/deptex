/**
 * Application-level job publishing.
 *
 * Historically this file spoke directly to QStash. It now routes through the
 * JobQueue abstraction in ./job-queue so the same call sites work under
 * QStash (cloud) and BullMQ (self-host). Public function signatures are
 * unchanged — the 20+ consumers elsewhere in the backend continue to work.
 *
 * See ./job-queue/types.ts for the contract and ./job-queue/index.ts for the
 * backend-selection rules.
 */

import { getJobQueue } from './job-queue';

/**
 * Base URL for the backend API. Destinations MUST have http:// or https://.
 * Normalizes values like "myapp.fly.dev" or "localhost:3001".
 */
function getApiBaseUrl(): string {
  const raw = process.env.API_BASE_URL || process.env.BACKEND_URL || 'http://localhost:3001';
  const trimmed = (raw || '').trim().replace(/\/$/, '');
  if (!trimmed) return 'http://localhost:3001';
  if (/^https?:\/\//i.test(trimmed)) return trimmed;
  if (/^localhost(:\d+)?$/i.test(trimmed) || /^127\.0\.0\.1(:\d+)?$/i.test(trimmed)) {
    return `http://${trimmed}`;
  }
  return `https://${trimmed}`;
}

/**
 * Verify that an inbound worker request is authentic. Accepts either:
 *   - QStash signature via upstash-signature header (cloud mode)
 *   - X-Internal-Api-Key equal to process.env.INTERNAL_API_KEY (self-host)
 * Pass the raw Express headers object and the raw request body string.
 */
export async function verifyJobRequest(
  headers: Record<string, string | string[] | undefined>,
  rawBody: string,
): Promise<boolean> {
  return getJobQueue().verifyRequest(headers, rawBody);
}

/**
 * @deprecated Prefer verifyJobRequest — it also accepts X-Internal-Api-Key for self-host.
 * Back-compat shim for legacy call sites that only had the QStash signature at hand.
 */
export async function verifyQStashSignature(
  signature: string,
  body: string,
): Promise<boolean> {
  return getJobQueue().verifyRequest({ 'upstash-signature': signature }, body);
}

/** True if the selected job backend is fully configured. */
export function isQStashConfigured(): boolean {
  return getJobQueue().isConfigured();
}

/**
 * Queue a single dependency-analysis job.
 */
export async function queueDependencyAnalysis(
  dependencyId: string,
  name: string,
  version: string,
): Promise<{ messageId: string } | null> {
  const url = `${getApiBaseUrl().replace(/\/$/, '')}/api/workers/analyze-dependency`;
  return getJobQueue().publish(
    url,
    { dependencyId, name, version },
    { retries: 3 },
  );
}

/**
 * Queue a batch of analyze-dependency jobs, grouped into messages of up to 20.
 * Uses a single flow-control key so batches run serially.
 */
export async function queueDependencyAnalysisBatch(
  dependencies: Array<{ dependencyId: string; name: string; version: string }>,
): Promise<{ queued: number; failed: number; messages: number }> {
  if (dependencies.length === 0) return { queued: 0, failed: 0, messages: 0 };
  const url = `${getApiBaseUrl().replace(/\/$/, '')}/api/workers/analyze-dependencies`;

  const BATCH_SIZE = 20;
  const batches: Array<Array<{ dependencyId: string; name: string; version: string }>> = [];
  for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
    batches.push(dependencies.slice(i, i + BATCH_SIZE));
  }

  const messages = batches.map((batch, index) => ({
    url,
    body: { dependencies: batch },
    opts: {
      delayMs: index * 30_000,
      flowControlKey: 'deptex-analyze-dependencies',
      retries: 5,
    },
  }));

  const results = await getJobQueue().publishBatch(messages);

  let queued = 0;
  let failed = 0;
  let messagesQueued = 0;
  results.forEach((r, i) => {
    if (r?.messageId) {
      messagesQueued++;
      queued += batches[i].length;
    } else {
      failed += batches[i].length;
    }
  });

  console.log(`Queued ${queued} dependencies in ${messagesQueued} messages`);
  return { queued, failed, messages: messagesQueued };
}

/**
 * Queue a batch of populate-dependency jobs (per-ecosystem flow control).
 * Each job populates a new dependency: registry info, version rows, GHSA,
 * OpenSSF, reputation score.
 */
export async function queuePopulateDependencyBatch(
  dependencies: Array<{ dependencyId: string; name: string; ecosystem?: string }>,
  projectId?: string,
  organizationId?: string,
): Promise<{ queued: number; failed: number; messages: number }> {
  if (dependencies.length === 0) return { queued: 0, failed: 0, messages: 0 };
  const url = `${getApiBaseUrl().replace(/\/$/, '')}/api/workers/populate-dependencies`;

  const byEcosystem = new Map<string, Array<{ dependencyId: string; name: string; ecosystem?: string }>>();
  for (const dep of dependencies) {
    const eco = dep.ecosystem || 'npm';
    if (!byEcosystem.has(eco)) byEcosystem.set(eco, []);
    byEcosystem.get(eco)!.push(dep);
  }

  const BATCH_SIZE = 10;
  const messages: Array<{ url: string; body: unknown; opts: { delayMs: number; flowControlKey: string; retries: number } }> = [];
  const batchSizes: number[] = [];

  for (const [ecosystem, deps] of byEcosystem) {
    const flowKey = `deptex-${ecosystem}-jobs`;
    for (let i = 0; i < deps.length; i += BATCH_SIZE) {
      const batch = deps.slice(i, i + BATCH_SIZE);
      const batchIndex = messages.length;
      messages.push({
        url,
        body: {
          dependencies: batch,
          ecosystem,
          ...(projectId && { projectId }),
          ...(organizationId && { organizationId }),
        },
        opts: {
          delayMs: batchIndex * 30_000,
          flowControlKey: flowKey,
          retries: 5,
        },
      });
      batchSizes.push(batch.length);
    }
  }

  const results = await getJobQueue().publishBatch(messages);

  let queued = 0;
  let failed = 0;
  let messagesQueued = 0;
  results.forEach((r, i) => {
    if (r?.messageId) {
      messagesQueued++;
      queued += batchSizes[i] ?? 0;
    } else {
      failed += batchSizes[i] ?? 0;
    }
  });

  console.log(`Queued ${queued} dependencies for population in ${messagesQueued} messages`);
  return { queued, failed, messages: messagesQueued };
}

/**
 * Queue a backfill job to populate transitive dependency edges.
 * Uses the same npm flow-control key so npm jobs never run concurrently.
 */
export async function queueBackfillDependencyTrees(
  dependencyId: string,
  name: string,
): Promise<{ messageId: string } | null> {
  const url = `${getApiBaseUrl().replace(/\/$/, '')}/api/workers/backfill-dependency-trees`;
  return getJobQueue().publish(
    url,
    { dependencyId, name },
    { flowControlKey: 'deptex-npm-jobs', retries: 5 },
  );
}
