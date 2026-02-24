import { Receiver } from '@upstash/qstash';

// NOTE: Environment variables are read lazily (inside functions) to ensure
// dotenv.config() has been called before we access them.

// Region-based config: set QSTASH_REGION (e.g. US_EAST_1 or EU_CENTRAL_1) and the
// corresponding {REGION}_QSTASH_* vars. Otherwise legacy QSTASH_TOKEN / QSTASH_*_SIGNING_KEY apply.

function getQStashRegionPrefix(): string | null {
  const region = process.env.QSTASH_REGION;
  if (!region) return null;
  return `${region}_`;
}

function getQStashToken(): string | undefined {
  const prefix = getQStashRegionPrefix();
  if (prefix) {
    const token = process.env[`${prefix}QSTASH_TOKEN`];
    if (token) return token;
  }
  return process.env.QSTASH_TOKEN;
}

function getQStashBaseUrl(): string {
  const prefix = getQStashRegionPrefix();
  if (prefix) {
    const url = process.env[`${prefix}QSTASH_URL`];
    if (url) return url.replace(/\/$/, ''); // trim trailing slash
  }
  return 'https://qstash.upstash.io';
}

function getQStashSigningKeys(): { current: string; next: string } | null {
  const prefix = getQStashRegionPrefix();
  const currentKey = prefix
    ? process.env[`${prefix}QSTASH_CURRENT_SIGNING_KEY`]
    : process.env.QSTASH_CURRENT_SIGNING_KEY;
  const nextKey = prefix
    ? process.env[`${prefix}QSTASH_NEXT_SIGNING_KEY`]
    : process.env.QSTASH_NEXT_SIGNING_KEY;
  if (currentKey && nextKey) return { current: currentKey, next: nextKey };
  return null;
}

// Cached receiver instance
let receiver: Receiver | null = null;
let receiverInitialized = false;

function getReceiver(): Receiver | null {
  if (!receiverInitialized) {
    const keys = getQStashSigningKeys();
    if (keys) {
      receiver = new Receiver({
        currentSigningKey: keys.current,
        nextSigningKey: keys.next,
      });
    }
    receiverInitialized = true;
  }
  return receiver;
}

function getApiBaseUrl(): string {
  // Check both possible env var names
  return process.env.API_BASE_URL || process.env.BACKEND_URL || 'http://localhost:3001';
}

/**
 * Verify that a request came from QStash
 */
export async function verifyQStashSignature(
  signature: string,
  body: string
): Promise<boolean> {
  const recv = getReceiver();
  if (!recv) {
    // If no signing keys configured, allow requests (dev mode)
    console.warn('QStash signing keys not configured - skipping signature verification');
    return true;
  }

  try {
    await recv.verify({
      signature,
      body,
    });
    return true;
  } catch (error) {
    console.error('QStash signature verification failed:', error);
    return false;
  }
}

/**
 * Queue a dependency analysis job via QStash
 * Uses QStash's built-in rate limiting with parallelism
 */
export async function queueDependencyAnalysis(
  dependencyId: string,
  name: string,
  version: string
): Promise<{ messageId: string } | null> {
  const token = getQStashToken();
  if (!token) {
    console.warn('QSTASH_TOKEN not configured - skipping queue');
    return null;
  }

  const url = `${getApiBaseUrl()}/api/workers/analyze-dependency`;
  
  const baseUrl = getQStashBaseUrl();
  try {
    const response = await fetch(`${baseUrl}/v2/publish/` + encodeURIComponent(url), {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Upstash-Method': 'POST',
        // Rate limiting: max 10 concurrent requests
        'Upstash-Delay': '0s',
        'Upstash-Retries': '3',
        'Upstash-Forward-Content-Type': 'application/json',
      },
      body: JSON.stringify({
        dependencyId,
        name,
        version,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('QStash publish failed:', response.status, errorText);
      return null;
    }

    const result = (await response.json()) as { messageId?: string };
    return result.messageId ? { messageId: result.messageId } : null;
  } catch (error) {
    console.error('Failed to queue dependency analysis:', error);
    return null;
  }
}

/**
 * Queue dependency analysis jobs in grouped batches
 * Groups packages together to reduce message count (important for free tier: 500 msgs/day)
 */
export async function queueDependencyAnalysisBatch(
  dependencies: Array<{ dependencyId: string; name: string; version: string }>
): Promise<{ queued: number; failed: number; messages: number }> {
  const token = getQStashToken();
  const apiBaseUrl = getApiBaseUrl();

  if (!token) {
    console.warn('QSTASH_TOKEN not configured - skipping batch queue');
    return { queued: 0, failed: dependencies.length, messages: 0 };
  }

  const url = `${apiBaseUrl}/api/workers/analyze-dependencies`;
  
  // Group dependencies into batches of 20 to reduce message count
  const BATCH_SIZE = 20;
  const batches: Array<Array<{ dependencyId: string; name: string; version: string }>> = [];
  
  for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
    batches.push(dependencies.slice(i, i + BATCH_SIZE));
  }

  // Create one message per batch with staggered delays and flow control
  // Upstash-Flow-Control-Key + parallelism=1: at most 1 delivery to this endpoint at a time (per key)
  // So even if multiple projects queue at once, QStash delivers one batch, waits for response, then the next
  // Upstash-Retries: on 503 (busy) or 500, QStash will retry; we cap at 5 so retries are bounded
  const FLOW_CONTROL_KEY = 'deptex-analyze-dependencies';
  const messages = batches.map((batch, index) => ({
    destination: url,
    headers: {
      'Content-Type': 'application/json',
      'Upstash-Delay': `${index * 30}s`, // 0s, 30s, 60s, 90s, etc.
      'Upstash-Flow-Control-Key': FLOW_CONTROL_KEY,
      'Upstash-Flow-Control-Value': 'parallelism=1',
      'Upstash-Retries': '5',
    },
    body: JSON.stringify({
      dependencies: batch,
    }),
  }));

  let queued = 0;
  let failed = 0;
  let messagesQueued = 0;

  const baseUrl = getQStashBaseUrl();
  try {
    const response = await fetch(`${baseUrl}/v2/batch`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(messages),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('QStash batch publish failed:', response.status, errorText);
      return { queued: 0, failed: dependencies.length, messages: 0 };
    }

    const results = await response.json();
    
    // Count successes and failures
    if (Array.isArray(results)) {
      results.forEach((result: any, index: number) => {
        if (result.messageId) {
          messagesQueued++;
          queued += batches[index].length;
        } else {
          failed += batches[index].length;
        }
      });
    } else {
      messagesQueued = messages.length;
      queued = dependencies.length;
    }

    console.log(`Queued ${queued} dependencies in ${messagesQueued} messages`);
    return { queued, failed, messages: messagesQueued };
  } catch (error: any) {
    console.error('Failed to queue dependency analysis batch:', error);
    return { queued: 0, failed: dependencies.length, messages: 0 };
  }
}

/**
 * Queue dependency population jobs in grouped batches
 * Each job populates a new dependency: fetches npm info, creates version rows, GHSA vulns, OpenSSF, calculates reputation score
 * Batch size of 10 (each populate job does more work than the old per-version analysis)
 */
export async function queuePopulateDependencyBatch(
  dependencies: Array<{ dependencyId: string; name: string }>
): Promise<{ queued: number; failed: number; messages: number }> {
  const token = getQStashToken();
  const apiBaseUrl = getApiBaseUrl();

  if (!token) {
    console.warn('QSTASH_TOKEN not configured - skipping populate batch queue');
    return { queued: 0, failed: dependencies.length, messages: 0 };
  }

  const url = `${apiBaseUrl}/api/workers/populate-dependencies`;
  
  // Batch size of 10 (populate does more work per dep: npm + 10 versions + GHSA + OpenSSF)
  const BATCH_SIZE = 10;
  const batches: Array<Array<{ dependencyId: string; name: string }>> = [];
  
  for (let i = 0; i < dependencies.length; i += BATCH_SIZE) {
    batches.push(dependencies.slice(i, i + BATCH_SIZE));
  }

  // Flow control: shared with backfill-dependency-trees so npm jobs never run concurrently
  const FLOW_CONTROL_KEY = 'deptex-npm-jobs';
  const messages = batches.map((batch, index) => ({
    destination: url,
    headers: {
      'Content-Type': 'application/json',
      'Upstash-Delay': `${index * 30}s`,
      'Upstash-Flow-Control-Key': FLOW_CONTROL_KEY,
      'Upstash-Flow-Control-Value': 'parallelism=1',
      'Upstash-Retries': '5',
    },
    body: JSON.stringify({
      dependencies: batch,
    }),
  }));

  let queued = 0;
  let failed = 0;
  let messagesQueued = 0;

  const baseUrl = getQStashBaseUrl();
  try {
    const response = await fetch(`${baseUrl}/v2/batch`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(messages),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('QStash populate batch publish failed:', response.status, errorText);
      return { queued: 0, failed: dependencies.length, messages: 0 };
    }

    const results = await response.json();
    
    if (Array.isArray(results)) {
      results.forEach((result: any, index: number) => {
        if (result.messageId) {
          messagesQueued++;
          queued += batches[index].length;
        } else {
          failed += batches[index].length;
        }
      });
    } else {
      messagesQueued = messages.length;
      queued = dependencies.length;
    }

    console.log(`Queued ${queued} dependencies for population in ${messagesQueued} messages`);
    return { queued, failed, messages: messagesQueued };
  } catch (error: any) {
    console.error('Failed to queue dependency population batch:', error);
    return { queued: 0, failed: dependencies.length, messages: 0 };
  }
}

/**
 * Queue a backfill job to populate transitive dependency edges for a dependency.
 * Uses same flow key as populate so npm jobs never run concurrently.
 */
export async function queueBackfillDependencyTrees(
  dependencyId: string,
  name: string
): Promise<{ messageId: string } | null> {
  const token = getQStashToken();
  if (!token) {
    console.warn('QSTASH_TOKEN not configured - skipping backfill queue');
    return null;
  }

  const url = `${getApiBaseUrl()}/api/workers/backfill-dependency-trees`;
  const baseUrl = getQStashBaseUrl();

  try {
    const response = await fetch(`${baseUrl}/v2/publish/` + encodeURIComponent(url), {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Upstash-Method': 'POST',
        'Upstash-Delay': '0s',
        'Upstash-Flow-Control-Key': 'deptex-npm-jobs',
        'Upstash-Flow-Control-Value': 'parallelism=1',
        'Upstash-Retries': '5',
        'Upstash-Forward-Content-Type': 'application/json',
      },
      body: JSON.stringify({
        dependencyId,
        name,
      }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('QStash backfill publish failed:', response.status, errorText);
      return null;
    }

    const result = (await response.json()) as { messageId?: string };
    return result.messageId ? { messageId: result.messageId } : null;
  } catch (error) {
    console.error('Failed to queue backfill dependency trees:', error);
    return null;
  }
}

/**
 * Check if QStash is configured
 */
export function isQStashConfigured(): boolean {
  return !!getQStashToken();
}
