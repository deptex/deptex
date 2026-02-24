import { Redis } from '@upstash/redis';

// Redis client for Watchtower job queue
// This handles queueing forensic analysis jobs for watched packages

let redisClient: Redis | null = null;

function getRedisClient(): Redis | null {
  if (!redisClient) {
    const url = process.env.UPSTASH_REDIS_URL;
    const token = process.env.UPSTASH_REDIS_TOKEN;

    if (!url || !token) {
      console.warn('UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN not configured - Watchtower queue disabled');
      return null;
    }

    redisClient = new Redis({
      url,
      token,
    });
  }

  return redisClient;
}

export interface WatchtowerJob {
  packageName: string;
  watchedPackageId: string;
  projectDependencyId: string;
  /** Version the project is using; worker runs integrity checks on this and on latest. */
  currentVersion?: string;
}

// Use different queue name for local development to avoid conflicts with deployed workers
const WATCHTOWER_QUEUE_NAME = process.env.WATCHTOWER_QUEUE_NAME || 
  (process.env.NODE_ENV === 'production' ? 'watchtower-jobs' : 'watchtower-jobs-local');

/**
 * Queue a Watchtower forensic analysis job to Redis
 * This is called when watching is enabled for a dependency
 */
export async function queueWatchtowerJob(job: WatchtowerJob): Promise<{ success: boolean; error?: string }> {
  const client = getRedisClient();
  if (!client) {
    console.warn('Redis not configured - skipping Watchtower job queue');
    return { success: false, error: 'Redis not configured' };
  }

  try {
    // Push job to the end of the queue (FIFO)
    const jobString = JSON.stringify(job);
    await client.rpush(WATCHTOWER_QUEUE_NAME, jobString);
    
    // Verify the job is actually in the queue using llen
    const queueLength = await client.llen(WATCHTOWER_QUEUE_NAME);
    console.log(`[${new Date().toISOString()}] ✅ Queued Watchtower job for ${job.packageName} to queue '${WATCHTOWER_QUEUE_NAME}' (queue length: ${queueLength})`);
    return { success: true };
  } catch (error: any) {
    console.error('Failed to queue Watchtower job:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Check if Watchtower queue is configured
 */
export function isWatchtowerQueueConfigured(): boolean {
  return !!getRedisClient();
}

/**
 * Get the Watchtower queue name (for worker use)
 */
export function getWatchtowerQueueName(): string {
  return WATCHTOWER_QUEUE_NAME;
}
