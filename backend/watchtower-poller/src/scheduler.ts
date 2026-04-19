import { Redis } from '@upstash/redis';

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

if (!redisUrl || !redisToken) {
  throw new Error('UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN must be set');
}

const redis = new Redis({
  url: redisUrl,
  token: redisToken,
});

// Queue for the single "Daily poll" job (delayed job; when due = run dependency refresh + poll watched_packages)
const DAILY_POLL_QUEUE_NAME = process.env.WATCHTOWER_DAILY_POLL_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'watchtower-daily-poll' : 'watchtower-daily-poll-local');

const DAILY_POLL_MEMBER = 'daily_poll';
export const TWENTY_FOUR_HOURS_MS = 24 * 60 * 60 * 1000;

export interface DailyPollJob {
  type: 'daily_poll';
}

/**
 * Schedule the "Daily poll" job to run at runAt (Unix ms).
 * There is only one such job; scheduling again overwrites the run time.
 */
export async function scheduleDailyPollJob(runAt: number): Promise<void> {
  await redis.zadd(DAILY_POLL_QUEUE_NAME, { score: runAt, member: DAILY_POLL_MEMBER });
  console.log(`[${new Date().toISOString()}] 📅 Daily poll job scheduled for ${new Date(runAt).toISOString()}`);
}

/**
 * Get due "Daily poll" job if any (score <= now). Claims it by removing from queue.
 */
export async function getDueDailyPollJob(): Promise<DailyPollJob | null> {
  const now = Date.now();
  const raw = await redis.zrange(DAILY_POLL_QUEUE_NAME, 0, now, { byScore: true });
  if (!raw || raw.length === 0) return null;
  await redis.zrem(DAILY_POLL_QUEUE_NAME, DAILY_POLL_MEMBER);
  return { type: 'daily_poll' };
}

/**
 * True if a Daily poll job is already in the queue (any runAt).
 */
export async function hasDailyPollScheduled(): Promise<boolean> {
  const count = await redis.zcard(DAILY_POLL_QUEUE_NAME);
  return count > 0;
}

/**
 * Next run time (Unix ms) for the Daily poll job, or null if none scheduled.
 * Handles both flat [member, score] and nested [[member, score]] from Upstash zrange.
 */
export async function getNextDailyPollRunAt(): Promise<number | null> {
  const withScores = await redis.zrange(DAILY_POLL_QUEUE_NAME, 0, 0, { withScores: true });
  if (!withScores || withScores.length === 0) return null;
  const first = withScores[0];
  const scoreRaw = Array.isArray(first) ? first[1] : withScores[1];
  if (scoreRaw === undefined) return null;
  const ms = typeof scoreRaw === 'number' ? scoreRaw : Number(scoreRaw);
  return Number.isFinite(ms) ? ms : null;
}

// Legacy (kept for seed-queue / any external refs; main worker uses Daily poll only)
const POLL_QUEUE_NAME = process.env.WATCHTOWER_POLL_QUEUE_NAME || 
  (process.env.NODE_ENV === 'production' ? 'watchtower-poll-schedule' : 'watchtower-poll-schedule-local');

export interface PollJob {
  watchedPackageId: string;
  packageName: string;
  githubUrl: string;
}

/**
 * Add a poll job to the sorted set queue
 * @param job The job to add
 * @param runAt Unix timestamp (ms) when the job should run
 */
export async function schedulePollJob(job: PollJob, runAt: number): Promise<void> {
  const jobJson = JSON.stringify(job);
  await redis.zadd(POLL_QUEUE_NAME, { score: runAt, member: jobJson });
  console.log(`[${new Date().toISOString()}] 📅 Scheduled poll job for ${job.packageName} at ${new Date(runAt).toISOString()}`);
}

/**
 * Schedule a poll job to run immediately
 */
export async function schedulePollJobNow(job: PollJob): Promise<void> {
  await schedulePollJob(job, Date.now());
}

/**
 * Reschedule a poll job for the next day (24 hours from now)
 */
export async function reschedulePollJobForTomorrow(job: PollJob): Promise<void> {
  const tomorrow = Date.now() + 24 * 60 * 60 * 1000;
  await schedulePollJob(job, tomorrow);
}

/**
 * Get all poll jobs that are due (score <= now)
 * Uses ZRANGEBYSCORE to get jobs with score between 0 and current time
 * Then removes them from the queue with ZREM
 */
export async function getDuePollJobs(): Promise<PollJob[]> {
  const now = Date.now();
  
  // Get all jobs with score <= now
  const jobsRaw = await redis.zrange(POLL_QUEUE_NAME, 0, now, { byScore: true });
  
  if (!jobsRaw || jobsRaw.length === 0) {
    return [];
  }

  const jobs: PollJob[] = [];
  
  for (const jobData of jobsRaw) {
    try {
      // Remove the job from the queue first (atomic claim)
      const removed = await redis.zrem(POLL_QUEUE_NAME, jobData);
      
      if (removed > 0) {
        // Successfully claimed the job
        const job = typeof jobData === 'string' ? JSON.parse(jobData) : jobData;
        jobs.push(job as PollJob);
      }
    } catch (error) {
      console.error(`Failed to parse/claim poll job:`, error);
    }
  }

  return jobs;
}

/**
 * Get the count of pending poll jobs in the queue
 */
export async function getPendingJobCount(): Promise<number> {
  return await redis.zcard(POLL_QUEUE_NAME);
}

/**
 * Get the count of due poll jobs (ready to run now)
 */
export async function getDueJobCount(): Promise<number> {
  const now = Date.now();
  return await redis.zcount(POLL_QUEUE_NAME, 0, now);
}

/**
 * Check if a package already has a scheduled poll job
 */
export async function hasScheduledJob(watchedPackageId: string): Promise<boolean> {
  // Get all jobs and check if any match the package ID
  // This is not the most efficient but works for reasonable queue sizes
  const allJobs = await redis.zrange(POLL_QUEUE_NAME, 0, -1);
  
  for (const jobData of allJobs) {
    try {
      const job = typeof jobData === 'string' ? JSON.parse(jobData) : jobData;
      if (job.watchedPackageId === watchedPackageId) {
        return true;
      }
    } catch {
      // Skip malformed jobs
    }
  }
  
  return false;
}

/**
 * Remove all scheduled jobs for a package (e.g., when it's no longer being watched)
 */
export async function removeScheduledJobs(watchedPackageId: string): Promise<number> {
  const allJobs = await redis.zrange(POLL_QUEUE_NAME, 0, -1);
  let removed = 0;
  
  for (const jobData of allJobs) {
    try {
      const job = typeof jobData === 'string' ? JSON.parse(jobData) : jobData;
      if (job.watchedPackageId === watchedPackageId) {
        await redis.zrem(POLL_QUEUE_NAME, jobData);
        removed++;
      }
    } catch {
      // Skip malformed jobs
    }
  }
  
  return removed;
}

/**
 * Test Redis connection
 */
export async function testRedisConnection(): Promise<boolean> {
  try {
    console.log(`[${new Date().toISOString()}] 🔌 Testing Redis connection...`);
    const pingResult = await redis.ping();
    console.log(`[${new Date().toISOString()}] ✅ Redis connection successful (ping: ${pingResult})`);
    const next = await getNextDailyPollRunAt();
    if (next != null && Number.isFinite(next)) {
      console.log(`[${new Date().toISOString()}] 📊 Daily poll queue: next run ${new Date(next).toISOString()}`);
    } else {
      console.log(`[${new Date().toISOString()}] 📊 Daily poll queue: no job (worker will schedule one)`);
    }
    return true;
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Redis connection failed:`, error.message);
    return false;
  }
}

/**
 * Redis key for last Job 1 (dependency refresh) run timestamp (ms).
 * Scoped by queue name so local/prod don't share.
 */
const LAST_DEPENDENCY_REFRESH_KEY = `watchtower-poller:last-dependency-refresh:${DAILY_POLL_QUEUE_NAME}`;

/**
 * Get last time Job 1 (dependency refresh) ran (Unix ms). Returns 0 if never.
 */
export async function getLastDependencyRefreshAt(): Promise<number> {
  const val = await redis.get(LAST_DEPENDENCY_REFRESH_KEY);
  if (val == null) return 0;
  const n = Number(val);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Set last time Job 1 (dependency refresh) ran (Unix ms).
 */
export async function setLastDependencyRefreshAt(ts: number): Promise<void> {
  await redis.set(LAST_DEPENDENCY_REFRESH_KEY, String(ts));
}

/**
 * Queue for auto-bump "new version" and "quarantine expired" jobs (consumed by worker).
 */
const NEW_VERSION_QUEUE_NAME = process.env.WATCHTOWER_NEW_VERSION_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'watchtower-new-version-jobs' : 'watchtower-new-version-jobs-local');

export interface NewVersionJob {
  type: 'new_version' | 'quarantine_expired';
  dependency_id: string;
  name: string;
  new_version?: string;
  latest_release_date?: string | null;
}

/**
 * Enqueue a new-version or quarantine-expired job for the auto-bump worker.
 */
export async function enqueueNewVersionJob(job: NewVersionJob): Promise<void> {
  const jobJson = JSON.stringify(job);
  await redis.rpush(NEW_VERSION_QUEUE_NAME, jobJson);
  console.log(`[${new Date().toISOString()}] 📤 Enqueued ${job.type} job for ${job.name}`);
}

export { POLL_QUEUE_NAME, NEW_VERSION_QUEUE_NAME };
