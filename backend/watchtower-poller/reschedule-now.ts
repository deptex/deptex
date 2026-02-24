/**
 * Reschedule all jobs in the watchtower poll queue to run now.
 * Use this when you have jobs scheduled for later (e.g. tomorrow) and want them to run on the next poll.
 *
 * Usage:
 *   cd backend/watchtower-poller
 *   npx tsx reschedule-now.ts
 */

import 'dotenv/config';
import { Redis } from '@upstash/redis';

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

if (!redisUrl || !redisToken) {
  console.error('❌ UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN must be set');
  process.exit(1);
}

const redis = new Redis({ url: redisUrl, token: redisToken });

const POLL_QUEUE_NAME =
  process.env.WATCHTOWER_POLL_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'watchtower-poll-schedule' : 'watchtower-poll-schedule-local');

async function main() {
  console.log('🔄 Rescheduling all poll jobs to run now...');
  console.log(`   Queue: ${POLL_QUEUE_NAME}`);
  console.log('');

  const members = await redis.zrange(POLL_QUEUE_NAME, 0, -1);

  if (members.length === 0) {
    console.log('   Queue is empty. Nothing to reschedule.');
    return;
  }

  const now = Date.now();

  for (const member of members) {
    await redis.zrem(POLL_QUEUE_NAME, member);
    await redis.zadd(POLL_QUEUE_NAME, { score: now, member });
    try {
      const job = typeof member === 'string' ? JSON.parse(member) : member;
      console.log(`   ✓ ${job.packageName ?? job.watchedPackageId}`);
    } catch {
      console.log('   ✓ (1 job)');
    }
  }

  console.log('');
  console.log(`✅ Rescheduled ${members.length} job(s) to run now. The poller will pick them up on its next run.`);
}

main()
  .then(() => process.exit(0))
  .catch((err) => {
    console.error('❌', err);
    process.exit(1);
  });
