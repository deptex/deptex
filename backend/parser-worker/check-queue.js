// Quick script to check Redis queue status
require('dotenv/config');
const { Redis } = require('@upstash/redis');

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

if (!redisUrl || !redisToken) {
  console.error('❌ UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN must be set');
  process.exit(1);
}

const redis = new Redis({
  url: redisUrl,
  token: redisToken,
});

const QUEUE_NAME = 'ast-parsing-jobs';

async function checkQueue() {
  try {
    console.log('🔍 Checking Redis queue...\n');
    
    const queueLength = await redis.llen(QUEUE_NAME);
    console.log(`📊 Queue: ${QUEUE_NAME}`);
    console.log(`📦 Jobs in queue: ${queueLength}\n`);
    
    if (queueLength > 0) {
      console.log('⚠️  WARNING: There are jobs waiting in the queue!');
      console.log('   This means no worker is currently processing them.\n');
      
      // Show first job (without removing it)
      const firstJob = await redis.lindex(QUEUE_NAME, 0);
      if (firstJob) {
        try {
          const job = typeof firstJob === 'string' ? JSON.parse(firstJob) : firstJob;
          console.log('📄 First job in queue:');
          console.log(`   Project ID: ${job.projectId}`);
          console.log(`   Repo: ${job.repoFullName}`);
          console.log(`   Branch: ${job.defaultBranch}\n`);
        } catch (e) {
          console.log('   (Could not parse job data)\n');
        }
      }
    } else {
      console.log('✅ Queue is empty - all jobs have been processed or no jobs were queued.\n');
    }
    
    // Test connection
    const ping = await redis.ping();
    console.log(`🔌 Redis connection: ${ping === 'PONG' ? '✅ OK' : '❌ Failed'}`);
    
  } catch (error) {
    console.error('❌ Error checking queue:', error.message);
    process.exit(1);
  }
}

checkQueue().then(() => process.exit(0));
