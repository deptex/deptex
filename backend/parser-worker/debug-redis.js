const { Redis } = require('@upstash/redis');
require('dotenv/config');

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

console.log('🔍 Redis Connection Debug\n');
console.log(`URL: ${redisUrl ? redisUrl.substring(0, 50) + '...' : 'NOT SET'}`);
console.log(`Token: ${redisToken ? redisToken.substring(0, 10) + '...' : 'NOT SET'}\n`);

if (!redisUrl || !redisToken) {
  console.error('❌ Missing Redis credentials');
  process.exit(1);
}

const redis = new Redis({ url: redisUrl, token: redisToken });

async function debug() {
  try {
    // Test connection
    const ping = await redis.ping();
    console.log(`✅ Ping: ${ping}\n`);

    // Check both queue names
    const queues = ['ast-parsing-jobs', 'ast-parsing-jobs-local'];
    for (const queueName of queues) {
      const length = await redis.llen(queueName);
      console.log(`📊 Queue '${queueName}': ${length} jobs`);
      
      if (length > 0) {
        // Get all jobs without removing them
        const jobs = [];
        for (let i = 0; i < length; i++) {
          const job = await redis.lindex(queueName, i);
          jobs.push(job);
        }
        console.log(`   Jobs:`, jobs.map(j => {
          try {
            const parsed = typeof j === 'string' ? JSON.parse(j) : j;
            return `{projectId: ${parsed.projectId}, repo: ${parsed.repoFullName}}`;
          } catch {
            return String(j).substring(0, 50);
          }
        }));
      }
    }
    
    // Try to push a test job and immediately check
    console.log(`\n🧪 Testing queue operations...`);
    const testQueue = 'ast-parsing-jobs';
    const testJob = JSON.stringify({ test: true, timestamp: Date.now() });
    
    const beforePush = await redis.llen(testQueue);
    console.log(`   Before push: ${beforePush} jobs`);
    
    await redis.rpush(testQueue, testJob);
    const afterPush = await redis.llen(testQueue);
    console.log(`   After push: ${afterPush} jobs`);
    
    const popped = await redis.lpop(testQueue);
    const afterPop = await redis.llen(testQueue);
    console.log(`   After pop: ${afterPop} jobs`);
    console.log(`   Popped: ${popped ? 'SUCCESS' : 'null'}`);
    
  } catch (error) {
    console.error('❌ Error:', error.message);
    console.error(error);
  }
}

debug().then(() => process.exit(0));
