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

// Check both possible queue names
const queues = ['ast-parsing-jobs', 'ast-parsing-jobs-local'];
const overrideQueue = process.env.AST_PARSING_QUEUE_NAME;

async function checkQueues() {
  try {
    console.log('🔍 Checking Redis queues...\n');
    console.log(`📋 AST_PARSING_QUEUE_NAME override: ${overrideQueue || '(not set)'}`);
    console.log(`📋 NODE_ENV: ${process.env.NODE_ENV || '(not set)'}\n`);
    
    for (const queueName of queues) {
      const queueLength = await redis.llen(queueName);
      console.log(`📊 Queue: ${queueName}`);
      console.log(`   Length: ${queueLength} jobs\n`);
      
      if (queueLength > 0) {
        console.log(`   ⚠️  WARNING: Found ${queueLength} job(s) in this queue!`);
        
        // Show first job (without removing it)
        const firstJob = await redis.lindex(queueName, 0);
        if (firstJob) {
          try {
            const job = typeof firstJob === 'string' ? JSON.parse(firstJob) : firstJob;
            console.log(`   📄 First job:`);
            console.log(`      Project ID: ${job.projectId}`);
            console.log(`      Repo: ${job.repoFullName}`);
            console.log(`      Branch: ${job.defaultBranch}\n`);
          } catch (e) {
            console.log(`      (Could not parse job data)\n`);
          }
        }
      }
    }
    
    // Test connection
    const ping = await redis.ping();
    console.log(`🔌 Redis connection: ${ping === 'PONG' ? '✅ OK' : '❌ Failed'}`);
    console.log(`🔗 Redis URL: ${redisUrl.substring(0, 50)}...\n`);
    
    // Determine expected queue name
    const expectedQueue = overrideQueue || 'ast-parsing-jobs';
    console.log(`✅ Expected queue name (based on config): ${expectedQueue}`);
    const expectedLength = await redis.llen(expectedQueue);
    console.log(`   Current length: ${expectedLength} jobs\n`);
    
  } catch (error) {
    console.error('❌ Error checking queues:', error.message);
    process.exit(1);
  }
}

checkQueues().then(() => process.exit(0));
