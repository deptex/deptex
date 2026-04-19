import 'dotenv/config';
import path from 'path';
import { Redis } from '@upstash/redis';
import { analyzeRepository } from './parser';
import { storeAnalysisResults } from './storage';
import { cloneRepository, cleanupRepository } from './github';

const redisUrl = process.env.UPSTASH_REDIS_URL;
const redisToken = process.env.UPSTASH_REDIS_TOKEN;

if (!redisUrl || !redisToken) {
  throw new Error('UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN must be set');
}

const redis = new Redis({
  url: redisUrl,
  token: redisToken,
});

// Use different queue name for local development to avoid conflicts with deployed workers
// Default to 'ast-parsing-jobs-local' for local dev, 'ast-parsing-jobs' for production
const QUEUE_NAME = process.env.AST_PARSING_QUEUE_NAME || (process.env.NODE_ENV === 'production' ? 'ast-parsing-jobs' : 'ast-parsing-jobs-local');
const WORKER_ID = `worker-${process.pid}-${Date.now()}`;

// Test Redis connection on startup
async function testRedisConnection(): Promise<boolean> {
  try {
    console.log(`[${new Date().toISOString()}] 🔌 Testing Redis connection...`);
    // Try a simple ping-like operation
    const pingResult = await redis.ping();
    console.log(`[${new Date().toISOString()}] ✅ Redis connection successful (ping: ${pingResult})`);
    
    // CRITICAL TEST: Write a test value and immediately read it back
    const testKey = `worker-test-${Date.now()}`;
    const testValue = 'worker-can-read-write';
    await redis.set(testKey, testValue);
    const readBack = await redis.get(testKey);
    await redis.del(testKey); // Clean up
    console.log(`[${new Date().toISOString()}] 🧪 Redis read-write test: ${readBack === testValue ? '✅ PASSED' : '❌ FAILED'} (wrote: ${testValue}, read: ${readBack})`);
    
    // Check queue length
    const queueLength = await redis.llen(QUEUE_NAME);
    console.log(`[${new Date().toISOString()}] 📊 Current queue length: ${queueLength} jobs`);
    
    if (queueLength > 0) {
      console.log(`[${new Date().toISOString()}] ⚠️  Found ${queueLength} job(s) waiting in queue - will process them now`);
    }
    
    return true;
  } catch (error: any) {
    console.error(`[${new Date().toISOString()}] ❌ Redis connection failed:`, error.message);
    console.error(`[${new Date().toISOString()}] Error details:`, error);
    return false;
  }
}

interface ASTParsingJob {
  projectId: string;
  repoFullName: string;
  installationId: string;
  defaultBranch: string;
  packageJsonPath?: string;
}

/**
 * Process a single AST parsing job
 */
async function processJob(job: ASTParsingJob): Promise<{ success: boolean; error?: string }> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] 🚀 Processing AST parsing job for project ${job.projectId}, repo ${job.repoFullName}`);

  let repoPath: string | null = null;

  try {
    // Clone the repository
    console.log(`[${new Date().toISOString()}] 📥 Cloning repository ${job.repoFullName} (branch: ${job.defaultBranch})...`);
    repoPath = await cloneRepository(job.installationId, job.repoFullName, job.defaultBranch);
    console.log(`[${new Date().toISOString()}] ✅ Repository cloned to ${repoPath}`);

    const packageJsonPath = job.packageJsonPath ?? '';
    const analysisRoot = packageJsonPath ? path.join(repoPath, packageJsonPath) : repoPath;
    console.log(`[${new Date().toISOString()}] 🔍 Analyzing repository for imports (root: ${analysisRoot})...`);
    const analysisResults = analyzeRepository(analysisRoot);
    console.log(`[${new Date().toISOString()}] 📊 Found ${analysisResults.length} files with imports`);

    // Store results in database
    console.log(`[${new Date().toISOString()}] 💾 Storing analysis results in database...`);
    const storeResult = await storeAnalysisResults(job.projectId, analysisResults);

    if (!storeResult.success) {
      throw new Error(storeResult.error || 'Failed to store analysis results');
    }

    console.log(`[${new Date().toISOString()}] ✅ Successfully processed AST parsing job for project ${job.projectId}`);
    return { success: true };
  } catch (error: any) {
    console.error(`Error processing job for project ${job.projectId}:`, error);
    return { success: false, error: error.message };
  } finally {
    // Clean up cloned repository
    if (repoPath) {
      console.log(`Cleaning up repository at ${repoPath}...`);
      cleanupRepository(repoPath);
    }
  }
}

/**
 * Main worker loop - continuously polls Redis for jobs
 */
async function runWorker(): Promise<void> {
  const startTime = new Date().toISOString();
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] AST Parser Worker starting...`);
  console.log(`[${startTime}] ========================================`);
  console.log(`[${startTime}] Queue name: ${QUEUE_NAME}`);
  console.log(`[${startTime}] Redis URL configured: ${!!redisUrl}`);
  console.log(`[${startTime}] Redis Token configured: ${!!redisToken}`);
  
  // Test Redis connection
  const redisConnected = await testRedisConnection();
  if (!redisConnected) {
    console.error(`[${startTime}] ❌ Cannot start worker - Redis connection failed`);
    process.exit(1);
  }
  
  // Log Redis URL (first 50 chars for verification)
  const redisUrlPreview = redisUrl?.substring(0, 50) + '...' || 'not set';
  console.log(`[${startTime}] 🔗 Worker Redis URL: ${redisUrlPreview}`);
  
  console.log(`[${startTime}] ✅ Worker ready, starting to poll for jobs...`);
  console.log(`[${startTime}] Worker ID: ${WORKER_ID} (PID: ${process.pid})`);
  console.log(`[${startTime}] ========================================`);
  
  // Warn if there might be other workers (check queue for unexpected activity)
  const initialQueueLength = await redis.llen(QUEUE_NAME);
  if (initialQueueLength > 0) {
    console.log(`[${startTime}] ⚠️  WARNING: Found ${initialQueueLength} job(s) in queue at startup - another worker may be running!`);
  }
  
  let pollCount = 0;
  let lastStatusLog = Date.now();

  while (true) {
    try {
      pollCount++;
      const pollStartTime = new Date().toISOString();
      console.log(`[${pollStartTime}] 🔄 STARTING Poll #${pollCount} on queue '${QUEUE_NAME}'`);
      
      // Poll Redis list for jobs (Upstash doesn't support blocking operations)
      let jobData: string | ASTParsingJob | null = null;
      try {
        // Check queue length before popping
        const queueLengthBefore = await redis.llen(QUEUE_NAME);
        console.log(`[${new Date().toISOString()}] 📊 Queue '${QUEUE_NAME}' length BEFORE lpop: ${queueLengthBefore}`);
        
        if (queueLengthBefore > 0) {
          console.log(`[${new Date().toISOString()}] 📬 Found ${queueLengthBefore} job(s) in queue '${QUEUE_NAME}', processing...`);
        }
        
        console.log(`[${new Date().toISOString()}] 🔍 Calling lpop on queue '${QUEUE_NAME}'...`);
        jobData = await redis.lpop(QUEUE_NAME) as string | ASTParsingJob | null;
        console.log(`[${new Date().toISOString()}] 📦 lpop result: ${jobData ? 'GOT JOB' : 'null'}`);
        
        if (jobData) {
          console.log(`[${new Date().toISOString()}] ✅ Successfully popped job from queue '${QUEUE_NAME}'`);
        }
        
        // Check queue length after popping
        const queueLengthAfter = await redis.llen(QUEUE_NAME);
        console.log(`[${new Date().toISOString()}] 📊 Queue '${QUEUE_NAME}' length AFTER lpop: ${queueLengthAfter}`);
      } catch (redisError: any) {
        console.error(`[${new Date().toISOString()}] ❌ Redis lpop error:`, redisError.message);
        console.error(`[${new Date().toISOString()}] ❌ Redis error stack:`, redisError.stack);
        throw redisError;
      }

      if (jobData) {
        // Parse the job - Upstash Redis may return string or already-parsed object
        let job: ASTParsingJob;
        if (typeof jobData === 'string') {
          // String needs parsing
          job = JSON.parse(jobData);
        } else if (typeof jobData === 'object' && jobData !== null) {
          // Already an object (Upstash auto-parses JSON strings)
          job = jobData as ASTParsingJob;
        } else {
          throw new Error(`Unexpected jobData type: ${typeof jobData}`);
        }

        // Process the job
        const jobResult = await processJob(job);

        if (!jobResult.success) {
          console.error(`[${new Date().toISOString()}] Job failed: ${jobResult.error}`);
          // TODO: Implement retry logic or dead letter queue
        } else {
          console.log(`[${new Date().toISOString()}] ✅ Job completed successfully for project ${job.projectId}`);
        }
      } else {
        // No job available, wait before polling again
        await new Promise((resolve) => setTimeout(resolve, 5000));
      }
    } catch (error: any) {
      console.error('Error in worker loop:', error);
      // Wait a bit before retrying to avoid tight error loops
      await new Promise((resolve) => setTimeout(resolve, 5000));
    }
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully...');
  process.exit(0);
});

// Start the worker
runWorker().catch((error) => {
  console.error('Fatal error in worker:', error);
  process.exit(1);
});
