import { Redis } from '@upstash/redis';

// Redis client for AST parsing job queue
// This is separate from QStash which handles dependency analysis jobs

let redisClient: Redis | null = null;

function getRedisClient(): Redis | null {
  if (!redisClient) {
    const url = process.env.UPSTASH_REDIS_URL;
    const token = process.env.UPSTASH_REDIS_TOKEN;

    if (!url || !token) {
      console.warn('UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN not configured - Redis queue disabled');
      return null;
    }

    redisClient = new Redis({
      url,
      token,
    });
    
    // Log Redis URL for debugging (first 50 chars)
    console.log(`[${new Date().toISOString()}] 🔗 Backend Redis URL: ${url.substring(0, 50)}...`);
  }

  return redisClient;
}

export interface ASTParsingJob {
  projectId: string;
  repoFullName: string;
  installationId: string;
  defaultBranch: string;
  /** Directory containing package.json ('' = repo root). */
  packageJsonPath?: string;
}

// Use different queue name for local development to avoid conflicts with deployed workers
// Default to 'ast-parsing-jobs-local' for local dev, 'ast-parsing-jobs' for production
const QUEUE_NAME = process.env.AST_PARSING_QUEUE_NAME || (process.env.NODE_ENV === 'production' ? 'ast-parsing-jobs' : 'ast-parsing-jobs-local');

/**
 * Queue an AST parsing job to Redis
 * This is called when a repository is connected to trigger import analysis
 */
export async function queueASTParsingJob(
  projectId: string,
  repoData: {
    repo_full_name: string;
    installation_id: string;
    default_branch: string;
    package_json_path?: string;
  }
): Promise<{ success: boolean; error?: string }> {
  const client = getRedisClient();
  if (!client) {
    console.warn('[AST] UPSTASH_REDIS_URL and/or UPSTASH_REDIS_TOKEN not set - AST parsing job NOT queued (import analysis will not run until Redis is configured and parser-worker is running).');
    return { success: false, error: 'Redis not configured' };
  }

  const job: ASTParsingJob = {
    projectId,
    repoFullName: repoData.repo_full_name,
    installationId: repoData.installation_id,
    defaultBranch: repoData.default_branch,
    packageJsonPath: repoData.package_json_path ?? '',
  };

  try {
    // Push job to the end of the queue (FIFO)
    const jobString = JSON.stringify(job);
    const pushResult = await client.rpush(QUEUE_NAME, jobString);
    
    // Verify the job is actually in the queue using llen
    const queueLength = await client.llen(QUEUE_NAME);
    
    console.log(`[${new Date().toISOString()}] ✅ Queued AST parsing job for project ${projectId}, repo ${repoData.repo_full_name} to queue '${QUEUE_NAME}' (queue length: ${queueLength})`);
    return { success: true };
  } catch (error: any) {
    console.error('Failed to queue AST parsing job:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Check if Redis is configured
 */
export function isRedisConfigured(): boolean {
  return !!getRedisClient();
}

/**
 * Get the queue name (for worker use)
 */
export function getQueueName(): string {
  return QUEUE_NAME;
}

// ============================================================================
// Extraction job queue (async repo extraction: clone, cdxgen, dep-scan, etc.)
// ============================================================================

export interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  /** Directory containing the manifest file ('' = repo root). */
  package_json_path?: string;
  /** Ecosystem identifier (npm, pypi, maven, etc.). Defaults to 'npm'. */
  ecosystem?: string;
}

const EXTRACTION_QUEUE_NAME =
  process.env.EXTRACTION_QUEUE_NAME ||
  (process.env.NODE_ENV === 'production' ? 'extraction-jobs' : 'extraction-jobs-local');

/**
 * Queue an extraction job for the extraction worker.
 * Called by connect endpoint when user connects a repo.
 */
export async function queueExtractionJob(
  projectId: string,
  organizationId: string,
  repoRecord: {
    repo_full_name: string;
    installation_id: string;
    default_branch: string;
    package_json_path?: string;
    ecosystem?: string;
  }
): Promise<{ success: boolean; error?: string }> {
  const client = getRedisClient();
  if (!client) {
    console.warn('[EXTRACT] Redis not configured - extraction job NOT queued.');
    return { success: false, error: 'Redis not configured' };
  }

  const job: ExtractionJob = {
    projectId,
    organizationId,
    repo_full_name: repoRecord.repo_full_name,
    installation_id: repoRecord.installation_id,
    default_branch: repoRecord.default_branch,
    package_json_path: repoRecord.package_json_path ?? '',
    ecosystem: repoRecord.ecosystem ?? 'npm',
  };

  try {
    await client.rpush(EXTRACTION_QUEUE_NAME, JSON.stringify(job));
    const queueLength = await client.llen(EXTRACTION_QUEUE_NAME);
    console.log(
      `[${new Date().toISOString()}] Queued extraction job for project ${projectId}, repo ${repoRecord.repo_full_name} (queue: ${EXTRACTION_QUEUE_NAME}, length: ${queueLength})`
    );
    return { success: true };
  } catch (error: any) {
    console.error('Failed to queue extraction job:', error);
    return { success: false, error: error.message };
  }
}

export function getExtractionQueueName(): string {
  return EXTRACTION_QUEUE_NAME;
}
