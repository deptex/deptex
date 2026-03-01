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
// Extraction job queue — Phase 2: Supabase-based job persistence
// Jobs stored in extraction_jobs table instead of Redis. Survives machine crashes.
// ============================================================================

import { supabase } from '../../../backend/src/lib/supabase';
import { startExtractionMachine } from './fly-machines';

export interface ExtractionJob {
  projectId: string;
  organizationId: string;
  repo_full_name: string;
  installation_id: string;
  default_branch: string;
  package_json_path?: string;
  ecosystem?: string;
  provider?: string;
  integration_id?: string;
}

/**
 * Queue an extraction job by inserting into Supabase extraction_jobs table
 * and starting a Fly.io machine to process it.
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
    provider?: string;
    integration_id?: string;
  }
): Promise<{ success: boolean; error?: string; run_id?: string }> {
  try {
    const runId = crypto.randomUUID();

    const { data: existingJob } = await supabase
      .from('extraction_jobs')
      .select('id, status')
      .eq('project_id', projectId)
      .in('status', ['queued', 'processing'])
      .maybeSingle();

    if (existingJob) {
      return { success: false, error: 'Extraction already in progress for this project' };
    }

    const { error: insertError } = await supabase.from('extraction_jobs').insert({
      project_id: projectId,
      organization_id: organizationId,
      status: 'queued',
      run_id: runId,
      payload: {
        repo_full_name: repoRecord.repo_full_name,
        installation_id: repoRecord.installation_id,
        default_branch: repoRecord.default_branch,
        package_json_path: repoRecord.package_json_path ?? '',
        ecosystem: repoRecord.ecosystem ?? 'npm',
        provider: repoRecord.provider ?? 'github',
        integration_id: repoRecord.integration_id,
      },
    });

    if (insertError) {
      console.error('[EXTRACT] Failed to insert extraction job:', insertError);
      return { success: false, error: insertError.message };
    }

    console.log(
      `[${new Date().toISOString()}] Queued extraction job for project ${projectId}, repo ${repoRecord.repo_full_name} (run_id: ${runId})`
    );

    // Start a Fly machine (best-effort — job is safe in Supabase if this fails)
    try {
      await startExtractionMachine();
    } catch (e: any) {
      console.warn(`[EXTRACT] Failed to start Fly machine (job stays queued for recovery): ${e.message}`);
    }

    return { success: true, run_id: runId };
  } catch (error: any) {
    console.error('Failed to queue extraction job:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Cancel an active extraction job for a project.
 */
export async function cancelExtractionJob(
  projectId: string
): Promise<{ success: boolean; error?: string }> {
  const { data: job } = await supabase
    .from('extraction_jobs')
    .select('id, status')
    .eq('project_id', projectId)
    .in('status', ['queued', 'processing'])
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();

  if (!job) {
    const { data: latest } = await supabase
      .from('extraction_jobs')
      .select('status')
      .eq('project_id', projectId)
      .order('created_at', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (latest?.status === 'completed') {
      return { success: false, error: 'Extraction already completed' };
    }
    if (latest?.status === 'cancelled') {
      return { success: false, error: 'Extraction already cancelled' };
    }
    return { success: false, error: 'No active extraction found' };
  }

  const { error } = await supabase
    .from('extraction_jobs')
    .update({
      status: 'cancelled',
      completed_at: new Date().toISOString(),
    })
    .eq('id', job.id);

  if (error) {
    return { success: false, error: error.message };
  }

  await supabase
    .from('project_repositories')
    .update({
      status: 'cancelled',
      extraction_step: null,
      extraction_error: 'Cancelled by user',
      updated_at: new Date().toISOString(),
    })
    .eq('project_id', projectId);

  return { success: true };
}
