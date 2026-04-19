import 'dotenv/config';
import { createClient, SupabaseClient } from '@supabase/supabase-js';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { claimJob, sendHeartbeat, updateJobStatus, isJobCancelled, FixJobRow } from './job-db';
import { FixLogger } from './logger';
import { detectEcosystem, getStrategyFiles, buildFixPrompt } from './strategies';
import { invokeAider, getAiderEnvVars, getAiderModelFlag, clearLLMKeys, parseTokenUsage } from './executor';
import { validateFix } from './validation';
import { cloneRepo, getBranchName, resolveBranchName, commitAndPush, getDiffSummary, checkDiskSpace, createPullRequest } from './git-ops';

const IDLE_TIMEOUT_MS = 30_000;
const POLL_INTERVAL_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 60_000;
const MACHINE_ID = process.env.FLY_MACHINE_ID || `local-${process.pid}`;

function getSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key);
}

// ---------- BYOK key decryption ----------

function decryptApiKey(encrypted: string, storedVersion: number): string {
  const ALGORITHM = 'aes-256-gcm';
  const AUTH_TAG_LENGTH = 16;

  const parts = encrypted.split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted key format');

  const nonce = Buffer.from(parts[0], 'base64');
  const ciphertext = Buffer.from(parts[1], 'base64');
  const authTag = Buffer.from(parts[2], 'base64');

  const keyHex = process.env.AI_ENCRYPTION_KEY;
  if (!keyHex) throw new Error('AI_ENCRYPTION_KEY not configured on aider worker');

  const key = Buffer.from(keyHex, 'hex');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext) + decipher.final('utf8');
}

async function getOrgAIKey(supabase: SupabaseClient, orgId: string): Promise<{ provider: string; apiKey: string; model: string }> {
  const { data } = await supabase
    .from('organization_ai_providers')
    .select('provider, encrypted_api_key, encryption_key_version, model_preference')
    .eq('organization_id', orgId)
    .eq('is_default', true)
    .single();

  if (!data) throw new Error('No AI provider configured for this organization');

  const apiKey = decryptApiKey(data.encrypted_api_key, data.encryption_key_version);
  const model = data.model_preference || getDefaultModel(data.provider);
  return { provider: data.provider, apiKey, model };
}

function getDefaultModel(provider: string): string {
  const defaults: Record<string, string> = {
    openai: 'gpt-4o',
    anthropic: 'claude-sonnet-4-20250514',
    google: 'gemini-2.5-flash',
  };
  return defaults[provider] ?? 'gpt-4o';
}

// ---------- Git token ----------

async function getGitToken(supabase: SupabaseClient, integrationId: string): Promise<string> {
  const { data } = await supabase
    .from('organization_integrations')
    .select('access_token')
    .eq('id', integrationId)
    .single();

  if (!data?.access_token) throw new Error('Git provider token not found');
  return data.access_token;
}

// ---------- Job processing ----------

async function processFixJob(supabase: SupabaseClient, job: FixJobRow): Promise<void> {
  const logger = new FixLogger(supabase, job.project_id, job.run_id);
  const workDir = path.join('/tmp', `fix-${job.id}`);

  let tokenUsage = { tokens: 0, cost: 0 };

  const heartbeatInterval = setInterval(async () => {
    try { await sendHeartbeat(supabase, job.id); } catch { /* non-fatal */ }
  }, HEARTBEAT_INTERVAL_MS);

  try {
    await logger.info('init', `Fix job started: ${job.strategy} for ${job.osv_id || job.fix_type}`);

    const repoInfo = job.payload.repo;
    if (!repoInfo?.fullName) {
      throw new Error('Missing repository information in job payload');
    }

    // Check disk space
    checkDiskSpace(workDir, logger);

    // 1. Get git token
    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('init', 'Fix cancelled by user');
      return;
    }

    const gitToken = await getGitToken(supabase, repoInfo.integrationId);

    // 2. Clone
    await cloneRepo(
      repoInfo.fullName,
      repoInfo.defaultBranch || 'main',
      repoInfo.provider || 'github',
      gitToken,
      workDir,
      logger,
    );

    // Navigate to monorepo root if needed
    const fixDir = repoInfo.rootDirectory ? path.join(workDir, repoInfo.rootDirectory) : workDir;

    // 3. Detect ecosystem
    const ecosystem = job.payload.dependency?.ecosystem || detectEcosystem(fixDir);
    if (!ecosystem) {
      throw Object.assign(new Error('Could not determine project ecosystem'), { category: 'ecosystem_detection_failed' });
    }

    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('aider', 'Fix cancelled by user');
      return;
    }

    // 4. Get BYOK key
    let aiConfig: { provider: string; apiKey: string; model: string };
    try {
      aiConfig = await getOrgAIKey(supabase, job.organization_id);
    } catch (err: any) {
      throw Object.assign(new Error(err.message), { category: 'key_decryption_failed' });
    }

    // 5. Build prompt + determine files
    const prompt = buildFixPrompt(job, ecosystem);
    const files = getStrategyFiles(ecosystem, fixDir);

    // Also add code files from reachability context
    if (job.payload.importingFiles) {
      for (const f of job.payload.importingFiles.slice(0, 5)) {
        const fullPath = path.join(workDir, f);
        if (fs.existsSync(fullPath) && !files.includes(fullPath)) {
          files.push(fullPath);
        }
      }
    }

    await logger.info('aider', `Running Aider (${aiConfig.provider}/${aiConfig.model}) on ${files.length} files`);

    // 6. Invoke Aider
    const envVars = getAiderEnvVars(aiConfig.provider, aiConfig.apiKey);
    const modelFlag = getAiderModelFlag(aiConfig.provider, aiConfig.model);

    const result = await invokeAider(workDir, prompt, files, modelFlag, envVars, logger);

    clearLLMKeys();

    tokenUsage = parseTokenUsage(result.stdout + '\n' + result.stderr);

    if (result.exitCode !== 0) {
      const stderr = result.stderr.slice(0, 1000);
      if (stderr.includes('401') || stderr.includes('403') || stderr.includes('Unauthorized')) {
        throw Object.assign(new Error('AI provider authentication failed. Check your API key.'), { category: 'auth_failed' });
      }
      throw Object.assign(new Error(`Aider exited with code ${result.exitCode}: ${stderr}`), { category: 'aider_error' });
    }

    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('aider', 'Fix cancelled by user');
      return;
    }

    // 7. Validate
    await logger.info('validate', 'Running post-fix validation...');
    const validationResult = await validateFix(fixDir, ecosystem, logger);

    // 8. Check for empty changes
    const diffSummary = getDiffSummary(workDir);

    // 9. Commit and push
    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('push', 'Fix cancelled by user');
      return;
    }

    const baseBranchName = getBranchName(job, repoInfo.rootDirectory);
    const branchName = await resolveBranchName(workDir, baseBranchName, logger);
    const commitMsg = buildPRTitle(job);

    try {
      await commitAndPush(workDir, branchName, commitMsg, logger);
    } catch (err: any) {
      if (err.message === 'no_changes') {
        throw Object.assign(new Error('Aider produced no changes'), { category: 'no_changes' });
      }
      throw err;
    }

    // 10. Create draft PR
    await logger.info('pr', 'Creating draft pull request...');
    const prResult = await createPullRequest(supabase, job, branchName, diffSummary, validationResult);

    if (prResult) {
      await updateJobStatus(supabase, job.id, 'completed', {
        pr_url: prResult.prUrl,
        pr_number: prResult.prNumber,
        pr_branch: prResult.prBranch,
        pr_provider: repoInfo.provider || 'github',
        pr_repo_full_name: repoInfo.fullName,
        diff_summary: diffSummary,
        validation_result: validationResult,
        tokens_used: tokenUsage.tokens || null,
        estimated_cost: tokenUsage.cost || null,
      });
      await logger.success('complete', `Fix PR #${prResult.prNumber} created: ${prResult.prUrl}`);
    } else {
      await updateJobStatus(supabase, job.id, 'completed', {
        pr_branch: branchName,
        pr_provider: repoInfo.provider || 'github',
        pr_repo_full_name: repoInfo.fullName,
        diff_summary: diffSummary,
        validation_result: validationResult,
        tokens_used: tokenUsage.tokens || null,
        estimated_cost: tokenUsage.cost || null,
        error_message: 'Changes pushed but PR creation failed. Create PR manually from branch.',
        error_category: 'pr_creation_failed',
      });
      await logger.warn('complete', `Changes pushed to ${branchName} but PR creation failed`);
    }
  } catch (err: any) {
    const message = err.message || 'Unknown error';
    const category = err.category || 'unknown';
    await logger.error('complete', `Fix failed: ${message}`, err);
    await updateJobStatus(supabase, job.id, 'failed', {
      error_message: message.slice(0, 2000),
      error_category: category,
      tokens_used: tokenUsage.tokens || null,
      estimated_cost: tokenUsage.cost || null,
    });
  } finally {
    clearInterval(heartbeatInterval);
    clearLLMKeys();
    try { fs.rmSync(workDir, { recursive: true, force: true }); } catch { /* best-effort */ }
  }
}

function buildPRTitle(job: FixJobRow): string {
  const dep = job.payload.dependency?.name;
  switch (job.strategy) {
    case 'bump_version': return `fix: upgrade ${dep || 'dependency'} to ${job.target_version || 'safe version'} (${job.osv_id})`;
    case 'code_patch': return `fix: mitigate ${job.osv_id} in ${dep || 'dependency'}`;
    case 'add_wrapper': return `fix: add safe wrapper for ${dep || 'dependency'} (${job.osv_id})`;
    case 'pin_transitive': return `fix: pin ${dep || 'transitive dep'} to safe version (${job.osv_id})`;
    case 'remove_unused': return `fix: remove unused dependency ${dep || ''}`;
    case 'fix_semgrep': return `fix: resolve Semgrep finding ${job.payload.semgrepFinding?.rule_id || ''}`;
    case 'remediate_secret': return `fix: remediate exposed ${job.payload.secretFinding?.detector_type || 'secret'}`;
    default: return `fix: security fix by Deptex AI`;
  }
}

// ---------- Main poll loop ----------

async function runWorker(): Promise<void> {
  const supabase = getSupabase();
  console.log(`[AIDER] Worker starting, machine: ${MACHINE_ID}`);

  let lastJobTime = Date.now();

  while (true) {
    try {
      const job = await claimJob(supabase, MACHINE_ID);

      if (job) {
        lastJobTime = Date.now();
        console.log(`[AIDER] Claimed job ${job.id}: ${job.strategy} for project ${job.project_id} (attempt ${job.attempts})`);

        try {
          await processFixJob(supabase, job);
          console.log(`[AIDER] Job ${job.id} complete`);
        } catch (e: any) {
          console.error(`[AIDER] Job ${job.id} failed:`, e.message);
        }

        continue;
      }

      if (Date.now() - lastJobTime > IDLE_TIMEOUT_MS) {
        console.log('[AIDER] No jobs for 30s, shutting down for scale-to-zero');
        process.exit(0);
      }

      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    } catch (e: any) {
      console.error('[AIDER] Worker error:', e.message);
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }
}

process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down');
  clearLLMKeys();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down');
  clearLLMKeys();
  process.exit(0);
});

runWorker().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
