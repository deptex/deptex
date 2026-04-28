import 'dotenv/config';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import {
  claimJob,
  getOrgInstallationId,
  isJobCancelled,
  loadFullRow,
  markCompleted,
  markFailed,
  sendHeartbeat,
  type FixJobRow,
} from './job-db';
import { createInstallationToken } from './github';
import { createSandbox, cloneAtSha, setupForLanguage } from './sandbox';
import { runFixPipeline, FixPipelineError } from './executor';
import { commitAndPushFix, openPullRequest } from './pr';
import { FixLogger } from './logger';
import { getLanguageModelForOrg } from './llm';
import { isShipGateLanguage } from './plan-types';

const IDLE_TIMEOUT_MS = 60_000;
const POLL_INTERVAL_MS = 5_000;
const HEARTBEAT_INTERVAL_MS = 60_000;

const MACHINE_ID = process.env.FLY_MACHINE_ID || `local-${process.pid}`;

function getSupabase(): SupabaseClient {
  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;
  if (!url || !key) throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
  return createClient(url, key);
}

async function processJob(supabase: SupabaseClient, job: FixJobRow): Promise<void> {
  const fullRow = await loadFullRow(supabase, job.id);
  if (!fullRow) {
    console.error(`[FIX] Could not reload row ${job.id}`);
    return;
  }

  const logger = new FixLogger(supabase, fullRow.project_id, fullRow.run_id);
  const sandbox = createSandbox(job.id);
  const pipelineStartMs = Date.now();

  const heartbeat = setInterval(() => {
    sendHeartbeat(supabase, job.id).catch(() => {});
  }, HEARTBEAT_INTERVAL_MS);

  try {
    await logger.info('init', `Starting fix ${fullRow.fix_type}/${fullRow.osv_id ?? fullRow.semgrep_finding_id ?? fullRow.secret_finding_id ?? job.id}`);

    const plan = job.plan;

    // Ship-gate guard. Stretch languages return failure with a clear message
    // until M8 wires their bootstrap.
    if (!isShipGateLanguage(plan.language)) {
      await logger.error('init', `Language ${plan.language} not supported in v1 ship gate`);
      await markFailed(supabase, job.id, `Language ${plan.language} not supported by Aegis Fix Agent v1`, 'unsupported_language');
      return;
    }

    if (!fullRow.plan_base_sha || !fullRow.plan_base_branch) {
      throw new Error('Fix row is missing plan_base_sha / plan_base_branch');
    }

    const repoInfo = await getOrgInstallationId(supabase, fullRow.organization_id, fullRow.project_id);
    if (!repoInfo) {
      throw new Error('Project no longer has a GitHub App installation');
    }

    const installationToken = await createInstallationToken(repoInfo.installationId);

    await cloneAtSha({
      workDir: sandbox.workDir,
      installationToken,
      repoFullName: repoInfo.repoFullName,
      branch: fullRow.plan_base_branch,
      baseSha: fullRow.plan_base_sha,
      logger,
    });

    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('complete', 'Fix cancelled by user before setup');
      return;
    }

    const setup = await setupForLanguage({ workDir: sandbox.workDir, language: plan.language, logger });

    const model = await getLanguageModelForOrg(supabase, fullRow.organization_id);

    const pipeline = await runFixPipeline({
      model,
      plan,
      workDir: sandbox.workDir,
      logger,
      extraEnv: setup.extraEnv,
      pipelineStartMs,
    });
    const totalTokens = pipeline.tokensUsed;

    const { prBranch, diffSummary } = await commitAndPushFix({
      workDir: sandbox.workDir,
      fixId: job.id,
      plan,
      installationToken,
      repoFullName: repoInfo.repoFullName,
      baseBranch: fullRow.plan_base_branch,
      logger,
    });

    const pr = await openPullRequest({
      installationToken,
      repoFullName: repoInfo.repoFullName,
      branch: prBranch,
      baseBranch: fullRow.plan_base_branch,
      plan,
      diffSummary,
      logger,
    });

    await markCompleted(supabase, job.id, {
      prUrl: pr.prUrl,
      prNumber: pr.prNumber,
      prBranch: pr.prBranch,
      prRepoFullName: pr.prRepoFullName,
      diffSummary,
      tokensUsed: totalTokens,
    });
    await logger.success('complete', `Fix complete — PR #${pr.prNumber} opened`);
  } catch (err: any) {
    const message = err?.message ?? String(err);
    const category = err instanceof FixPipelineError ? err.category : undefined;
    await logger.error('complete', `Fix failed: ${message}`, err);
    await markFailed(supabase, job.id, message, category);
  } finally {
    clearInterval(heartbeat);
    sandbox.cleanup();
  }
}

async function runWorker(): Promise<void> {
  const supabase = getSupabase();
  console.log(`[FIX] Worker starting, machine: ${MACHINE_ID}`);

  let lastJobTime = Date.now();

  while (true) {
    try {
      const job = await claimJob(supabase, MACHINE_ID);
      if (job) {
        lastJobTime = Date.now();
        console.log(`[FIX] Claimed job ${job.id} (attempt ${job.attempts})`);
        try {
          await processJob(supabase, job);
          console.log(`[FIX] Job ${job.id} done`);
        } catch (e: any) {
          console.error(`[FIX] Job ${job.id} fatal: ${e.message}`);
        }
        continue;
      }

      if (Date.now() - lastJobTime > IDLE_TIMEOUT_MS) {
        console.log('[FIX] No jobs for 60s, shutting down');
        process.exit(0);
      }
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    } catch (e: any) {
      console.error('[FIX] Worker loop error:', e?.message ?? e);
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }
}

process.on('SIGTERM', () => {
  console.log('SIGTERM received');
  process.exit(0);
});
process.on('SIGINT', () => {
  console.log('SIGINT received');
  process.exit(0);
});

runWorker().catch((e) => {
  console.error('Fatal:', e);
  process.exit(1);
});
