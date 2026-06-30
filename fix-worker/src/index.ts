import 'dotenv/config';
import './instrument';
import * as Sentry from '@sentry/node';
import * as fs from 'fs';
import * as path from 'path';
import { captureInfraError, captureInfraMessage } from './observability/capture';
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
import { isLanguageEnabled, getEnabledLanguages } from './plan-types';
import { postFixTaskMeterEvent } from './meter-event';
import {
  makeTaskNarrator,
  narrateStep,
  generateVoiceLine,
  postPrReadyCard,
  getProjectName,
  markTaskFromFix,
  type TaskStep,
} from './task-chat';

// Trim a failure reason to one short clause for the chat (the full message is on
// the fix row + Sentry).
function shortReason(message: string): string {
  const firstLine = (message || 'an unexpected error').split('\n')[0].trim();
  return firstLine.length > 140 ? `${firstLine.slice(0, 137)}…` : firstLine;
}

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
    captureInfraMessage('fix row could not be reloaded', 'fix-worker', { jobId: job.id });
    return;
  }

  const logger = new FixLogger(supabase, fullRow.project_id, fullRow.run_id);
  const sandbox = createSandbox(job.id);
  const pipelineStartMs = Date.now();

  // Task fixes narrate their real steps into the task chat, in the first person.
  // No-op (and no project-name lookup) for a standalone fix.
  const narrate = makeTaskNarrator(supabase, fullRow.thread_id);
  const step = (s: TaskStep) => narrateStep(supabase, fullRow.thread_id, s);
  const projectName = fullRow.thread_id
    ? await getProjectName(supabase, fullRow.project_id)
    : 'the project';

  const heartbeat = setInterval(() => {
    sendHeartbeat(supabase, job.id).catch(() => {});
  }, HEARTBEAT_INTERVAL_MS);

  try {
    await logger.info('init', `Starting fix ${fullRow.fix_type}/${fullRow.osv_id ?? fullRow.semgrep_finding_id ?? fullRow.secret_finding_id ?? job.id}`);

    const plan = job.plan;

    // Language gate is read from LANGUAGE_GATE env (defaults to v1 ship gate
    // js/ts/python/go). Stretch language bootstrap is wired in sandbox.ts but
    // the gate stays closed by default — operator opens it explicitly.
    if (!isLanguageEnabled(plan.language)) {
      const enabled = getEnabledLanguages().join(', ');
      await logger.error('init', `Language ${plan.language} not enabled (LANGUAGE_GATE=${enabled})`);
      await markFailed(
        supabase,
        job.id,
        `Language ${plan.language} not enabled on this fix-worker. Enabled: ${enabled}.`,
        'unsupported_language',
      );
      await narrate(`I can't fix this one yet — ${plan.language} isn't supported here.`);
      await markTaskFromFix(supabase, fullRow.task_id, {
        status: 'failed',
        summary: `Language ${plan.language} not supported`,
      });
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

    // The model powers both the editor and the live first-person VOICE — one
    // short sentence the worker speaks between its steps. Best-effort and
    // no-op for a non-task fix (no thread).
    const model = await getLanguageModelForOrg(supabase, fullRow.organization_id);
    // A dependency bump (vulnerability) re-resolves deps; semgrep/secret are code
    // fixes that run the tests. The narration phrasing follows from this.
    const isDepBump = fullRow.fix_type === 'vulnerability';
    const findingLabel = fullRow.osv_id
      ? fullRow.osv_id
      : fullRow.fix_type === 'secret'
        ? 'a hardcoded secret'
        : 'a code security finding';
    const fixContext = `You are Aegis, fixing ${findingLabel} in the ${projectName} project. The change: ${plan.summary}.`;
    const voice = async (justDid: string, next?: string): Promise<void> => {
      if (!fullRow.thread_id) return;
      const line = await generateVoiceLine(
        model,
        `${fixContext}\nYou just ${justDid}.${next ? ` Your next step: ${next}.` : ''}`,
      );
      if (line) await narrate(line);
    };

    await cloneAtSha({
      workDir: sandbox.workDir,
      installationToken,
      repoFullName: repoInfo.repoFullName,
      branch: fullRow.plan_base_branch,
      baseSha: fullRow.plan_base_sha,
      logger,
    });
    await step({ icon: 'clone', label: `Cloned the ${projectName} repository` });
    await voice(
      'cloned the repo into a clean sandbox',
      isDepBump ? 'open the dependency manifest and apply the version bump' : 'open the affected file and apply the fix',
    );

    if (await isJobCancelled(supabase, job.id)) {
      await logger.warn('complete', 'Fix cancelled by user before setup');
      return;
    }

    // Monorepo support: setup (install), plan file-edits, and tests run inside
    // the project's subdirectory (project_repositories.package_json_path);
    // '' = repo root. The clone + all git ops stay at sandbox.workDir (the repo
    // root) so `git add -A` from the root captures edits made in the subdir.
    const projectDir = repoInfo.packageJsonPath
      ? path.join(sandbox.workDir, repoInfo.packageJsonPath)
      : sandbox.workDir;

    if (repoInfo.packageJsonPath) {
      await logger.info('setup', `Project subdir: ${repoInfo.packageJsonPath} (running setup/tests in ${projectDir})`);
      if (!fs.existsSync(projectDir)) {
        await markFailed(
          supabase,
          job.id,
          `package_json_path '${repoInfo.packageJsonPath}' not found in repo`,
          'project_dir_missing',
        );
        await narrate(`I couldn't find the project directory in the repository, so I had to stop.`);
        await markTaskFromFix(supabase, fullRow.task_id, {
          status: 'failed',
          summary: 'Project directory not found in repo',
        });
        return;
      }
    }

    const setup = await setupForLanguage({ workDir: projectDir, language: plan.language, logger });

    const changedFiles = (plan.fileChanges ?? []).map((fc) => fc.path).filter(Boolean);
    const primaryFile = changedFiles[0] ?? 'the affected file';

    // onPhase posts the edit/verify step + voice with REAL timing: the edit lands
    // before the slow install ("now let me reinstall…"), then the install runs,
    // then verify lands after it passes. (verifiedLocally false = we soft-passed
    // and deferred to the PR's CI, so we don't claim a local check.)
    const pipeline = await runFixPipeline({
      model,
      plan,
      fixType: fullRow.fix_type,
      workDir: projectDir,
      repoRoot: sandbox.workDir,
      logger,
      extraEnv: setup.extraEnv,
      pipelineStartMs,
      onPhase: async (phase, meta) => {
        if (phase === 'edit') {
          await step({ icon: 'edit', label: `Updated ${primaryFile}` });
          await voice(
            `applied the change to ${primaryFile}`,
            isDepBump ? 'reinstall dependencies to update the lockfile' : 'run a quick typecheck to make sure nothing broke',
          );
        } else {
          const ok = meta?.verifiedLocally !== false;
          await step({
            icon: 'verify',
            label: ok
              ? isDepBump
                ? 'Verified the new version resolves'
                : 'Type-checked — no errors'
              : "Applied the change (the PR's CI runs the tests)",
          });
          await voice(
            ok
              ? isDepBump
                ? 'reinstalled and confirmed the new version resolves with no conflicts'
                : "type-checked the change and it's clean"
              : "applied the change (the project's CI will run the full test suite on the pull request)",
            'open the pull request for review',
          );
        }
      },
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
    await step({ icon: 'pr', label: `Opened pull request #${pr.prNumber}` });
    // No voice line here — the PR card's caption ("The pull request is up …") is
    // the closing beat, right above the card. The PR card lands LAST so the chat
    // reads top-to-bottom (reason → steps → card); then the task is marked done.
    await postPrReadyCard(supabase, fullRow.thread_id, job.id);
    await markTaskFromFix(supabase, fullRow.task_id, { status: 'completed', summary: plan.summary });
  } catch (err: any) {
    const message = err?.message ?? String(err);
    const category = err instanceof FixPipelineError ? err.category : undefined;
    Sentry.captureException(err, {
      tags: { component: 'fix-worker', ...(category ? { category } : {}) },
      user: { id: fullRow.organization_id },
      contexts: { fix_task: { fix_id: job.id, project_id: fullRow.project_id, run_id: fullRow.run_id } },
    });
    await logger.error('complete', `Fix failed: ${message}`, err);
    await markFailed(supabase, job.id, message, category);
    await narrate(
      `I couldn't finish this safely — ${shortReason(message)}. I haven't opened a pull request.`,
    );
    await markTaskFromFix(supabase, fullRow.task_id, {
      status: 'failed',
      summary: `Fix failed: ${shortReason(message)}`,
    });
  } finally {
    clearInterval(heartbeat);
    sandbox.cleanup();
    try {
      await postFixTaskMeterEvent({
        taskId: job.id,
        orgId: fullRow.organization_id,
        projectId: fullRow.project_id,
        startedAtMs: pipelineStartMs,
      });
    } catch (err) {
      console.warn(`[FIX] meter-event emit failed`, err);
    }
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
          Sentry.captureException(e, {
            tags: { component: 'fix-worker', phase: 'process-escape' },
            contexts: { fix_task: { fix_id: job.id } },
          });
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
      captureInfraError(e, 'fix-worker', { phase: 'claim' });
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  }
}

// Flush Sentry then exit. Never let a slow/failing flush block shutdown:
// Sentry.close has its own internal timeout, and we swallow any rejection so
// process.exit always runs even if close() rejects (Fly sends SIGINT on
// scale-to-zero with a 5-min grace, so 2s is comfortably within budget).
async function flushSentryAndExit(code: number): Promise<void> {
  try {
    await Sentry.close(2000);
  } catch {
    /* never block exit on flush */
  }
  process.exit(code);
}

process.on('SIGTERM', () => {
  console.log('SIGTERM received');
  void flushSentryAndExit(0);
});
process.on('SIGINT', () => {
  console.log('SIGINT received');
  void flushSentryAndExit(0);
});

// No global handlers existed before — a stray rejection or uncaught exception
// would crash with no trace (Node's default is to crash on both). Capture to
// Sentry first, then exit non-zero so the machine restarts clean rather than
// limping on in a half-broken/zombie state (restores the prior crash default).
process.on('unhandledRejection', (reason) => {
  console.error('[FIX] Unhandled rejection:', reason);
  Sentry.captureException(reason, { tags: { component: 'fix-worker', kind: 'unhandledRejection' } });
  void flushSentryAndExit(1);
});
process.on('uncaughtException', (err) => {
  console.error('[FIX] Uncaught exception:', err);
  Sentry.captureException(err, { tags: { component: 'fix-worker', kind: 'uncaughtException' } });
  void flushSentryAndExit(1);
});

runWorker().catch((e) => {
  console.error('Fatal:', e);
  Sentry.captureException(e, { tags: { component: 'fix-worker', kind: 'fatal' } });
  void flushSentryAndExit(1);
});
