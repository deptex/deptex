import 'dotenv/config';
import './instrument';
import * as Sentry from '@sentry/node';
import { execSync } from 'child_process';
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
  maybeRequeueFollowup,
  sendHeartbeat,
  type FixJobRow,
} from './job-db';
import { createInstallationToken } from './github';
import { createSandbox, cloneAtSha, setupForLanguage } from './sandbox';
import { runFixPipeline, FixPipelineError } from './executor';
import { runTaskAgent, type AgentRunInput } from './agent/loop';
import { runBaseImageBump, describeBaseImageTarget } from './base-image';
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
  describeFailure,
  getProjectName,
  markTaskFromFix,
  type TaskStep,
} from './task-chat';

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

/** The per-finding-type live-finding-id column on the fix row. */
function agentFindingId(row: any): string {
  switch (row.fix_type) {
    case 'vulnerability':
      return row.osv_id ?? '';
    case 'semgrep':
      return row.semgrep_finding_id ?? '';
    case 'secret':
      return row.secret_finding_id ?? '';
    case 'malicious':
      return row.malicious_finding_id ?? '';
    case 'iac':
      return row.iac_finding_id ?? '';
    case 'container':
      return row.container_finding_id ?? '';
    case 'base_image':
      return row.base_image_rec_id ?? '';
    case 'dataflow':
      return row.reachable_flow_id ?? '';
    case 'dast':
      return row.dast_finding_id ?? '';
    default:
      return '';
  }
}

/** Normalize a claimed agentic fix row into the table-agnostic AgentRunInput. */
function buildAgentInput(row: any, fixId: string): AgentRunInput {
  // The sentinel plan carries { strategy:'agent', summary, findingBrief? } plus,
  // after a wake, { resume: true, prior_status } stamped by wake_agent_fix.
  const sentinel = (row.plan ?? {}) as {
    summary?: string;
    findingBrief?: string;
    severity?: string;
    resume?: boolean;
    prior_status?: string;
  };
  return {
    fixId,
    organizationId: row.organization_id,
    projectId: row.project_id,
    threadId: row.thread_id ?? null,
    taskId: row.task_id ?? null,
    fixType: row.fix_type,
    finding: { type: row.fix_type, id: agentFindingId(row), severity: sentinel.severity },
    summary: sentinel.summary ?? 'Fix the targeted security finding.',
    findingBrief: sentinel.findingBrief,
    baseBranch: row.plan_base_branch,
    baseSha: row.plan_base_sha,
    resume: sentinel.resume === true,
    resumePriorStatus: sentinel.prior_status ?? null,
    runSeq: row.run_seq ?? 0,
    priorPr:
      row.pr_branch && row.pr_number
        ? {
            branch: row.pr_branch,
            number: row.pr_number,
            url: row.pr_url ?? '',
            repoFullName: row.pr_repo_full_name ?? '',
          }
        : null,
  };
}

async function processJob(supabase: SupabaseClient, job: FixJobRow): Promise<void> {
  const fullRow = await loadFullRow(supabase, job.id);
  if (!fullRow) {
    console.error(`[FIX] Could not reload row ${job.id}`);
    captureInfraMessage('fix row could not be reloaded', 'fix-worker', { jobId: job.id });
    return;
  }

  // Claim-time capture — the end-of-run drain bumps the DB run_seq BEFORE the
  // finally-block meter fires; metering must bill THIS run's seq, and the NEXT
  // run bills the bumped one.
  const meterRunSeq = fullRow.run_seq ?? 0;

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

    // Autonomous agent path (strategy='agent'): one bounded tool-loop in the
    // cloned repo that decides its own steps and opens the PR. It sits FIRST in
    // the try so it never hits the deterministic pipeline's language gate or its
    // plan-shaped assumptions, and INSIDE this try/finally so the existing 60s
    // heartbeat + the meter event still cover it. It owns its own terminal state
    // (markCompleted / markFailed); an unexpected throw falls through to the
    // shared failure path below.
    if (fullRow.strategy === 'agent') {
      let agentResult: { replayedThrough: string | null; cancelled: boolean } | null = null;
      try {
        agentResult = await runTaskAgent(supabase, buildAgentInput(fullRow, job.id), {
          machineId: MACHINE_ID,
          projectName,
          logger,
          workDir: sandbox.workDir,
        });
      } finally {
        // Drain: if the user messaged DURING this run, re-queue so the next run
        // replays it. Runs even when setup THREW (token/clone/replay failures
        // escape runTaskAgent) — the machine-id fence keeps the outer catch's
        // markFailed from clobbering a woken row. Watermark = what the run
        // actually saw (replayedThrough covers the claim→read window);
        // approved_at fallback covers first runs (a message between accept and
        // claim was unseen). SKIPPED when the user STOPPED the run — Stop must
        // win over a queued follow-up.
        if (!agentResult?.cancelled) {
          await maybeRequeueFollowup(
            supabase,
            job.id,
            fullRow.thread_id,
            fullRow.task_id,
            agentResult?.replayedThrough ?? fullRow.approved_at ?? fullRow.started_at ?? null,
          );
        }
      }
      return;
    }

    const plan = job.plan;

    // Language gate is read from LANGUAGE_GATE env (defaults to v1 ship gate
    // js/ts/python/go). Stretch language bootstrap is wired in sandbox.ts but
    // the gate stays closed by default — operator opens it explicitly.
    if (!isLanguageEnabled(plan.language)) {
      const enabled = getEnabledLanguages().join(', ');
      // Throw so it flows through the one failure path (below) that narrates +
      // posts the failure card, rather than a bespoke dead-end here.
      throw new FixPipelineError(
        `${plan.language} isn't one of the languages I can fix here yet (enabled: ${enabled}).`,
        'unsupported_language',
      );
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
    // The fix strategy drives both the execution path and the narration:
    //  - dependency bump (vulnerability): re-resolve deps.
    //  - base-image bump (base_image / container): deterministic Dockerfile FROM edit.
    //  - explore (dataflow / dast): agentic read-then-patch loop.
    //  - everything else (semgrep / secret / iac): the plan-only code editor.
    const strategy = fullRow.strategy;
    const isDepBump = fullRow.fix_type === 'vulnerability';
    const isBaseImageBump = strategy === 'bump_base_image';
    const isExplore = strategy === 'sanitize_dataflow' || strategy === 'patch_handler';
    const isDast = fullRow.fix_type === 'dast';
    const findingLabel = fullRow.osv_id
      ? fullRow.osv_id
      : fullRow.fix_type === 'secret'
        ? 'a hardcoded secret'
        : fullRow.fix_type === 'iac'
          ? 'an infrastructure misconfiguration'
          : isBaseImageBump
            ? 'an outdated base image'
            : fullRow.fix_type === 'dataflow'
              ? 'a reachable data-flow vulnerability'
              : isDast
                ? 'a runtime security finding'
                : 'a code security finding';
    // For a base-image bump, resolve the concrete current→target image up front so
    // the narration can name it. Best-effort (null if unresolvable).
    const baseTarget = isBaseImageBump ? await describeBaseImageTarget(supabase, fullRow) : null;
    const fixContext = `You are Aegis, fixing ${findingLabel} in the ${projectName} project. The change: ${plan.summary}.`;
    const voice = async (justDid: string, next?: string): Promise<void> => {
      if (!fullRow.thread_id) return;
      const line = await generateVoiceLine(
        model,
        `${fixContext}\nYou just ${justDid}.${next ? ` Your next step: ${next}.` : ''}`,
      );
      if (line) await narrate(line);
    };

    const cloneOutput = await cloneAtSha({
      workDir: sandbox.workDir,
      installationToken,
      repoFullName: repoInfo.repoFullName,
      branch: fullRow.plan_base_branch,
      baseSha: fullRow.plan_base_sha,
      logger,
    });
    await step({
      icon: 'clone',
      label: `Cloned the ${projectName} repository`,
      command: `git clone --depth 1 https://github.com/${repoInfo.repoFullName}.git`,
      output: cloneOutput,
    });
    await voice(
      'cloned the repo into a clean sandbox',
      isDepBump
        ? 'open the dependency manifest and apply the version bump'
        : isBaseImageBump
          ? 'find the Dockerfile and move it to the recommended base image'
          : isExplore
            ? isDast
              ? 'explore the code to find the vulnerable endpoint handler, then patch it'
              : 'explore the code to trace the tainted data flow, then add a sanitizer'
            : 'open the affected file and apply the fix',
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
        throw new FixPipelineError(
          `I couldn't find the project directory ('${repoInfo.packageJsonPath}') in the repository, so I had to stop.`,
          'project_dir_missing',
        );
      }
    }

    const setup = await setupForLanguage({ workDir: projectDir, language: plan.language, logger });

    const changedFiles = (plan.fileChanges ?? []).map((fc) => fc.path).filter(Boolean);
    const primaryFile = changedFiles[0] ?? 'the affected file';

    // onPhase posts the edit/verify step + voice with REAL timing: the edit lands
    // before the slow verify, then verify lands after it passes. Mode-aware so a
    // base-image bump, an explore-and-sanitize, and a plain code edit each read
    // truthfully. (verifiedLocally false = we soft-passed to the PR's CI.)
    const onPhase = async (
      phase: 'edit' | 'verify',
      meta?: { verifiedLocally?: boolean; command?: string; output?: string },
    ): Promise<void> => {
      if (phase === 'edit') {
        if (isExplore) {
          await step({
            icon: 'explore',
            label: isDast
              ? `Explored ${projectName} to find the vulnerable handler`
              : `Traced the tainted data flow in ${projectName}`,
          });
        }
        const editLabel = isBaseImageBump
          ? baseTarget
            ? `Bumped the base image to ${baseTarget.targetImage}`
            : 'Edited the Dockerfile'
          : `Edited ${primaryFile}`;
        // Capture the change so the chat can expand "Edited X" to the real diff.
        // onPhase('edit') fires right after the patch applies and BEFORE verify
        // (which, for a dep bump, regenerates the lockfile) — so the working-tree
        // diff here is exactly the edit itself. Best-effort, capped.
        let editDiff: string | undefined;
        try {
          const raw = execSync(`git -C "${sandbox.workDir}" diff`, {
            encoding: 'utf-8',
            timeout: 15_000,
            maxBuffer: 5 * 1024 * 1024,
          });
          editDiff = raw.trim() ? raw.slice(0, 6000) : undefined;
        } catch {
          editDiff = undefined;
        }
        await step({ icon: 'edit', label: editLabel, diff: editDiff });
        await voice(
          isBaseImageBump
            ? `moved the base image${baseTarget ? ` to ${baseTarget.targetImage}` : ''}`
            : isExplore
              ? isDast
                ? `patched the ${primaryFile} handler to validate the input`
                : `added a sanitizer in ${primaryFile} to neutralize the tainted input`
              : `applied the change to ${primaryFile}`,
          isDepBump
            ? 'reinstall dependencies to update the lockfile'
            : isBaseImageBump
              ? 'open the pull request for review'
              : 'run a quick typecheck to make sure nothing broke',
        );
      } else {
        const ok = meta?.verifiedLocally !== false;
        const verifyLabel = isBaseImageBump
          ? "Bumped the base image (the PR's CI builds the new image)"
          : ok
            ? isDepBump
              ? 'Verified the new version resolves'
              : 'Type-checked — no errors'
            : "Applied the change (the PR's CI runs the tests)";
        await step({ icon: 'verify', label: verifyLabel, command: meta?.command, output: meta?.output });
        await voice(
          isBaseImageBump
            ? 'swapped the base image; the CI pipeline will build and validate the new image'
            : ok
              ? isDepBump
                ? 'reinstalled and confirmed the new version resolves with no conflicts'
                : "type-checked the change and it's clean"
              : "applied the change (the project's CI will run the full test suite on the pull request)",
          'open the pull request for review',
        );
      }
    };

    // Base-image / container bumps are deterministic (no LLM edit): read the
    // curated recommendation and swap the Dockerfile FROM line. Everything else
    // runs the plan editor or the explore loop inside runFixPipeline.
    const pipeline = isBaseImageBump
      ? await runBaseImageBump(supabase, fullRow, {
          workDir: projectDir,
          repoRoot: sandbox.workDir,
          logger,
          onPhase,
        })
      : await runFixPipeline({
          model,
          plan,
          fixType: fullRow.fix_type,
          strategy,
          workDir: projectDir,
          repoRoot: sandbox.workDir,
          logger,
          extraEnv: setup.extraEnv,
          pipelineStartMs,
          onPhase,
          // Narrate the struggle in real time so a fix that needs retries reads as
          // work-in-progress, not silence before a failure.
          onTrouble: async (e) => {
            if (e.kind === 'apply_retry') {
              await narrate(
                `That patch didn't line up with the file — re-reading it and trying again (attempt ${e.attempt + 1}).`,
              );
            } else {
              await narrate(`The checks came back failing — adjusting the fix and trying again.`);
            }
          },
        });
    const totalTokens = pipeline.tokensUsed;

    const { prBranch, diffSummary, pushOutput } = await commitAndPushFix({
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
    await step({
      icon: 'pr',
      label: `Opened pull request #${pr.prNumber}`,
      command: `git push origin ${prBranch}`,
      output: pushOutput,
    });
    // No voice line here — the PR card's caption ("The pull request is up …") is
    // the closing beat, right above the card. The PR card lands LAST so the chat
    // reads top-to-bottom (reason → steps → card); then the task is marked done.
    await postPrReadyCard(supabase, fullRow.thread_id, job.id);
    await markTaskFromFix(supabase, fullRow.task_id, { status: 'completed', summary: plan.summary });
  } catch (err: any) {
    const message = err?.message ?? String(err);
    const category = err instanceof FixPipelineError ? err.category : undefined;
    const details = err instanceof FixPipelineError ? err.details : undefined;
    Sentry.captureException(err, {
      tags: { component: 'fix-worker', ...(category ? { category } : {}) },
      user: { id: fullRow.organization_id },
      contexts: {
        fix_task: {
          fix_id: job.id,
          project_id: fullRow.project_id,
          run_id: fullRow.run_id,
          // Resume failures group distinctly from first-run failures.
          resume: (fullRow.plan as any)?.resume === true,
          run_seq: meterRunSeq,
        },
      },
    });
    await logger.error('complete', `Fix failed: ${message}`, err);

    // Turn the failure into an honest, specific account instead of a generic
    // apology. `plan` may be undefined only on the earliest throws; the primary
    // file comes off the plan directly (always safe in this scope).
    const primaryFile =
      job.plan?.fileChanges?.find((fc) => fc.action !== 'delete')?.path ??
      job.plan?.fileChanges?.[0]?.path;
    const copy = describeFailure(category, message, { primaryFile });

    // Record what was tried + why it stopped on failure_details (logs + detail
    // view only — never rendered in the chat). Machine-fenced: harmless for
    // standalone fixes (claimed under this
    // machine), and it stops a zombie write onto a woken agent row that a NEW
    // machine has since claimed.
    await markFailed(
      supabase,
      job.id,
      message,
      category,
      {
        category: category ?? 'unknown',
        headline: copy.headline,
        explanation: copy.explanation,
        nextStep: copy.nextStep,
        attemptedDiff: details?.attemptedDiff ?? null,
        errorOutput: details?.errorOutput ?? null,
        repairAttempts: details?.repairAttempts ?? null,
      },
      MACHINE_ID,
    );

    // Failure surface = an honest lead-in beat → a failed step line. No card:
    // the attempted diff + real error live only on failure_details (logs / detail
    // view), never in the chat. (The old FixFailureCard was retired.)
    await narrate(copy.leadIn);
    await step({ icon: 'failed', label: copy.stepLabel });
    await markTaskFromFix(supabase, fullRow.task_id, { status: 'failed', summary: copy.headline });
  } finally {
    clearInterval(heartbeat);
    sandbox.cleanup();
    try {
      await postFixTaskMeterEvent({
        taskId: job.id,
        orgId: fullRow.organization_id,
        projectId: fullRow.project_id,
        startedAtMs: pipelineStartMs,
        runSeq: meterRunSeq,
      });
    } catch (err) {
      console.warn(`[FIX] meter-event emit failed`, err);
      // A wake that silently fails to bill is unrecoverable — surface it.
      Sentry.captureException(err, {
        tags: { component: 'fix-worker', money_path: 'meter-emit' },
        contexts: { fix_task: { fix_id: job.id, run_seq: meterRunSeq } },
      });
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
            contexts: {
              fix_task: {
                fix_id: job.id,
                // Best-effort resume context off the claimed row (fullRow is
                // out of scope here); groups resume escapes distinctly.
                resume: (job.plan as any)?.resume === true,
                run_seq: (job as any).run_seq ?? undefined,
              },
            },
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
