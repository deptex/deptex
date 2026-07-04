import { generateText, stepCountIs, hasToolCall } from 'ai';
import * as fsp from 'fs/promises';
import * as path from 'path';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { FindingType } from './../plan-types';
import { getOrgInstallationId, isJobCancelled } from './../job-db';
import { createInstallationToken } from './../github';
import { cloneAtSha, cloneBranchHead } from './../sandbox';
import { getPullRequestState } from './../pr';
import { getLanguageModelForOrg } from './../llm';
import { makeTaskNarrator, narrateStep } from './../task-chat';
import { FixLogger } from './../logger';
import { AGENT_SYSTEM, buildBrief, buildResumeSystem } from './brief';
import { reconstructAgentMessages } from './replay';
import { buildAgentTools, finalizeFailure, type AgentRunState, type AgentToolDeps } from './tools';

/** Wall-clock ceiling — an agent run bills by the second, so this bounds cost too.
 *  Configurable via AEGIS_TASK_WALL_CLOCK_SEC; default 30 min (a slower/cheaper
 *  model needs more room than a frontier one). */
const WALL_CLOCK_MS = (parseInt(process.env.AEGIS_TASK_WALL_CLOCK_SEC || '1800', 10) || 1800) * 1000;
/** Hard step cap (mirrors the plan's ~40). */
const MAX_STEPS = 40;
/** Steps with no side-effecting tool call before we call it stuck. */
const STALL_LIMIT = 6;

/**
 * Table-agnostic input so the loop can later back the standalone request_fix
 * path too (opportunity-scout-f5). Built from the claimed fix row in index.ts.
 */
export interface AgentRunInput {
  fixId: string;
  organizationId: string;
  projectId: string;
  threadId: string | null;
  taskId: string | null;
  fixType: FindingType;
  finding: { type: FindingType; id: string; severity?: string };
  summary: string;
  findingBrief?: string;
  baseBranch: string;
  baseSha: string;
  /** plan.resume === true — this is a user wake, not a first run. */
  resume: boolean;
  /** row.run_seq — 0 = first run, +1 per user wake (billing + branch suffix). */
  runSeq: number;
  /** plan.prior_status — what the row was before the wake reset it. */
  resumePriorStatus: string | null;
  /** The prior run's PR (pr_* columns), when one was opened. */
  priorPr: { branch: string; number: number; url: string; repoFullName: string } | null;
}

export interface AgentRunDeps {
  machineId: string;
  projectName: string;
  logger: FixLogger;
  /** The sandbox clone root. */
  workDir: string;
}

/** Strip any leaked chain-of-thought before narrating a model beat. */
function stripReasoning(text: string): string {
  return text.replace(/<think>[\s\S]*?<\/think>/gi, '').replace(/<\/?think>/gi, '').trim();
}

async function safeList(dir: string): Promise<string> {
  try {
    const entries = await fsp.readdir(dir, { withFileTypes: true });
    return entries
      .filter((e) => e.name !== 'node_modules' && e.name !== '.git')
      .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
      .sort()
      .join('\n');
  } catch {
    return '(could not list repo root)';
  }
}

/**
 * The autonomous coding agent. Clones the repo, hands the model a full toolbox,
 * runs a single bounded generateText loop, and always reaches a terminal state.
 * Owns its own token/clone/model; runs INSIDE processJob's try/finally so the
 * existing 60s heartbeat keeps firing.
 */
export async function runTaskAgent(
  supabase: SupabaseClient,
  input: AgentRunInput,
  deps: AgentRunDeps,
): Promise<{ replayedThrough: string | null; cancelled: boolean }> {
  const { machineId, projectName, logger, workDir } = deps;
  const narrate = makeTaskNarrator(supabase, input.threadId);

  const repoInfo = await getOrgInstallationId(supabase, input.organizationId, input.projectId);
  if (!repoInfo) throw new Error('Project no longer has a GitHub App installation');
  const installationToken = await createInstallationToken(repoInfo.installationId);
  const model = await getLanguageModelForOrg(supabase, input.organizationId, process.env.AEGIS_TASK_MODEL || undefined);

  // Clone the repo up front — this is infrastructure setup, not a step the user
  // needs to watch, so it isn't narrated. The agent's first visible beat is its
  // own investigation.
  //
  // Resume fork: when a prior PR is still OPEN, clone ITS head branch — the
  // earlier changes are already in the files and the eventual push
  // fast-forwards the same PR (amend mode). Otherwise a resume clones the
  // CURRENT base tip (new-PR mode); only first runs pin to the accept-time SHA.
  let resumeMode: { prNumber: number; prUrl: string; branch: string } | null = null;
  if (input.resume && input.priorPr && input.threadId) {
    const prState = await getPullRequestState(
      installationToken,
      input.priorPr.repoFullName || repoInfo.repoFullName,
      input.priorPr.number,
    );
    if (prState === 'unknown') {
      // A transient GitHub failure must NOT default to new-PR mode — if the
      // prior PR is actually still open, that would fork a duplicate PR. Fail
      // retryable instead; only a confirmed 'closed' takes the new-PR path.
      throw new Error('Could not verify the state of the existing pull request — retry this follow-up');
    }
    if (prState === 'open') {
      try {
        await cloneBranchHead({
          workDir,
          installationToken,
          repoFullName: repoInfo.repoFullName,
          branch: input.priorPr.branch,
          logger,
        });
        resumeMode = { prNumber: input.priorPr.number, prUrl: input.priorPr.url, branch: input.priorPr.branch };
      } catch (cloneErr: any) {
        // Only a MISSING branch (deleted despite the open PR) falls through to
        // new-PR mode. Any other clone failure (auth, network, disk) rethrows —
        // a duplicate PR while the original is still open is worse than a
        // retryable failed run.
        const msg = String(cloneErr?.message ?? cloneErr);
        if (!/remote branch .* not found|couldn't find remote ref|not found in upstream/i.test(msg)) {
          throw cloneErr;
        }
        // Reset the sandbox dir (a failed clone can leave partial contents)
        // before the fresh-tip clone below.
        await fsp.rm(workDir, { recursive: true, force: true }).catch(() => {});
        await fsp.mkdir(workDir, { recursive: true }).catch(() => {});
      }
    }
  }
  if (!resumeMode) {
    if (input.resume && input.threadId) {
      // Resume-new-PR mode: clone the CURRENT base tip (not the stale
      // accept-time SHA) — the prior PR is merged/closed/gone.
      await cloneBranchHead({
        workDir,
        installationToken,
        repoFullName: repoInfo.repoFullName,
        branch: input.baseBranch,
        logger,
      });
    } else {
      await cloneAtSha({
        workDir,
        installationToken,
        repoFullName: repoInfo.repoFullName,
        branch: input.baseBranch,
        baseSha: input.baseSha,
        logger,
      });
    }
  }

  const projectDir = repoInfo.packageJsonPath ? path.join(workDir, repoInfo.packageJsonPath) : workDir;
  // Seed the brief with the PROJECT dir listing (the agent's tools + shell are
  // rooted there), not the repo root — so its first paths land in the right place.
  const repoRootListing = await safeList(projectDir);

  const state: AgentRunState = {
    prOpened: false,
    terminal: false,
    progressCalls: 0,
    seenCalls: new Set<string>(),
    novelCalls: 0,
    editedFiles: new Set<string>(),
    pendingSteps: [],
    pendingAfter: [],
  };
  const toolDeps: AgentToolDeps = {
    supabase,
    fixId: input.fixId,
    machineId,
    organizationId: input.organizationId,
    projectId: input.projectId,
    threadId: input.threadId,
    taskId: input.taskId,
    repoRoot: workDir,
    projectDir,
    installationToken,
    repoFullName: repoInfo.repoFullName,
    baseBranch: input.baseBranch,
    fixType: input.fixType,
    finding: input.finding,
    projectName,
    logger,
    model,
    state,
    resumeMode,
    runSeq: input.runSeq,
    resumePriorStatus: input.resumePriorStatus,
  };
  const tools = buildAgentTools(toolDeps);

  const controller = new AbortController();
  let abortReason: 'cancelled' | 'wall_clock' | 'stall' | null = null;
  const wallTimer = setTimeout(() => {
    abortReason = abortReason ?? 'wall_clock';
    controller.abort();
  }, WALL_CLOCK_MS);
  let lastProgress = 0;
  let lastNovel = 0;
  let stall = 0;
  let loopError: any = null;

  const prompt = buildBrief({
    fixType: input.fixType,
    finding: input.finding,
    summary: input.summary,
    findingBrief: input.findingBrief,
    projectName,
    projectSubdir: repoInfo.packageJsonPath ?? '',
    repoRootListing,
  });

  let replayedThrough: string | null = null;

  const onStepFinish = async (s: any) => {
    const text = stripReasoning(s?.text ?? '');
    if (text) await narrate(text);
    // Flush this step's queued tool rows AFTER its reasoning text, so the
    // narration reads "let me do X" → X (the tools ran before this callback).
    // Then flush pendingAfter (the PR-ready card) so it lands last.
    if (state.pendingSteps.length) {
      for (const st of state.pendingSteps.splice(0)) await narrateStep(supabase, input.threadId, st);
    }
    if (state.pendingAfter.length) {
      for (const fn of state.pendingAfter.splice(0)) await fn();
    }
    // Novelty-aware stall detection. Reading six NEW files (package.json →
    // grep → lockfile chunks for a transitive dep) is legitimate investigation,
    // not spinning — the detector exists for the old spin bug (repeating the
    // same failing call forever). A step counts toward the stall limit only
    // when it produced NOTHING new at all: no side-effecting call
    // (progressCalls) AND no first-time read/list/grep (novelCalls). MAX_STEPS
    // + the wall clock remain the hard backstops against endless wandering.
    if (state.progressCalls > lastProgress || state.novelCalls > lastNovel) {
      lastProgress = state.progressCalls;
      lastNovel = state.novelCalls;
      stall = 0;
    } else {
      stall++;
    }
    if (stall >= STALL_LIMIT && !state.terminal) {
      abortReason = abortReason ?? 'stall';
      controller.abort();
      return;
    }
    // Cancel: a cheap status read between steps — the row went 'rejected'
    // (user Stop) OR its machine_id no longer matches (a wake re-queued the
    // row and another machine claimed it; this run is a zombie and must stop).
    if (!state.terminal && (await isJobCancelled(supabase, input.fixId, machineId))) {
      abortReason = abortReason ?? 'cancelled';
      controller.abort();
    }
  };

  try {
    if (input.resume && input.threadId) {
      // Resume: replay the thread as conversation history. The brief seeds the
      // first user turn (it was never persisted to the thread). A replay
      // failure throws into this try — the run resolves as system_error rather
      // than silently resuming with no memory.
      const replay = await reconstructAgentMessages(supabase, input.threadId, { brief: prompt });
      replayedThrough = replay.replayedThrough;
      await generateText({
        model,
        system: buildResumeSystem(
          resumeMode ? { prNumber: resumeMode.prNumber } : null,
          input.resumePriorStatus === 'completed',
        ),
        messages: replay.messages,
        tools,
        stopWhen: [stepCountIs(MAX_STEPS), hasToolCall('finish_task')],
        abortSignal: controller.signal,
        onStepFinish,
      });
    } else {
      await generateText({
        model,
        system: AGENT_SYSTEM,
        prompt,
        tools,
        stopWhen: [stepCountIs(MAX_STEPS), hasToolCall('finish_task')],
        abortSignal: controller.signal,
        onStepFinish,
      });
    }
  } catch (e: any) {
    // An abort is expected (cancel / wall-clock / stall); anything else is a real error.
    if (!controller.signal.aborted) loopError = e;
  } finally {
    clearTimeout(wallTimer);
  }

  // Safety: flush any narration queued by the final step whose onStepFinish may
  // not have run (e.g. the PR step if the loop ended right after it).
  for (const st of state.pendingSteps.splice(0)) {
    await narrateStep(supabase, input.threadId, st).catch(() => {});
  }
  for (const fn of state.pendingAfter.splice(0)) {
    await fn().catch(() => {});
  }

  // Always-terminal guarantee: if a PR wasn't opened and finish_task wasn't
  // called, the row must not be left 'executing' (recovery would re-run the
  // whole agent). Resolve it honestly here.
  if (!state.terminal) {
    // An unexpected exception (model/provider/infra error) → system_error, so the
    // user sees a generic "something went wrong", not the raw provider message.
    // 'stall' and 'budget_exhausted' (= wall-clock only) each carry their own
    // safe copy in finalizeFailure — kept distinct because "budget" wording
    // reads as prepaid BILLING to a paying user.
    const category: 'cancelled' | 'stall' | 'budget_exhausted' | 'system_error' | 'not_fixable' =
      abortReason === 'cancelled'
        ? 'cancelled'
        : abortReason === 'stall'
          ? 'stall'
          : abortReason
            ? 'budget_exhausted'
            : loopError
              ? 'system_error'
              : 'not_fixable';
    const message =
      abortReason === 'cancelled'
        ? 'Task stopped by user.'
        : abortReason === 'wall_clock'
          ? `Reached the ${Math.round(WALL_CLOCK_MS / 1000)}s time budget before finishing.`
          : abortReason === 'stall'
            ? 'Stopped making progress and was halted.'
            : loopError
              ? loopError?.message ?? 'Unexpected error in the agent loop.'
              : "Couldn't complete a fix for this finding.";
    await finalizeFailure(toolDeps, category, message);
  }

  // The drain watermark: what this run actually replayed (null on a first run —
  // the caller falls back to approved_at). `cancelled` lets the caller SKIP the
  // end-of-run drain after a user Stop — Stop must win over a queued follow-up.
  return { replayedThrough, cancelled: abortReason === 'cancelled' };
}
