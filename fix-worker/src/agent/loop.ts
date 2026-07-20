import { generateText, stepCountIs, hasToolCall } from 'ai';
import * as fsp from 'fs/promises';
import * as path from 'path';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { FindingType } from './../plan-types';
import { getOrgInstallationId, isJobCancelled, updateAgentRunStats } from './../job-db';
import { createInstallationToken } from './../github';
import { cloneAtSha, cloneBranchHead } from './../sandbox';
import { getPullRequestState } from './../pr';
import { resolveOrgModel } from './../llm';
import { captureInfraError } from './../observability/capture';
import { makeTaskNarrator, narrateStep } from './../task-chat';
import { FixLogger } from './../logger';
import { AGENT_SYSTEM, buildBrief, buildResumeSystem } from './brief';
import { reconstructAgentMessages } from './replay';
import {
  buildAgentTools,
  finalizeFailure,
  maybeFinalizeAnsweredNaturalStop,
  type AgentRunState,
  type AgentToolDeps,
} from './tools';

/** Wall-clock ceiling — an agent run bills by the second, so this bounds cost too.
 *  Configurable via AEGIS_TASK_WALL_CLOCK_SEC; default 30 min (a slower/cheaper
 *  model needs more room than a frontier one). */
const WALL_CLOCK_MS = (parseInt(process.env.AEGIS_TASK_WALL_CLOCK_SEC || '1800', 10) || 1800) * 1000;
/** Hard step cap PER compaction pass (mirrors the plan's ~40). Env-overridable
 *  (lower it to exercise the step-cap budget terminal in a test). */
const MAX_STEPS = parseInt(process.env.AEGIS_TASK_MAX_STEPS || '', 10) || 40;
/** Max auto-compaction cycles in a single run. A run that fills the window this
 *  many times is pathological (each compaction restarts from a bounded view);
 *  the wall clock is the real cost bound. Env-overridable for testing. */
const MAX_COMPACTIONS = parseInt(process.env.AEGIS_TASK_MAX_COMPACTIONS || '', 10) || 25;
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

/** Fraction of the model's context window at which a generateText pass ends
 *  cleanly so the loop can auto-compact and continue — before the provider
 *  hard-400s on an over-long prompt. */
const CONTEXT_SOFT_LIMIT = 0.9;

/** Strip any leaked chain-of-thought before narrating a model beat. */
function stripReasoning(text: string): string {
  return text.replace(/<think>[\s\S]*?<\/think>/gi, '').replace(/<\/?think>/gi, '').trim();
}

/** Collect every string an SDK error might hide the provider's reason in. The AI
 *  SDK's APICallError puts the human message in `.message` for some providers but
 *  leaves the real detail only in `.responseBody` (the raw provider JSON) for
 *  others (DeepInfra/openai-compatible), and reasons can nest under `.cause` /
 *  `.data`. Scanning just `.message` misses those, so we flatten them all. */
function errorText(e: any, depth = 0): string {
  if (e == null || depth > 3) return '';
  if (typeof e === 'string') return e;
  const parts: string[] = [];
  if (e.message) parts.push(String(e.message));
  if (e.responseBody) parts.push(String(e.responseBody));
  if (e.data != null) {
    try {
      parts.push(typeof e.data === 'string' ? e.data : JSON.stringify(e.data));
    } catch {
      /* non-serialisable data — skip */
    }
  }
  if (e.cause && e.cause !== e) parts.push(errorText(e.cause, depth + 1));
  return parts.join(' ');
}

/** A provider "prompt too long / context length exceeded" error — a DETERMINISTIC
 *  overflow (retrying reproduces it), distinct from a transient infra hiccup.
 *  Covers all four providers' phrasings: OpenAI/DeepInfra ("maximum context
 *  length", code context_length_exceeded), Anthropic ("prompt is too long"),
 *  and Gemini ("input token count (X) exceeds the maximum number of tokens") —
 *  the last of which the old message-only regex missed, misfiling a Gemini
 *  overflow as a generic system_error ("try again later" → user retries forever).
 *  Exported for direct classifier tests. */
export function isContextLengthError(e: any): boolean {
  const msg = errorText(e).toLowerCase();
  return /context length|context_length_exceeded|prompt is too long|maximum context|too many tokens|reduce the length|input is too long|input token count|token count[^.]*exceed|exceeds? the maximum number of tokens|exceeds? the maximum context|string too long/.test(
    msg,
  );
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
  const resolved = await resolveOrgModel(supabase, input.organizationId, process.env.AEGIS_TASK_MODEL || undefined);
  const model = resolved.model;
  // Effective context window: the model's real window, unless AEGIS_TASK_CONTEXT_WINDOW
  // overrides it (a knob to cap agent context for cost/predictability — and to
  // force the soft-stop in a test by setting it low). Feeds both the meter's
  // denominator and the 90% soft-limit.
  const windowOverride = parseInt(process.env.AEGIS_TASK_CONTEXT_WINDOW || '', 10);
  const contextWindow = Number.isFinite(windowOverride) && windowOverride > 0 ? windowOverride : resolved.contextWindow;

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
          // Amend mode also needs the BASE ref (origin/<base>) to compare
          // against or restore files from — a single-branch clone of the PR
          // branch alone blinded the lockfile heal into a churny regen.
          alsoFetchBranch: input.baseBranch,
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
  // Context-meter tracking. peakInputTokens = the largest prompt the model has
  // been sent this run (each step re-sends the whole accumulated history, so
  // this is "how full the window got"); persisted per step for the chat's
  // context bar + /status, and the trigger for the graceful soft-limit stop.
  let peakInputTokens = 0;
  let stepCount = 0;
  // Did the model produce ANY chat text this run? A resume that answers in
  // prose and stops without calling finish_task is an answer-only turn, not a
  // failure — see maybeFinalizeAnsweredNaturalStop.
  let narrated = false;

  const prompt = buildBrief({
    fixType: input.fixType,
    finding: input.finding,
    summary: input.summary,
    findingBrief: input.findingBrief,
    projectName,
    projectSubdir: repoInfo.packageJsonPath ?? '',
    repoRootListing,
  });

  // TEST-ONLY overflow lever (never set in normal operation): filler appended to
  // the FIRST pass's opening message so a fresh run overflows the window and the
  // loop must auto-compact. Deliberately NOT baked into `prompt` — the compaction
  // re-seeds the (small) brief, so keeping the pad out of it lets a test overflow
  // compact-then-continue instead of re-injecting the pad every cycle.
  const padTokens = parseInt(process.env.AEGIS_TASK_TEST_PAD_TOKENS || '', 10);
  const padSuffix =
    !input.resume && Number.isFinite(padTokens) && padTokens > 0
      ? `\n\n<!-- test-pad -->\n${'lorem ipsum dolor sit amet '.repeat(Math.ceil(padTokens / 5))}`
      : '';
  if (padSuffix) console.log(`[test] padding the first pass with ~${padTokens} filler tokens to force a context overflow`);

  let replayedThrough: string | null = null;

  const onStepFinish = async (s: any) => {
    const text = stripReasoning(s?.text ?? '');
    if (text) {
      narrated = true;
      await narrate(text);
    }
    // Flush this step's queued tool rows AFTER its reasoning text, so the
    // narration reads "let me do X" → X (the tools ran before this callback).
    // Then flush pendingAfter (the PR-ready card) so it lands last.
    if (state.pendingSteps.length) {
      for (const st of state.pendingSteps.splice(0)) await narrateStep(supabase, input.threadId, st);
    }
    if (state.pendingAfter.length) {
      for (const fn of state.pendingAfter.splice(0)) await fn();
    }

    // Context meter: the step's usage carries the prompt (input) tokens for
    // THIS step = the full accumulated history at this point. Track the peak +
    // persist it (best-effort) so the task chat can render a live context bar.
    stepCount++;
    const stepUsage: any = s?.usage ?? {};
    const inTok: number = stepUsage.inputTokens ?? stepUsage.promptTokens ?? 0;
    if (inTok > peakInputTokens) peakInputTokens = inTok;
    await updateAgentRunStats(
      supabase,
      input.fixId,
      { inputTokens: peakInputTokens, window: contextWindow, step: stepCount },
      machineId,
    );
    // NOTE: the context-window limit is NOT handled here anymore. Instead of
    // aborting the run when the window fills, the outer loop auto-compacts and
    // continues (see the compaction loop below) — so a task never terminates on
    // context; it summarizes and keeps going. The `contextHigh` stopWhen cleanly
    // ends a generateText pass at the soft limit so the loop can compact.

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

  // A generateText pass ends cleanly (no abort) once a step's prompt crosses the
  // soft limit, so the outer loop can compact and continue instead of the run
  // dying on a full window.
  const contextHigh = ({ steps }: { steps: any[] }): boolean => {
    const inTok = steps[steps.length - 1]?.usage?.inputTokens ?? 0;
    return contextWindow > 0 && inTok > contextWindow * CONTEXT_SOFT_LIMIT;
  };

  // Build the starting conversation. A fresh run seeds the brief as the first
  // user turn; a resume replays the (already bounded) thread history.
  let system = AGENT_SYSTEM;
  let messages: any[];
  if (input.resume && input.threadId) {
    // A replay failure throws → system_error, rather than silently resuming with
    // no memory.
    const replay = await reconstructAgentMessages(supabase, input.threadId, { brief: prompt });
    replayedThrough = replay.replayedThrough;
    messages = replay.messages;
    system = buildResumeSystem(
      resumeMode ? { prNumber: resumeMode.prNumber } : null,
      input.resumePriorStatus === 'completed',
      input.baseBranch,
    );
  } else {
    // padSuffix is '' in normal operation; only a test overflow appends filler.
    messages = [{ role: 'user', content: prompt + padSuffix }];
  }

  // Auto-compaction loop: the run keeps going across context-window refills. A
  // pass fills the window → post a "Context compacted" beat, rebuild a bounded
  // view of the conversation (recent work kept, old history dropped — the same
  // compaction the resume path uses), and run again. The task only ever ends on
  // finish_task / cancel / time budget — never on context.
  let compactions = 0;
  // Steps taken by the FINAL generateText pass (the step cap is per-pass, whereas
  // the global stepCount spans all passes), and whether the run ended because the
  // window filled but no compactions were left.
  let lastPassSteps = 0;
  let compactionsExhausted = false;
  try {
    while (true) {
      let filledContext = false;
      try {
        const result = await generateText({
          model,
          system,
          messages,
          tools,
          stopWhen: [stepCountIs(MAX_STEPS), hasToolCall('finish_task'), contextHigh],
          abortSignal: controller.signal,
          onStepFinish,
        });
        lastPassSteps = result.steps?.length ?? 0;
        messages = [...messages, ...((result.response?.messages as any[]) ?? [])];
        const lastIn = result.steps?.[result.steps.length - 1]?.usage?.inputTokens ?? 0;
        filledContext = !state.terminal && contextWindow > 0 && lastIn > contextWindow * CONTEXT_SOFT_LIMIT;
      } catch (e: any) {
        // cancel / wall-clock / stall aborts rethrow to the outer handler. A
        // provider hard-400 that slipped past the soft stop is ALSO "context
        // filled" — compact and continue rather than die.
        if (controller.signal.aborted) throw e;
        if (isContextLengthError(e) && input.threadId && compactions < MAX_COMPACTIONS) {
          filledContext = true;
        } else {
          throw e;
        }
      }

      if (state.terminal) break; // finish_task opened a PR / answered
      if (filledContext && input.threadId && compactions < MAX_COMPACTIONS) {
        compactions++;
        await narrateStep(supabase, input.threadId, { icon: 'compact', label: 'Context compacted' });
        // The bounded rebuild from the thread's persisted beats IS the compacted
        // "summary" the model continues from.
        const compacted = await reconstructAgentMessages(supabase, input.threadId, { brief: prompt });
        messages = compacted.messages;
        system = buildResumeSystem(
          resumeMode ? { prNumber: resumeMode.prNumber } : null,
          input.resumePriorStatus === 'completed',
          input.baseBranch,
        );
        peakInputTokens = 0; // reset the meter for the next pass
        lastPassSteps = 0; // the next pass starts fresh; don't misread as a step cap
        continue;
      }
      if (filledContext) compactionsExhausted = true; // filled but out of compactions
      break; // natural stop / step cap / compactions exhausted
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

  // Did the run END by hitting the step cap (stopWhen: stepCountIs(MAX_STEPS))?
  // That's indistinguishable from a natural stop otherwise — no abort, no error
  // — so without this it would be misread as not_fixable (first run) or, worse,
  // as a successful answer-only turn (resume). It's really "ran out of room in
  // one pass": a resumable budget exhaustion.
  const hitStepCap = !state.terminal && !abortReason && !loopError && lastPassSteps >= MAX_STEPS;

  // A clean natural stop (no abort, no error, NOT a step-cap / compaction-exhausted
  // cutoff) on a resume whose fix already stands, where the model answered in
  // prose, IS an answer-only turn — resolve it as answered BEFORE the failure
  // fallback so a good answer isn't stamped "I couldn't complete that follow-up"
  // (the PR #16 wake bug). A dirty tree, an abort/error, or a budget cutoff falls
  // through to the honest failure path below.
  if (!state.terminal && !abortReason && !loopError && !hitStepCap && !compactionsExhausted) {
    await maybeFinalizeAnsweredNaturalStop(toolDeps, narrated);
  }

  // Context overflow is no longer a terminal state — the loop auto-compacts. The
  // only ways a context limit reaches here are pathological: exhausting
  // MAX_COMPACTIONS on a clean soft-stop (compactionsExhausted) or a hard-400
  // after the last allowed compaction (a context-length loopError). Both resolve
  // as a resumable "needs another run"; never page Sentry for them.
  const contextEscaped = (!!loopError && isContextLengthError(loopError)) || compactionsExhausted;
  if (loopError && !contextEscaped) {
    captureInfraError(loopError, 'aegis-task-loop', { fixId: input.fixId, taskId: input.taskId });
  }

  // Always-terminal guarantee: if a PR wasn't opened and finish_task wasn't
  // called, the row must not be left 'executing' (recovery would re-run the
  // whole agent). Resolve it honestly here.
  if (!state.terminal) {
    // An unexpected exception (model/provider/infra error) → system_error, so the
    // user sees a generic "something went wrong", not the raw provider message.
    // 'stall' / 'budget_exhausted' (= wall-clock / step-cap / compaction-exhausted)
    // each carry their own safe copy in finalizeFailure — "budget" wording is kept
    // out of the user copy (it reads as prepaid BILLING to a paying user).
    const category: 'cancelled' | 'stall' | 'budget_exhausted' | 'system_error' | 'not_fixable' =
      abortReason === 'cancelled'
        ? 'cancelled'
        : abortReason === 'stall'
          ? 'stall'
          : abortReason || hitStepCap || contextEscaped
            ? 'budget_exhausted'
            : loopError
              ? 'system_error'
              : 'not_fixable';
    const message =
      abortReason === 'cancelled'
        ? 'Task stopped by user.'
        : contextEscaped
          ? 'Reached the context-window limit after repeated compaction.'
          : hitStepCap
            ? `Reached the ${MAX_STEPS}-step limit before finishing.`
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
