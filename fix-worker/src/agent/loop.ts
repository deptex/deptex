import { generateText, stepCountIs, hasToolCall } from 'ai';
import * as fsp from 'fs/promises';
import * as path from 'path';
import type { SupabaseClient } from '@supabase/supabase-js';
import type { FindingType } from './../plan-types';
import { getOrgInstallationId, isJobCancelled } from './../job-db';
import { createInstallationToken } from './../github';
import { cloneAtSha } from './../sandbox';
import { getLanguageModelForOrg } from './../llm';
import { makeTaskNarrator, narrateStep } from './../task-chat';
import { FixLogger } from './../logger';
import { AGENT_SYSTEM, buildBrief } from './brief';
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
): Promise<void> {
  const { machineId, projectName, logger, workDir } = deps;
  const narrate = makeTaskNarrator(supabase, input.threadId);

  const repoInfo = await getOrgInstallationId(supabase, input.organizationId, input.projectId);
  if (!repoInfo) throw new Error('Project no longer has a GitHub App installation');
  const installationToken = await createInstallationToken(repoInfo.installationId);
  const model = await getLanguageModelForOrg(supabase, input.organizationId, process.env.AEGIS_TASK_MODEL || undefined);

  // Clone the repo up front — this is infrastructure setup, not a step the user
  // needs to watch, so it isn't narrated. The agent's first visible beat is its
  // own investigation.
  await cloneAtSha({
    workDir,
    installationToken,
    repoFullName: repoInfo.repoFullName,
    branch: input.baseBranch,
    baseSha: input.baseSha,
    logger,
  });

  const projectDir = repoInfo.packageJsonPath ? path.join(workDir, repoInfo.packageJsonPath) : workDir;
  // Seed the brief with the PROJECT dir listing (the agent's tools + shell are
  // rooted there), not the repo root — so its first paths land in the right place.
  const repoRootListing = await safeList(projectDir);

  const state: AgentRunState = {
    prOpened: false,
    terminal: false,
    progressCalls: 0,
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
  };
  const tools = buildAgentTools(toolDeps);

  const controller = new AbortController();
  let abortReason: 'cancelled' | 'wall_clock' | 'stall' | null = null;
  const wallTimer = setTimeout(() => {
    abortReason = abortReason ?? 'wall_clock';
    controller.abort();
  }, WALL_CLOCK_MS);
  let lastProgress = 0;
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

  try {
    await generateText({
      model,
      system: AGENT_SYSTEM,
      prompt,
      tools,
      stopWhen: [stepCountIs(MAX_STEPS), hasToolCall('finish_task')],
      abortSignal: controller.signal,
      onStepFinish: async (s: any) => {
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
        // Stall detection: a step that made no write/command/PR call counts toward
        // the limit; a read-only spin trips it well before the 40-step cap.
        if (state.progressCalls > lastProgress) {
          lastProgress = state.progressCalls;
          stall = 0;
        } else {
          stall++;
        }
        if (stall >= STALL_LIMIT && !state.terminal) {
          abortReason = abortReason ?? 'stall';
          controller.abort();
          return;
        }
        // Cancel: a cheap status read between steps (the row goes 'rejected').
        if (!state.terminal && (await isJobCancelled(supabase, input.fixId))) {
          abortReason = abortReason ?? 'cancelled';
          controller.abort();
        }
      },
    });
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
    // Budget/stall/no-PR use our own safe copy.
    const category: 'cancelled' | 'budget_exhausted' | 'system_error' | 'not_fixable' =
      abortReason === 'cancelled'
        ? 'cancelled'
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
}
