import { generateText, type LanguageModel } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';

const VOICE_SYSTEM = `You are Aegis, an autonomous security engineer, narrating your OWN work out loud in a task chat as you do it. Speak in the FIRST PERSON, exactly ONE short natural sentence (max ~16 words), conversational — like a senior engineer thinking out loud while they work. No markdown, no lists, no surrounding quotes. Refer to the project by name.

Base your sentence ONLY on the facts you are given (what you just did, and the stated next step). Do NOT invent steps you weren't told about — NEVER claim you'll run a test suite, a build, lint, or a deploy unless that is the stated next step. Don't just restate the step verbatim. Vary how you open — do NOT start with "Alright", "Okay", "Got it", "Now", or "Let me". Never mention being an AI, a model, or a "worker".`;

/**
 * Generate one short first-person voice line for the live narration. Best-effort:
 * returns null on any failure so narration never blocks (or fails) the fix.
 */
export function stripReasoning(raw: string): string | null {
  // Reasoning models (DeepSeek etc.) emit <think>…</think> before the answer.
  // Keep only what follows the LAST </think>; if the block never closed (the
  // answer got truncated inside the reasoning), there's no usable line — skip it
  // rather than post chain-of-thought into the chat.
  let s = raw ?? '';
  const close = s.lastIndexOf('</think>');
  if (close !== -1) {
    s = s.slice(close + '</think>'.length);
  } else if (/<think>/i.test(s)) {
    return null;
  }
  s = s.replace(/<\/?think>/gi, '').trim();
  // First non-empty line only, quotes stripped.
  s = (s.split('\n').map((l) => l.trim()).find(Boolean) ?? '').replace(/^["']+|["']+$/g, '').trim();
  return s || null;
}

export async function generateVoiceLine(
  model: LanguageModel,
  context: string,
): Promise<string | null> {
  try {
    const { text } = await generateText({
      model,
      system: VOICE_SYSTEM,
      prompt: context,
      // Enough room for a reasoning model to think AND still emit the one-line
      // answer after </think>; stripReasoning discards the think block.
      maxOutputTokens: 400,
    });
    return stripReasoning(text ?? '');
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Task-chat narration from the fix-worker.
//
// When a fix belongs to an Aegis task (the row carries a thread_id), the worker
// IS the agent doing the work — so it narrates its OWN real steps (cloning,
// editing, verifying, opening the PR) straight into the task's chat thread, in
// the first person. The thread realtime-subscribes to aegis_chat_messages, so
// each beat lands live as the step happens. Everything here no-ops when there is
// no thread_id (a standalone fix, not a task), so the normal fix path is
// untouched.
// ---------------------------------------------------------------------------

export type Narrator = (text: string) => Promise<void>;

// A discrete tool-use step the chat renders as a gray icon + label line (past
// tense — the action is done), distinct from the first-person prose beats. The
// `icon` is a semantic key the frontend maps to a lucide glyph.
export type StepIcon = 'clone' | 'explore' | 'read' | 'search' | 'edit' | 'verify' | 'pr' | 'compact' | 'failed' | 'error' | 'tired';
export interface TaskStep {
  icon: StepIcon;
  label: string;
  // The literal shell command this step ran, when it maps to one (git clone,
  // npm install, git push). The chat renders it as a terminal card — the step
  // label as the title, then `$ command` and its output. Omitted for steps that
  // aren't a shell command (an in-process file edit, the explore loop).
  command?: string;
  // The captured terminal output of `command` (stdout/stderr, trimmed + capped).
  // Shown under the command line in the terminal card. Optional — a card with no
  // output just shows the command.
  output?: string;
  // The udiff this step produced, when it edited files (the `edit` step). The
  // chat renders it as an expandable colored diff under the label ("Edited
  // package.json" → the change). Omitted for non-edit steps.
  diff?: string;
}

/**
 * Post a completed tool-use step into the task chat. Renders as a gray line
 * ("✓ Cloned the repository") rather than prose, so the work reads as a sequence
 * of actions the agent actually performed. content mirrors the label so the
 * message is never empty; the frontend renders the `step` part, not the content.
 */
export async function narrateStep(
  supabase: SupabaseClient,
  threadId: string | null | undefined,
  step: TaskStep,
): Promise<void> {
  if (!threadId) return;
  const label = (step.label ?? '').trim();
  if (!label) return;
  const command = step.command?.trim() || undefined;
  const diff = step.diff?.trim() || undefined;
  const output = step.output?.trim() || undefined;
  const { error } = await supabase.from('aegis_chat_messages').insert({
    thread_id: threadId,
    role: 'assistant',
    content: label,
    metadata: { parts: [{ type: 'step', icon: step.icon, label, command, diff, output, status: 'done' }] },
  });
  if (error) console.warn('[FIX] task step failed:', error.message);
}

/** A first-person beat into the task chat. No-op without a thread. */
export function makeTaskNarrator(
  supabase: SupabaseClient,
  threadId: string | null | undefined,
): Narrator {
  return async (text: string) => {
    if (!threadId) return;
    const trimmed = (text ?? '').trim();
    if (!trimmed) return;
    const { error } = await supabase.from('aegis_chat_messages').insert({
      thread_id: threadId,
      role: 'assistant',
      content: trimmed,
      metadata: { parts: [{ type: 'text', text: trimmed }] },
    });
    if (error) console.warn('[FIX] task narrate failed:', error.message);
  };
}

/**
 * Post the final "Ready for review" card into the task chat. Shaped exactly like
 * the persisted apply_fix tool-result so the frontend rehydrates it into the
 * ChangeCard, which subscribes to the fix row by id and shows the live PR. Posted
 * AFTER the step beats so the chat reads top-to-bottom: reason → steps → PR card.
 */
export async function postPrReadyCard(
  supabase: SupabaseClient,
  threadId: string | null | undefined,
  fixId: string,
): Promise<void> {
  if (!threadId) return;
  // content doubles as the caption line above the card (the chat rehydrates a
  // card message with no text part by surfacing its content) — so make it a
  // natural closing beat rather than something that duplicates the card header.
  const { error } = await supabase.from('aegis_chat_messages').insert({
    thread_id: threadId,
    role: 'assistant',
    content: "The pull request is up — here's the change for your review.",
    metadata: {
      parts: [
        { type: 'tool-result', toolCallId: fixId, toolName: 'apply_fix', result: { fixId }, isError: false },
      ],
    },
  });
  if (error) console.warn('[FIX] pr-ready card post failed:', error.message);
}

export interface FailureCopy {
  headline: string; // failure-card title
  explanation: string; // 1-2 honest sentences: what happened
  nextStep: string; // what the user can do from here
  leadIn: string; // first-person chat beat, posted just before the card
  stepLabel: string; // the gray failed-step line
}

// Turn a failure category + message into honest, specific, first-person copy —
// never a blanket "I couldn't finish this safely". The category is already set
// at every throw site (FixPipelineError.category).
export function describeFailure(
  category: string | undefined,
  message: string,
  ctx: { primaryFile?: string },
): FailureCopy {
  const file =
    ctx.primaryFile && ctx.primaryFile !== 'the affected file' ? ctx.primaryFile : null;
  const inFile = file ? ` in \`${file}\`` : '';
  switch (category) {
    case 'patch_unapplied':
      return {
        headline: "I couldn't get the change to apply cleanly",
        explanation: `I worked out the fix, but my edit${file ? ` to \`${file}\`` : ''} didn't line up with the file and wouldn't apply after a couple of retries.`,
        nextStep: `The change I was trying to make is below — it likely needs a hand${inFile}.`,
        leadIn: `I worked out the change, but my patch wouldn't apply cleanly to ${file ?? 'the file'} — here's exactly what I tried.`,
        stepLabel: "Couldn't apply the change",
      };
    case 'tests_failed':
      return {
        headline: "The change didn't pass the checks",
        explanation: `I applied a fix${file ? ` to \`${file}\`` : ''}, but the checks still failed. The exact output is below.`,
        nextStep: `The diff I made and the failing output are below — the fix probably needs a small adjustment.`,
        leadIn: `I applied the change, but the checks came back failing — let me show you what I changed and what broke.`,
        stepLabel: 'Checks failed',
      };
    case 'diff_too_large':
      return {
        headline: 'This fix is too big to do safely',
        explanation: `The change grew past the size cap I'm allowed to make in a single automated fix.`,
        nextStep: `It should be split into smaller changes, or handled by hand.`,
        leadIn: `This one grew bigger than I can safely land in a single automated fix.`,
        stepLabel: 'Change too large',
      };
    case 'budget_wall_clock':
    case 'budget_tool_calls':
      return {
        headline: 'I ran out of room working through this',
        explanation: `This fix needed more exploration or retries than a single automated attempt allows.`,
        nextStep: `Re-running it may get further, or it may need a hand — what I got to is below.`,
        leadIn: `I ran out of budget partway through this one — here's where I got to.`,
        stepLabel: 'Ran out of budget',
      };
    case 'not_fixable':
      // message is already the specific reason (no patched version, shell-required
      // base image, configured registry image, …).
      return {
        headline: "This one can't be fixed automatically",
        explanation: message,
        nextStep: `It needs a human decision — see the reason above.`,
        leadIn: `I looked at this one and it can't be fixed automatically — ${message}`,
        stepLabel: "Can't fix automatically",
      };
    case 'unsupported_language':
      return {
        headline: "I can't fix this language here yet",
        explanation: message,
        nextStep: `This language isn't enabled on the fix agent yet.`,
        leadIn: message,
        stepLabel: 'Language not supported',
      };
    case 'project_dir_missing':
      return {
        headline: "I couldn't find the project in the repo",
        explanation: message,
        nextStep: `Check the project's configured subdirectory.`,
        leadIn: `I couldn't find the project directory in the repository, so I had to stop.`,
        stepLabel: 'Project directory missing',
      };
    default:
      return {
        headline: "I couldn't complete this fix",
        explanation: message,
        nextStep: `Here's what I tried and where it stopped.`,
        leadIn: `I couldn't complete this one — here's what happened.`,
        stepLabel: "Couldn't complete the fix",
      };
  }
}

/** The project's display name, for narrating by name instead of by id. */
export async function getProjectName(supabase: SupabaseClient, projectId: string): Promise<string> {
  const { data } = await supabase.from('projects').select('name').eq('id', projectId).maybeSingle();
  return ((data?.name as string | undefined) || '').trim() || 'the project';
}

/**
 * Carry the fix's terminal state onto its parent task. The task agent loop hands
 * off to the fix pipeline and stops; the pipeline (here) owns the task's final
 * status — completed when the PR opens, failed when the fix can't land. No-op
 * for a standalone fix (no task_id).
 */
export async function markTaskFromFix(
  supabase: SupabaseClient,
  taskId: string | null | undefined,
  patch: { status: 'completed' | 'failed'; summary?: string },
): Promise<void> {
  if (!taskId) return;
  // For a MULTI-target task the DB rollup trigger (recompute_aegis_task_status)
  // is the SINGLE source of truth for status/completed_at — it counts every
  // sibling fix. Writing status from one fix's single-fix view races it: it can
  // stamp the task 'completed' while a sibling still runs, or stomp a
  // 'completed_with_failures' back to 'failed' when the last fix happens to fail
  // after earlier ones succeeded. So on a multi-fix task we write ONLY the
  // summary and let the trigger own status. A single-fix task (the common case)
  // keeps the explicit write — it agrees with the trigger and gives immediacy.
  const { count } = await supabase
    .from('project_security_fixes')
    .select('id', { count: 'exact', head: true })
    .eq('task_id', taskId)
    .eq('strategy', 'agent');
  const multi = (count ?? 0) > 1;
  const update: Record<string, unknown> = {};
  if (!multi) {
    update.status = patch.status;
    if (patch.status === 'completed') update.completed_at = new Date().toISOString();
  }
  if (patch.summary) update.summary = patch.summary;
  if (Object.keys(update).length === 0) return;
  const { error } = await supabase.from('aegis_agent_tasks').update(update).eq('id', taskId);
  if (error) console.warn('[FIX] task status update failed:', error.message);
}
