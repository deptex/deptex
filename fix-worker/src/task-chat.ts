import type { SupabaseClient } from '@supabase/supabase-js';

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
export type StepIcon = 'clone' | 'edit' | 'verify' | 'pr';
export interface TaskStep {
  icon: StepIcon;
  label: string;
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
  const { error } = await supabase.from('aegis_chat_messages').insert({
    thread_id: threadId,
    role: 'assistant',
    content: label,
    metadata: { parts: [{ type: 'step', icon: step.icon, label, status: 'done' }] },
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
  const update: Record<string, unknown> = { status: patch.status };
  if (patch.status === 'completed') update.completed_at = new Date().toISOString();
  if (patch.summary) update.summary = patch.summary;
  const { error } = await supabase.from('aegis_agent_tasks').update(update).eq('id', taskId);
  if (error) console.warn('[FIX] task status update failed:', error.message);
}
