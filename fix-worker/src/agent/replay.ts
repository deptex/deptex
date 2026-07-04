// Reconstructs a task thread as the agent's own conversation history for a
// resume run. The thread's rows were written for the CHAT UI (prose beats,
// step rows, PR/failure cards); here they're folded back into compact
// user/assistant turns so the model re-reads its earlier work before acting
// on the user's latest instruction.

import type { SupabaseClient } from '@supabase/supabase-js';

export interface ReplayMessage {
  role: 'user' | 'assistant';
  content: string;
}

const OMISSION_MARKER = '[… earlier work omitted …]';

/**
 * Fetch + fold the thread into model messages.
 *
 * - The finding brief is prepended as the FIRST user turn (it was never
 *   persisted to the thread — the first run consumed it as `prompt`).
 * - `replayedThrough` is the max created_at actually replayed: the end-of-run
 *   drain uses it as the "seen" watermark, so a message that lands in the
 *   claim→read window is never stranded OR double-run.
 * - Errors THROW: the loop's existing catch resolves the run as system_error —
 *   simpler and more honest than silently resuming with no memory.
 */
export async function reconstructAgentMessages(
  supabase: SupabaseClient,
  threadId: string,
  opts: { brief: string; charBudget?: number },
): Promise<{ messages: ReplayMessage[]; replayedThrough: string | null }> {
  // Fetch NEWEST-first with an explicit cap, then reverse into chronological
  // order. An unbounded ascending select gets silently truncated by
  // PostgREST's row cap (default 1000) keeping only the OLDEST rows — which
  // would make replayedThrough stale, so the end-of-run drain would see the
  // latest user message as "unseen" and re-wake FOREVER, billing a run each
  // time. Newest-first guarantees the true watermark (and the most recent
  // turns, which matter most) are always inside the window.
  const { data, error } = await supabase
    .from('aegis_chat_messages')
    .select('role, content, metadata, created_at')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: false })
    .limit(1000);
  if (error) throw new Error(`replay fetch failed: ${error.message}`);

  const rows = ((data ?? []) as Array<{
    role: string;
    content: string | null;
    metadata: { parts?: Array<Record<string, any>> } | null;
    created_at: string;
  }>)
    .slice()
    .reverse();

  const mapped: ReplayMessage[] = [];
  for (const row of rows) {
    const content = (row.content ?? '').trim();
    if (row.role === 'user') {
      if (content) mapped.push({ role: 'user', content });
      continue;
    }
    if (row.role !== 'assistant') continue;
    const parts = row.metadata?.parts;
    if (Array.isArray(parts) && parts.length) {
      for (const part of parts) {
        if (part?.type === 'text' && typeof part.text === 'string' && part.text.trim()) {
          mapped.push({ role: 'assistant', content: part.text.trim() });
        } else if (part?.type === 'step') {
          // Compact single line: icon + label (+ command). Diff/output bodies
          // are deliberately omitted — in amend mode the checked-out branch
          // already carries the code, and the bodies would blow the budget.
          const label = String(part.label ?? '').trim();
          if (!label) continue;
          const cmd = String(part.command ?? '').trim();
          mapped.push({
            role: 'assistant',
            content: `[${part.icon ?? 'step'}] ${label}${cmd ? ` — $ ${cmd}` : ''}`,
          });
        } else if (part?.type === 'tool-result') {
          // The PR-ready card vs the failure card — replaying a failure as a
          // PR card would gaslight the model into believing a PR exists.
          mapped.push({
            role: 'assistant',
            content:
              part.result?.failed === true
                ? '[showed the failure card to the user]'
                : '[showed the pull request change card to the user]',
          });
        }
      }
    } else if (content) {
      mapped.push({ role: 'assistant', content });
    }
  }

  const replayedThrough = rows.length ? rows[rows.length - 1].created_at : null;

  const parsedBudget = parseInt(process.env.AEGIS_TASK_REPLAY_CHAR_BUDGET || '40000', 10);
  const charBudget = opts.charBudget ?? (Number.isFinite(parsedBudget) ? parsedBudget : 40000);

  const brief: ReplayMessage = { role: 'user', content: opts.brief };
  const total = brief.content.length + mapped.reduce((n, m) => n + m.content.length, 0);
  let messages: ReplayMessage[];
  if (total <= charBudget || mapped.length === 0) {
    messages = [brief, ...mapped];
  } else {
    // Over budget: ALWAYS keep the brief, then as many TAIL messages as fit,
    // with one omission marker at the gap. If a dropped message named the PR,
    // re-inject one synthetic line so the model still knows the PR exists.
    const allowed = charBudget - brief.content.length;
    const tail: ReplayMessage[] = [];
    let used = 0;
    for (let i = mapped.length - 1; i >= 0; i--) {
      const len = mapped[i].content.length;
      // Always keep at least the final message, even if it alone overflows.
      if (tail.length > 0 && used + len > allowed) break;
      tail.unshift(mapped[i]);
      used += len;
    }
    const dropped = mapped.slice(0, mapped.length - tail.length);
    const inject: ReplayMessage[] = [{ role: 'assistant', content: OMISSION_MARKER }];
    for (const m of dropped) {
      const match = m.content.match(/pull request #(\d+)/);
      if (match) {
        inject.push({ role: 'assistant', content: `[earlier: opened pull request #${match[1]}]` });
        break;
      }
    }
    messages = [brief, ...inject, ...tail];
  }

  // generateText must end on a user turn.
  if (messages[messages.length - 1].role !== 'user') {
    messages.push({ role: 'user', content: '(Continue with my latest request above.)' });
  }

  return { messages, replayedThrough };
}
