import type { ModelMessage } from 'ai';
import { supabase } from '../../lib/supabase';
import { addParticipant } from './participants';

export interface ThreadContext {
  type?: string;
  id?: string;
  projectId?: string;
}

export async function getOrCreateThread(
  organizationId: string,
  userId: string,
  threadId: string | undefined,
  message: string,
  context?: ThreadContext,
): Promise<string> {
  if (threadId) {
    // Client-provided id. Three possibilities:
    //   1. Row exists and belongs to this user  -> bump updated_at, return.
    //   2. Row exists but belongs to someone else -> reject (defense in depth).
    //   3. Row doesn't exist (client generated the UUID before first send so
    //      the threadId is known regardless of network outcomes) -> insert
    //      with that id.
    const { data: existing } = await supabase
      .from('aegis_chat_threads')
      .select('id, organization_id, user_id')
      .eq('id', threadId)
      .maybeSingle();

    if (existing) {
      if (existing.organization_id !== organizationId || existing.user_id !== userId) {
        throw new Error('thread_not_authorized');
      }
      await supabase
        .from('aegis_chat_threads')
        .update({ updated_at: new Date().toISOString() })
        .eq('id', threadId);
      return threadId;
    }

    // Sentinel placeholder. The route kicks off generateThreadTitle in
    // parallel with the model stream and overwrites this once the LLM picks
    // a real title. Keeping it 'New chat' (matching the frontend's optimistic
    // insert) lets the sidebar's "still waiting for title" poll detect the
    // pending state without ever flashing the raw user message as a title.
    const title = 'New chat';
    const { error: insertErr } = await supabase
      .from('aegis_chat_threads')
      .insert({
        id: threadId,
        organization_id: organizationId,
        user_id: userId,
        created_by: userId,
        title,
        project_id: context?.projectId || null,
        context_type: context?.type || null,
        context_id: context?.id || null,
      });
    if (insertErr) {
      console.error('[aegis] thread insert with client id failed', insertErr);
      throw new Error('thread_create_failed');
    }
    await addParticipant(threadId, userId);
    return threadId;
  }

  // Legacy path: no client id provided. Kept for any caller that still relies
  // on server-generated ids. The aegis chat route always provides one.
  const title = message.substring(0, 50) + (message.length > 50 ? '...' : '');
  const { data, error } = await supabase
    .from('aegis_chat_threads')
    .insert({
      organization_id: organizationId,
      user_id: userId,
      created_by: userId,
      title,
      project_id: context?.projectId || null,
      context_type: context?.type || null,
      context_id: context?.id || null,
    })
    .select('id')
    .single();

  if (error || !data) {
    console.error('[aegis] thread insert failed', error);
    throw new Error('thread_create_failed');
  }

  await addParticipant(data.id as string, userId);
  return data.id as string;
}

export async function loadThreadHistory(threadId: string): Promise<ModelMessage[]> {
  const { data: messages, error } = await supabase
    .from('aegis_chat_messages')
    .select('role, content, metadata')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true })
    .limit(50);

  if (error) {
    console.error('[aegis] Failed to load thread history:', error);
    return [];
  }
  if (!messages?.length) return [];

  const result: ModelMessage[] = [];
  for (const m of messages) {
    if (m.role === 'user') {
      result.push({ role: 'user', content: m.content });
    } else if (m.role === 'assistant') {
      // Persisted assistant errors carry only a generic user-facing string in
      // `content` (we never leak raw provider text to the chat). Without
      // metadata, the model that re-loads this thread sees "Something went
      // wrong" with no idea what failed and answers a follow-up "what went
      // wrong?" with "I don't know what you mean." Pull the structured error
      // out of metadata and inline it as an internal note the user never
      // sees but the model can reason from.
      const errorMeta = (m as { metadata?: { error?: { type?: string; statusCode?: number | null; message?: string | null } } })
        .metadata?.error;
      if (errorMeta) {
        const detail = [
          errorMeta.type ? `type=${errorMeta.type}` : null,
          errorMeta.statusCode ? `status=${errorMeta.statusCode}` : null,
          errorMeta.message ? `message=${errorMeta.message}` : null,
        ]
          .filter(Boolean)
          .join(', ');
        result.push({
          role: 'assistant',
          content:
            `${m.content}\n\n` +
            `[Internal context, not shown to user: my previous response failed (${detail || 'no detail'}). ` +
            `If the user now asks "what went wrong" / "why did that fail" / "keep going", explain the failure ` +
            `briefly in plain language (e.g. "I hit a rate limit", "the model dropped the connection"), do NOT ` +
            `surface raw error strings or status codes, and offer to retry the original request.]`,
        });
      } else {
        result.push({ role: 'assistant', content: m.content });
      }
    }
  }
  return result;
}
