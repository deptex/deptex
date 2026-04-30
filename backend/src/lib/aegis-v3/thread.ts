import type { ModelMessage } from 'ai';
import { supabase } from '../../lib/supabase';

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
    await supabase
      .from('aegis_chat_threads')
      .update({ updated_at: new Date().toISOString() })
      .eq('id', threadId);
    return threadId;
  }

  const title = message.substring(0, 50) + (message.length > 50 ? '...' : '');
  const { data, error } = await supabase
    .from('aegis_chat_threads')
    .insert({
      organization_id: organizationId,
      user_id: userId,
      title,
      project_id: context?.projectId || null,
      context_type: context?.type || null,
      context_id: context?.id || null,
    })
    .select('id')
    .single();

  if (error || !data) {
    throw new Error(`Failed to create chat thread: ${error?.message ?? 'unknown error'}`);
  }

  return data.id as string;
}

export async function loadThreadHistory(threadId: string): Promise<ModelMessage[]> {
  const { data: messages, error } = await supabase
    .from('aegis_chat_messages')
    .select('role, content')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true })
    .limit(50);

  if (error) {
    console.error('[aegis-v3] Failed to load thread history:', error);
    return [];
  }
  if (!messages?.length) return [];

  const result: ModelMessage[] = [];
  for (const m of messages) {
    if (m.role === 'user') {
      result.push({ role: 'user', content: m.content });
    } else if (m.role === 'assistant') {
      result.push({ role: 'assistant', content: m.content });
    }
  }
  return result;
}
