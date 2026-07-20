import { supabase } from '../supabase';

export type ChatErrorClass = {
  type: 'rate_limit' | 'transient' | 'cost_cap';
  statusCode?: number;
  message?: string;
};

export function classifyChatError(err: unknown): ChatErrorClass {
  const e = err as { statusCode?: number; lastError?: { statusCode?: number; message?: string }; message?: string; name?: string };
  const status = e?.statusCode ?? e?.lastError?.statusCode;
  if (status === 429) return { type: 'rate_limit', statusCode: 429 };
  if (e?.name === 'AbortError') return { type: 'transient', message: 'Stream cancelled' };
  return {
    type: 'transient',
    statusCode: typeof status === 'number' ? status : undefined,
    message: e?.message ?? e?.lastError?.message,
  };
}

export function chatErrorUserText(error: ChatErrorClass): string {
  if (error.type === 'cost_cap') return error.message ?? 'Monthly AI budget reached.';
  return 'Something went wrong while generating a response.';
}

// Persist a structured error assistant message so the chat UI can render an
// error bubble (with a Regenerate button for transient/rate_limit, or a
// settings link for cost_cap) instead of staring at silence.
export async function writeAegisChatError(threadId: string, error: ChatErrorClass): Promise<void> {
  const text = chatErrorUserText(error);
  try {
    await Promise.all([
      supabase.from('aegis_chat_messages').insert({
        thread_id: threadId,
        role: 'assistant',
        user_id: null,
        content: text,
        metadata: {
          parts: [{ type: 'text', text }],
          error: {
            type: error.type,
            statusCode: error.statusCode ?? null,
            message: error.message ?? null,
          },
        },
      }),
      supabase.from('aegis_chat_threads').update({ updated_at: new Date().toISOString() }).eq('id', threadId),
    ]);
  } catch (writeErr) {
    console.error('[aegis] failed to persist chat error', writeErr);
  }
}
