import { supabase } from '../../lib/supabase';
import { logAIUsage } from '../ai/logging';
import { getProviderInfoForOrg } from './provider';

export interface SaveAssistantMessageOptions {
  threadId: string;
  userMessage: string;
  assistantText: string;
  steps: number;
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
}

export interface SaveToolExecutionOptions {
  organizationId: string;
  userId: string;
  threadId: string;
  toolName: string;
  toolCategory: string;
  permissionLevel: 'safe' | 'moderate' | 'dangerous';
  parameters: unknown;
  result: unknown;
  success: boolean;
  durationMs: number;
  tokensUsed: number;
}

export async function saveAssistantMessage(opts: SaveAssistantMessageOptions): Promise<void> {
  const { threadId, userMessage, assistantText, steps, totalTokens } = opts;

  try {
    await supabase.from('aegis_chat_messages').insert([
      { thread_id: threadId, role: 'user', content: userMessage },
      {
        thread_id: threadId,
        role: 'assistant',
        content: assistantText || 'No response generated.',
        metadata: { steps, tokens: totalTokens },
      },
    ]);

    if (totalTokens > 0) {
      const { data: thread } = await supabase
        .from('aegis_chat_threads')
        .select('total_tokens_used')
        .eq('id', threadId)
        .single();

      await supabase
        .from('aegis_chat_threads')
        .update({
          total_tokens_used: (thread?.total_tokens_used || 0) + totalTokens,
          updated_at: new Date().toISOString(),
        })
        .eq('id', threadId);
    }
  } catch (err) {
    console.error('[aegis-v3] Failed to save assistant message:', err);
  }
}

export async function logChatUsage(params: {
  organizationId: string;
  userId: string;
  promptTokens: number;
  completionTokens: number;
  contextType?: string;
  contextId?: string;
  durationMs?: number;
}): Promise<void> {
  try {
    const providerInfo = await getProviderInfoForOrg(params.organizationId);
    await logAIUsage({
      organizationId: params.organizationId,
      userId: params.userId,
      feature: 'aegis_chat_v3',
      tier: 'byok',
      provider: providerInfo?.provider || 'unknown',
      model: providerInfo?.model || 'unknown',
      inputTokens: params.promptTokens,
      outputTokens: params.completionTokens,
      contextType: params.contextType,
      contextId: params.contextId,
      durationMs: params.durationMs ?? 0,
      success: true,
    });
  } catch {
    // Logging failures should not break the chat response.
  }
}

export async function saveToolExecution(opts: SaveToolExecutionOptions): Promise<void> {
  try {
    await supabase.from('aegis_tool_executions').insert({
      organization_id: opts.organizationId,
      user_id: opts.userId,
      thread_id: opts.threadId,
      tool_name: opts.toolName,
      tool_category: opts.toolCategory,
      parameters: opts.parameters,
      result: opts.result,
      success: opts.success,
      permission_level: opts.permissionLevel,
      duration_ms: opts.durationMs,
      tokens_used: opts.tokensUsed,
    });
  } catch (err) {
    console.error('[aegis-v3] Failed to save tool execution:', err);
  }
}
