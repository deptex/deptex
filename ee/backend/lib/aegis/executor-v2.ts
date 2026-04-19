import { streamText, CoreMessage } from 'ai';
import { getLanguageModelForOrg, getProviderInfoForOrg } from './llm-provider';
import { buildToolSet, ToolContext } from './tools';
import { supabase } from '../../../../backend/src/lib/supabase';
import { buildAgentSystemPrompt } from './system-prompt-v2';

export interface AegisStreamConfig {
  organizationId: string;
  userId: string;
  threadId?: string;
  message: string;
  context?: {
    type?: string;
    id?: string;
    projectId?: string;
  };
}

export interface AegisStreamResult {
  threadId: string;
  dataStream: ReturnType<Awaited<ReturnType<typeof streamText>>['toDataStreamResponse']>;
}

async function getOrgSettings(organizationId: string) {
  const { data } = await supabase
    .from('aegis_org_settings')
    .select('*')
    .eq('organization_id', organizationId)
    .single();

  return data || {
    operating_mode: 'propose',
    monthly_budget: null,
    daily_budget: null,
    per_task_budget: 25,
    tool_permissions: {},
    pr_review_mode: 'advisory',
  };
}

async function getOrCreateThread(
  organizationId: string,
  userId: string,
  threadId: string | undefined,
  message: string,
  context?: AegisStreamConfig['context'],
): Promise<string> {
  if (threadId) {
    await supabase
      .from('aegis_chat_threads')
      .update({ updated_at: new Date().toISOString() })
      .eq('id', threadId);
    return threadId;
  }

  const title = message.substring(0, 50) + (message.length > 50 ? '...' : '');
  const { data } = await supabase
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

  return data!.id;
}

async function loadThreadHistory(threadId: string): Promise<CoreMessage[]> {
  const { data: messages } = await supabase
    .from('aegis_chat_messages')
    .select('role, content, metadata')
    .eq('thread_id', threadId)
    .order('created_at', { ascending: true })
    .limit(50);

  if (!messages?.length) return [];

  return messages.map(m => ({
    role: m.role as 'user' | 'assistant',
    content: m.content,
  }));
}

async function queryRelevantMemories(organizationId: string, message: string): Promise<string> {
  try {
    const { getEmbeddingModel } = await import('./llm-provider');
    const { embed } = await import('ai');
    const model = getEmbeddingModel();
    const result = await embed({ model, value: message });

    const { data } = await supabase.rpc('match_aegis_memories', {
      query_embedding: JSON.stringify(result.embedding),
      match_threshold: 0.6,
      match_count: 5,
      filter_org_id: organizationId,
      filter_category: null,
    });

    if (data?.length) {
      return '\n\n## Relevant Organizational Context (from memory)\n' +
        data.map((m: any) => `- [${m.category}] ${m.key}: ${m.content}`).join('\n');
    }
  } catch {
    // Memory retrieval is non-critical
  }

  // Fallback text search
  try {
    const keywords = message.split(/\s+/).slice(0, 3).join('%');
    const { data } = await supabase
      .from('aegis_memory')
      .select('category, key, content')
      .eq('organization_id', organizationId)
      .or(`key.ilike.%${keywords}%,content.ilike.%${keywords}%`)
      .limit(3);

    if (data?.length) {
      return '\n\n## Relevant Organizational Context (from memory)\n' +
        data.map((m: any) => `- [${m.category}] ${m.key}: ${m.content}`).join('\n');
    }
  } catch {
    // Text search also non-critical
  }

  return '';
}

export async function createAegisStream(config: AegisStreamConfig) {
  const { organizationId, userId, message, context } = config;

  const [model, orgSettings, orgRow] = await Promise.all([
    getLanguageModelForOrg(organizationId),
    getOrgSettings(organizationId),
    supabase.from('organizations').select('name').eq('id', organizationId).single().then(r => r.data),
  ]);

  const orgName = orgRow?.name || 'Organization';

  const currentThreadId = await getOrCreateThread(
    organizationId, userId, config.threadId, message, context,
  );

  const [history, memoryContext] = await Promise.all([
    loadThreadHistory(currentThreadId),
    queryRelevantMemories(organizationId, message),
  ]);

  const toolContext: ToolContext = {
    organizationId,
    userId,
    projectId: context?.projectId,
    threadId: currentThreadId,
    operatingMode: orgSettings.operating_mode as ToolContext['operatingMode'],
  };

  const systemPrompt = buildAgentSystemPrompt(orgName, organizationId, context) + memoryContext;
  const tools = buildToolSet(toolContext, message);

  const result = streamText({
    model,
    system: systemPrompt,
    messages: [...history, { role: 'user' as const, content: message }],
    tools,
    maxSteps: 25,
    onStepFinish: async ({ toolCalls, toolResults, usage }) => {
      if (toolCalls?.length) {
        for (const tc of toolCalls) {
          console.log(`[Aegis] Tool called: ${tc.toolName}`);
        }
      }
    },
    onFinish: async ({ usage, steps, text }) => {
      // Save messages to thread
      try {
        await supabase.from('aegis_chat_messages').insert([
          { thread_id: currentThreadId, role: 'user', content: message },
          {
            thread_id: currentThreadId,
            role: 'assistant',
            content: text || 'No response generated.',
            metadata: {
              steps: steps?.length || 0,
              tokens: usage ? usage.totalTokens : 0,
            },
          },
        ]);

        // Update thread token count
        if (usage) {
          const { data: thread } = await supabase
            .from('aegis_chat_threads')
            .select('total_tokens_used')
            .eq('id', currentThreadId)
            .single();

          await supabase
            .from('aegis_chat_threads')
            .update({
              total_tokens_used: (thread?.total_tokens_used || 0) + (usage.totalTokens || 0),
              updated_at: new Date().toISOString(),
            })
            .eq('id', currentThreadId);
        }

        // Log AI usage
        const providerInfo = await getProviderInfoForOrg(organizationId);
        const { logAIUsage } = await import('../ai/logging');
        logAIUsage({
          organizationId,
          userId,
          feature: 'aegis_chat_v2',
          tier: 'byok',
          provider: providerInfo?.provider || 'unknown',
          model: providerInfo?.model || 'unknown',
          inputTokens: usage?.promptTokens || 0,
          outputTokens: usage?.completionTokens || 0,
          contextType: context?.type,
          contextId: context?.id,
          durationMs: 0,
          success: true,
        }).catch(() => {});
      } catch (err) {
        console.error('[Aegis] Failed to save messages:', err);
      }
    },
  });

  return { threadId: currentThreadId, result };
}

export { executeMessage } from './executor';
