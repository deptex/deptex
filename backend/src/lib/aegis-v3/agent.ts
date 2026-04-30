import { ToolLoopAgent, stepCountIs, type ModelMessage } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { supabase } from '../../lib/supabase';
import { getLanguageModelForOrg } from './provider';
import { buildAegisSystemPrompt, type SystemPromptContext } from './system-prompt';
import { buildToolSet } from './tools';
import { saveAssistantMessage, saveToolExecution, logChatUsage } from './persistence';
import type { AegisOperatingMode, AegisToolContext } from './tool-types';

export interface CreateAegisAgentOptions {
  orgId: string;
  userId: string;
  threadId: string;
  userMessage: string;
  context?: SystemPromptContext;
  memoryContext?: string;
}

const DEFAULT_OPERATING_MODE: AegisOperatingMode = 'propose';

async function getOrgName(orgId: string): Promise<string> {
  const { data } = await supabase
    .from('organizations')
    .select('name')
    .eq('id', orgId)
    .single();
  return data?.name ?? 'Organization';
}

async function getOperatingMode(orgId: string): Promise<AegisOperatingMode> {
  const { data } = await supabase
    .from('aegis_org_settings')
    .select('operating_mode')
    .eq('organization_id', orgId)
    .single();
  const mode = data?.operating_mode as AegisOperatingMode | undefined;
  return mode ?? DEFAULT_OPERATING_MODE;
}

export async function createAegisAgent(opts: CreateAegisAgentOptions): Promise<ToolLoopAgent> {
  const [model, orgName, operatingMode] = await Promise.all([
    getLanguageModelForOrg(opts.orgId),
    getOrgName(opts.orgId),
    getOperatingMode(opts.orgId),
  ]);

  const instructions =
    buildAegisSystemPrompt({
      orgName,
      organizationId: opts.orgId,
      context: opts.context,
    }) + (opts.memoryContext ?? '');

  const ctx: AegisToolContext = {
    orgId: opts.orgId,
    userId: opts.userId,
    threadId: opts.threadId,
    operatingMode,
    supabase: supabase as unknown as SupabaseClient,
  };

  const startedAt = Date.now();

  return new ToolLoopAgent({
    model,
    instructions,
    tools: buildToolSet(ctx),
    stopWhen: stepCountIs(25),
    onStepFinish: async ({ toolCalls, toolResults }) => {
      if (!toolCalls?.length) return;
      const resultByCallId = new Map<string, unknown>();
      for (const r of toolResults ?? []) {
        resultByCallId.set(r.toolCallId, (r as { output?: unknown }).output);
      }
      for (const call of toolCalls) {
        await saveToolExecution({
          organizationId: opts.orgId,
          userId: opts.userId,
          threadId: opts.threadId,
          toolName: call.toolName,
          toolCategory: 'read_only',
          permissionLevel: 'safe',
          parameters: (call as { input?: unknown }).input ?? null,
          result: resultByCallId.get(call.toolCallId) ?? null,
          success: resultByCallId.has(call.toolCallId),
          durationMs: 0,
          tokensUsed: 0,
        });
      }
    },
    onFinish: async ({ text, totalUsage, steps }) => {
      const inputTokens = totalUsage?.inputTokens ?? 0;
      const outputTokens = totalUsage?.outputTokens ?? 0;
      const totalTokens = totalUsage?.totalTokens ?? inputTokens + outputTokens;

      await saveAssistantMessage({
        threadId: opts.threadId,
        userMessage: opts.userMessage,
        assistantText: text,
        steps: steps?.length ?? 0,
        promptTokens: inputTokens,
        completionTokens: outputTokens,
        totalTokens,
      });

      await logChatUsage({
        organizationId: opts.orgId,
        userId: opts.userId,
        promptTokens: inputTokens,
        completionTokens: outputTokens,
        contextType: opts.context?.type,
        contextId: opts.context?.id,
        durationMs: Date.now() - startedAt,
      });
    },
  });
}

export type { ModelMessage };
