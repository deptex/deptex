import { ToolLoopAgent, stepCountIs, type ModelMessage } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { supabase } from '../../lib/supabase';
import { getLanguageModelForOrg } from './provider';
import { buildAegisSystemPrompt, type SystemPromptContext } from './system-prompt';
import { buildToolSet } from './tools';
import { saveToolExecution, logChatUsage } from './persistence';
import type { MessagePart } from '../aegis/types';
import type { AegisOperatingMode, AegisToolContext } from './tool-types';

export interface GenerateAegisChatOptions {
  orgId: string;
  userId: string;
  threadId: string;
  userMessage: string;
  history: Array<{ role: 'user' | 'assistant'; content: string }>;
  context?: SystemPromptContext;
  memoryContext?: string;
}

export interface GenerateAegisChatResult {
  text: string;
  parts: MessagePart[];
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

/**
 * Run the v3 ToolLoopAgent in non-streaming mode and produce a multi-part
 * assistant message that the v2 chat UI's MessageBubble can render.
 *
 * The route handler is responsible for writing the resulting {text, parts}
 * to aegis_chat_messages — Supabase Realtime carries it to the client.
 */
export async function generateAegisChat(
  opts: GenerateAegisChatOptions,
): Promise<GenerateAegisChatResult> {
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

  const agent = new ToolLoopAgent({
    model,
    instructions,
    tools: buildToolSet(ctx),
    stopWhen: stepCountIs(25),
    temperature: 0.2,
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
  });

  const messages: ModelMessage[] = [
    ...opts.history.map((m) => ({ role: m.role, content: m.content })),
    { role: 'user' as const, content: opts.userMessage },
  ];

  const result = await agent.generate({ messages });

  const inputTokens = result.totalUsage?.inputTokens ?? 0;
  const outputTokens = result.totalUsage?.outputTokens ?? 0;

  await logChatUsage({
    organizationId: opts.orgId,
    userId: opts.userId,
    promptTokens: inputTokens,
    completionTokens: outputTokens,
    contextType: opts.context?.type,
    contextId: opts.context?.id,
    durationMs: Date.now() - startedAt,
  });

  const parts = stepsToMessageParts(result.steps);
  return { text: result.text ?? '', parts };
}

type StepLike = {
  text?: string;
  toolCalls?: Array<{
    toolCallId: string;
    toolName: string;
    input?: unknown;
  }>;
  toolResults?: Array<{
    toolCallId: string;
    toolName: string;
    output?: unknown;
  }>;
};

/**
 * Convert ToolLoopAgent step results into the MessagePart shape stored in
 * aegis_chat_messages.metadata.parts. ChatPane.buildInitialMessages pairs
 * tool-call/tool-result by toolCallId and emits a single dynamic-tool UI
 * part per call for MessageBubble.
 */
function stepsToMessageParts(steps: ReadonlyArray<unknown>): MessagePart[] {
  const parts: MessagePart[] = [];
  for (const stepUnknown of steps) {
    const step = stepUnknown as StepLike;

    if (typeof step.text === 'string' && step.text.length > 0) {
      parts.push({ type: 'text', text: step.text });
    }

    const resultByCallId = new Map<string, unknown>();
    for (const r of step.toolResults ?? []) {
      resultByCallId.set(r.toolCallId, r.output);
    }

    for (const call of step.toolCalls ?? []) {
      const args =
        call.input && typeof call.input === 'object'
          ? (call.input as Record<string, unknown>)
          : {};
      parts.push({
        type: 'tool-call',
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        args,
      });

      if (resultByCallId.has(call.toolCallId)) {
        const output = resultByCallId.get(call.toolCallId);
        const isError =
          !!output &&
          typeof output === 'object' &&
          'error' in (output as Record<string, unknown>);
        parts.push({
          type: 'tool-result',
          toolCallId: call.toolCallId,
          toolName: call.toolName,
          result: output,
          ...(isError ? { isError: true } : {}),
        });
      }
    }
  }
  return parts;
}
