import { ToolLoopAgent, stepCountIs, type ModelMessage } from 'ai';
import type { SupabaseClient } from '@supabase/supabase-js';
import { supabase } from '../../lib/supabase';
import { getLanguageModelForOrg, getProviderInfoForOrg } from './provider';
import { buildAegisSystemPrompt, type SystemPromptContext } from './system-prompt';
import { ALL_AEGIS_TOOLS, buildToolSet } from './chat-tools';
import { saveAssistantMessage, saveToolExecution, logChatUsage } from './persistence';
import { stepsToMessageParts } from './parts';
import { recordMeterEvent } from '../billing/ledger';
import { chargedCentsForAi } from '../ai/pricing';
import { newTurnState, type AegisOperatingMode, type AegisToolContext } from './tool-types';

export interface CreateAegisAgentOptions {
  orgId: string;
  userId: string;
  threadId: string;
  userMessage: string;
  // Number of prior messages already in the thread (excluding the new user turn).
  // Used to decide whether to auto-title on first exchange.
  priorMessageCount: number;
  context?: SystemPromptContext;
  memoryContext?: string;
  // Per-request model override. Validated server-side against the org's
  // enabled_models list inside resolveOrgModel; an unknown / disabled id
  // throws before the agent is constructed.
  modelId?: string;
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
    getLanguageModelForOrg(opts.orgId, opts.modelId),
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
    // Fresh per-turn state. Tools mutate this Set / flag to dedupe in-turn
    // (e.g. revise_fix refuses a 2nd revision of the same plan; request_fix
    // refuses re-requesting the same finding). The state never persists
    // across stream calls because ctx is rebuilt in createAegisAgent.
    turnState: newTurnState(),
  };

  const startedAt = Date.now();

  return new ToolLoopAgent({
    model,
    instructions,
    tools: buildToolSet(ctx),
    stopWhen: stepCountIs(25),
    // Without this, each step uses the SDK / provider default (often 1024-4096
    // tokens), which truncates long answers — e.g. "list every issue on this
    // project" cuts off mid-listing and fires a stream error. 32k matches
    // what Claude Code / Cursor / ChatGPT effectively use for modern frontier
    // models, and every model in DEFAULT_MODELS (Sonnet 4.6, Opus 4.7,
    // GPT-5.4, Gemini 3, DeepSeek V4, Qwen3.6) supports at least 32k output.
    // If a smaller model is added later that caps lower (e.g. 8k), Anthropic
    // will 400 and we'll need per-model lookup via ModelMetadata.
    maxOutputTokens: 32768,
    onStepFinish: async ({ toolCalls, toolResults }) => {
      if (!toolCalls?.length) return;
      const resultByCallId = new Map<string, unknown>();
      for (const r of toolResults ?? []) {
        resultByCallId.set(r.toolCallId, (r as { output?: unknown }).output);
      }
      for (const call of toolCalls) {
        const entry = ALL_AEGIS_TOOLS.find((t) => t.name === call.toolName);
        if (entry?.audit === false) continue;
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
      console.log(
        `[aegis] onFinish fired thread=${opts.threadId} textLen=${text?.length ?? 0} steps=${steps?.length ?? 0}`,
      );
      const inputTokens = totalUsage?.inputTokens ?? 0;
      const outputTokens = totalUsage?.outputTokens ?? 0;
      const totalTokens = totalUsage?.totalTokens ?? inputTokens + outputTokens;

      const parts = stepsToMessageParts(steps ?? []);

      // Race fix: pipeUIMessageStreamToResponse.onError can fire BEFORE this
      // onFinish (e.g. when the SDK throws during pipe serialization but the
      // model itself finished generating). The pipe handler writes a generic
      // "Something went wrong" assistant row; if we then persist the real
      // response, the user sees a phantom error bubble next to a successful
      // answer and on follow-up the model thinks nothing went wrong (it sees
      // its own correct response and the user's "what failed?" makes no
      // sense). Clean up any pipe-error row from this turn before writing the
      // real one. Scoped to >= startedAt so prior turn errors are untouched.
      try {
        await supabase
          .from('aegis_chat_messages')
          .delete()
          .eq('thread_id', opts.threadId)
          .eq('role', 'assistant')
          .not('metadata->error', 'is', null)
          .gte('created_at', new Date(startedAt).toISOString());
      } catch (cleanupErr) {
        console.warn('[aegis] error-row cleanup failed', cleanupErr);
      }

      try {
        await saveAssistantMessage({
          threadId: opts.threadId,
          assistantText: text ?? '',
          parts,
          totalTokens,
        });
        console.log(`[aegis] saveAssistantMessage OK thread=${opts.threadId}`);
      } catch (saveErr) {
        console.error(
          `[aegis] saveAssistantMessage FAILED thread=${opts.threadId}`,
          saveErr,
        );
        throw saveErr;
      }

      await logChatUsage({
        organizationId: opts.orgId,
        userId: opts.userId,
        promptTokens: inputTokens,
        completionTokens: outputTokens,
        contextType: opts.context?.type,
        contextId: opts.context?.id,
        durationMs: Date.now() - startedAt,
      });

      // Charge the org's prepaid balance once per turn. Errors are
      // swallowed so a billing-DB blip can't kill the chat reply — the
      // worker still wrote the assistant message; reconcile catches drift.
      try {
        const providerInfo = await getProviderInfoForOrg(opts.orgId, opts.modelId);
        const { cogCents, chargedCents } = chargedCentsForAi(providerInfo.model, inputTokens, outputTokens);
        if (chargedCents > 0) {
          await recordMeterEvent({
            organizationId: opts.orgId,
            eventType: 'ai_tokens',
            provider: providerInfo.provider as 'openai' | 'anthropic' | 'google' | 'deepinfra',
            feature: 'aegis.chat',
            quantity: inputTokens,
            outputQuantity: outputTokens > 0 ? outputTokens : undefined,
            unit: 'mixed_tokens',
            cogCents,
            chargedCents,
            modelId: providerInfo.model,
            attribution: {
              userId: opts.userId,
              resourceType: 'aegis_chat',
              resourceId: opts.threadId,
            },
            idempotencyKey: `aegis:${opts.threadId}:${startedAt}:tokens`,
          });
        }
      } catch (err) {
        console.warn('[aegis] recordMeterEvent failed', err);
      }

      // Title generation lives in the route (kicked off in parallel with the
      // model stream) so it survives a Stop click — the user's intent to keep
      // a thread is committed the moment they send the first message.
    },
  });
}

export type { ModelMessage };
