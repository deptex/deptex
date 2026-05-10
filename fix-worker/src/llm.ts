import type { LanguageModel } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';
import { createOpenAICompatible } from '@ai-sdk/openai-compatible';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import type { SupabaseClient } from '@supabase/supabase-js';

type AIProvider = 'openai' | 'anthropic' | 'google' | 'deepinfra';

// DeepInfra's OpenAI-compatible endpoint. We use @ai-sdk/openai-compatible
// rather than @ai-sdk/openai because the latter maps system messages to the
// new role: 'developer' (introduced for OpenAI's o1/o3 reasoning models),
// which DeepInfra rejects with 422. The openai-compatible provider sticks
// to the older standard role: 'system'.
const DEEPINFRA_BASE_URL = 'https://api.deepinfra.com/v1/openai';

const DEFAULT_MODELS: Record<AIProvider, string> = {
  openai: 'gpt-4o',
  anthropic: 'claude-sonnet-4-5-20250929',
  google: 'gemini-2.5-pro',
  deepinfra: 'deepseek-ai/DeepSeek-V3.1',
};

// Model-id → provider mapping for `organizations.default_model`. Backend's
// llm-provider keeps the canonical map in `lib/ai/models.ts` but we can't
// reach across the worker boundary; we infer provider from the prefix. If
// the prefix is unrecognised we fall through to default_ai_provider so the
// worker behaves like the backend's resolveOrgModel().
function inferProviderFromModelId(modelId: string): AIProvider | null {
  const id = modelId.toLowerCase();
  if (id.startsWith('claude-')) return 'anthropic';
  if (id.startsWith('gpt-') || id.startsWith('o1-') || id.startsWith('o3-') || id.startsWith('o4-')) return 'openai';
  if (id.startsWith('gemini-')) return 'google';
  if (id.startsWith('deepseek-') || id.includes('/')) return 'deepinfra';
  return null;
}

function getPlatformKey(provider: AIProvider): string | undefined {
  switch (provider) {
    case 'openai':
      return process.env.OPENAI_API_KEY;
    case 'anthropic':
      return process.env.ANTHROPIC_API_KEY;
    case 'google':
      return process.env.GOOGLE_AI_API_KEY;
    case 'deepinfra':
      return process.env.DEEPINFRA_API_KEY;
  }
}

function envVarFor(provider: AIProvider): string {
  if (provider === 'google') return 'GOOGLE_AI_API_KEY';
  if (provider === 'deepinfra') return 'DEEPINFRA_API_KEY';
  return `${provider.toUpperCase()}_API_KEY`;
}

function buildModel(provider: AIProvider, apiKey: string, modelName: string): LanguageModel {
  switch (provider) {
    case 'openai':
      return createOpenAI({ apiKey })(modelName);
    case 'deepinfra':
      return createOpenAICompatible({
        name: 'deepinfra',
        apiKey,
        baseURL: DEEPINFRA_BASE_URL,
      }).chatModel(modelName);
    case 'anthropic':
      return createAnthropic({ apiKey })(modelName);
    case 'google':
      return createGoogleGenerativeAI({ apiKey })(modelName);
  }
}

export async function getLanguageModelForOrg(
  supabase: SupabaseClient,
  organizationId: string,
): Promise<LanguageModel> {
  const { data, error } = await supabase
    .from('organizations')
    .select('default_ai_provider, default_model')
    .eq('id', organizationId)
    .single();
  if (error) throw new Error(`Failed to load organization: ${error.message}`);

  // Mirror backend resolveOrgModel(): prefer default_model when the prefix
  // unambiguously identifies a provider, fall back to default_ai_provider
  // with the worker's hard-coded default for that provider. Without this
  // sync, the user sees their chosen model in the UI but the worker quietly
  // runs against gpt-4o / sonnet / etc.
  const defaultModel = data?.default_model as string | null | undefined;
  let provider: AIProvider;
  let modelName: string;
  if (defaultModel) {
    const inferred = inferProviderFromModelId(defaultModel);
    if (inferred) {
      provider = inferred;
      modelName = defaultModel;
    } else {
      provider = ((data?.default_ai_provider as AIProvider) ?? 'anthropic');
      modelName = DEFAULT_MODELS[provider];
    }
  } else {
    provider = ((data?.default_ai_provider as AIProvider) ?? 'anthropic');
    modelName = DEFAULT_MODELS[provider];
  }

  const apiKey = getPlatformKey(provider);
  if (!apiKey) {
    throw new Error(
      `Platform API key for ${provider} is not configured on the fix-worker. Set ${envVarFor(provider)}.`,
    );
  }
  return buildModel(provider, apiKey, modelName);
}
