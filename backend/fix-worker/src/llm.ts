import type { LanguageModel } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import type { SupabaseClient } from '@supabase/supabase-js';

type AIProvider = 'openai' | 'anthropic' | 'google' | 'deepinfra';

// DeepInfra's OpenAI-compatible endpoint. Reuse the OpenAI SDK with this
// baseURL — no separate package required.
const DEEPINFRA_BASE_URL = 'https://api.deepinfra.com/v1/openai';

const DEFAULT_MODELS: Record<AIProvider, string> = {
  openai: 'gpt-4o',
  anthropic: 'claude-sonnet-4-5-20250929',
  google: 'gemini-2.5-pro',
  deepinfra: 'Qwen/Qwen3-235B-A22B-Instruct-2507',
};

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
      // DeepInfra speaks only the Chat Completions API. The AI SDK defaults
      // to OpenAI's newer Responses API, which DeepInfra returns 404 for.
      // .chat(modelName) pins this branch to /chat/completions.
      return createOpenAI({ apiKey, baseURL: DEEPINFRA_BASE_URL }).chat(modelName);
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
    .select('default_ai_provider')
    .eq('id', organizationId)
    .single();
  if (error) throw new Error(`Failed to load organization: ${error.message}`);
  const provider = ((data?.default_ai_provider as AIProvider) ?? 'anthropic') as AIProvider;
  const apiKey = getPlatformKey(provider);
  if (!apiKey) {
    throw new Error(
      `Platform API key for ${provider} is not configured on the fix-worker. Set ${envVarFor(provider)}.`,
    );
  }
  return buildModel(provider, apiKey, DEFAULT_MODELS[provider]);
}
