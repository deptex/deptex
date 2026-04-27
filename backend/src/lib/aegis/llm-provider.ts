import { LanguageModel } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { decryptApiKey } from '../ai/encryption';
import { DEFAULT_MODELS } from '../ai/models';

interface ProviderConfig {
  providerType: 'openai' | 'anthropic' | 'google';
  apiKey: string;
  model: string;
  baseURL?: string;
}

export function getLanguageModel(config: ProviderConfig): LanguageModel {
  switch (config.providerType) {
    case 'openai':
      return createOpenAI({ apiKey: config.apiKey, baseURL: config.baseURL })(config.model);
    case 'anthropic':
      return createAnthropic({ apiKey: config.apiKey })(config.model);
    case 'google':
      return createGoogleGenerativeAI({ apiKey: config.apiKey })(config.model);
    default:
      throw new Error(`Unknown provider: ${config.providerType}`);
  }
}

export async function getLanguageModelForOrg(organizationId: string): Promise<LanguageModel> {
  const { supabase } = await import('../supabase');

  const { data: providers } = await supabase
    .from('organization_ai_providers')
    .select('*')
    .eq('organization_id', organizationId)
    .order('is_default', { ascending: false })
    .limit(1);

  if (!providers?.length) {
    throw new Error(
      'No AI provider configured. Set up a provider in Organization Settings > AI Configuration.'
    );
  }

  const row = providers[0];
  const apiKey = decryptApiKey(row.encrypted_api_key, row.encryption_key_version);
  const model = row.model_preference || DEFAULT_MODELS[row.provider as keyof typeof DEFAULT_MODELS];

  return getLanguageModel({
    providerType: row.provider as ProviderConfig['providerType'],
    apiKey,
    model,
  });
}

export async function getProviderInfoForOrg(organizationId: string): Promise<{
  provider: string;
  model: string;
  monthlyCostCap: number;
} | null> {
  const { supabase } = await import('../supabase');

  const { data: providers } = await supabase
    .from('organization_ai_providers')
    .select('provider, model_preference, monthly_cost_cap, is_default')
    .eq('organization_id', organizationId)
    .order('is_default', { ascending: false })
    .limit(1);

  if (!providers?.length) return null;
  const row = providers[0];
  return {
    provider: row.provider,
    model: row.model_preference || DEFAULT_MODELS[row.provider as keyof typeof DEFAULT_MODELS],
    monthlyCostCap: row.monthly_cost_cap ?? 100,
  };
}

export function getEmbeddingModel() {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY required for memory embeddings');
  return createGoogleGenerativeAI({ apiKey })('text-embedding-004');
}
