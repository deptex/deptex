import { LanguageModel } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { DEFAULT_MODELS } from '../ai/models';

export type AIProvider = 'openai' | 'anthropic' | 'google';

interface ProviderConfig {
  providerType: AIProvider;
  apiKey: string;
  model: string;
  baseURL?: string;
}

const DEFAULT_MONTHLY_COST_CAP_USD = 100;

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

export function getPlatformKeyForProvider(provider: AIProvider): string | undefined {
  switch (provider) {
    case 'openai':
      return process.env.OPENAI_API_KEY;
    case 'anthropic':
      return process.env.ANTHROPIC_API_KEY;
    case 'google':
      return process.env.GOOGLE_AI_API_KEY;
  }
}

function envVarFor(provider: AIProvider): string {
  return provider === 'google' ? 'GOOGLE_AI_API_KEY' : `${provider.toUpperCase()}_API_KEY`;
}

async function getOrgDefaultProvider(organizationId: string): Promise<AIProvider> {
  const { supabase } = await import('../supabase');
  const { data, error } = await supabase
    .from('organizations')
    .select('default_ai_provider')
    .eq('id', organizationId)
    .single();
  if (error) throw new Error(`Failed to load organization: ${error.message}`);
  return (data?.default_ai_provider as AIProvider) ?? 'anthropic';
}

export async function getLanguageModelForOrg(organizationId: string): Promise<LanguageModel> {
  const provider = await getOrgDefaultProvider(organizationId);
  const apiKey = getPlatformKeyForProvider(provider);
  if (!apiKey) {
    throw new Error(
      `Platform API key for ${provider} is not configured. Set ${envVarFor(provider)} on the backend, or pick a different provider in Organization Settings > AI.`
    );
  }
  const model = DEFAULT_MODELS[provider];
  return getLanguageModel({ providerType: provider, apiKey, model });
}

export async function getProviderInfoForOrg(organizationId: string): Promise<{
  provider: AIProvider;
  model: string;
  monthlyCostCap: number;
}> {
  const provider = await getOrgDefaultProvider(organizationId);
  return {
    provider,
    model: DEFAULT_MODELS[provider],
    monthlyCostCap: DEFAULT_MONTHLY_COST_CAP_USD,
  };
}

export function getEmbeddingModel() {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY required for memory embeddings');
  return createGoogleGenerativeAI({ apiKey })('text-embedding-004');
}
