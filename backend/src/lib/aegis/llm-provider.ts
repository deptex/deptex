import { LanguageModel } from 'ai';
import { createOpenAI } from '@ai-sdk/openai';
import { createOpenAICompatible } from '@ai-sdk/openai-compatible';
import { createAnthropic } from '@ai-sdk/anthropic';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { DEFAULT_MODELS, getModelById } from '../ai/models';

export type AIProvider = 'openai' | 'anthropic' | 'google' | 'deepinfra';

interface ProviderConfig {
  providerType: AIProvider;
  apiKey: string;
  model: string;
  baseURL?: string;
}

const DEFAULT_MONTHLY_COST_CAP_USD = 100;

// DeepInfra exposes an OpenAI-API-compatible endpoint, so we reuse the
// OpenAI factory with a custom baseURL — no separate SDK required.
// IMPORTANT: DeepInfra implements only the Chat Completions API
// (/chat/completions), not OpenAI's newer Responses API (/responses) which
// the AI SDK uses by default. Call .chat(model) so the SDK targets
// /chat/completions and DeepInfra responds 200 instead of 404.
const DEEPINFRA_BASE_URL = 'https://api.deepinfra.com/v1/openai';

export function getLanguageModel(config: ProviderConfig): LanguageModel {
  switch (config.providerType) {
    case 'openai':
      return createOpenAI({ apiKey: config.apiKey, baseURL: config.baseURL })(config.model);
    case 'deepinfra':
      // Use @ai-sdk/openai-compatible rather than @ai-sdk/openai for
      // DeepInfra. The OpenAI provider maps system messages to
      // role: 'developer' (the new OpenAI o1/o3 role) which DeepInfra
      // rejects with 422. The compatible provider keeps role: 'system'.
      return createOpenAICompatible({
        name: 'deepinfra',
        apiKey: config.apiKey,
        baseURL: config.baseURL ?? DEEPINFRA_BASE_URL,
      }).chatModel(config.model);
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
    case 'deepinfra':
      return process.env.DEEPINFRA_API_KEY;
  }
}

function envVarFor(provider: AIProvider): string {
  if (provider === 'google') return 'GOOGLE_AI_API_KEY';
  if (provider === 'deepinfra') return 'DEEPINFRA_API_KEY';
  return `${provider.toUpperCase()}_API_KEY`;
}

// Resolve which model to run a request against. If a per-request override is
// supplied (the user picked a model in the chat input), validate it's in the
// org's enabled list — otherwise a malicious client could bypass the
// enable/disable gate from settings. With no override, fall back to the org
// default.
async function resolveOrgModel(
  organizationId: string,
  requestedModelId?: string,
): Promise<{ provider: AIProvider; model: string }> {
  const { supabase } = await import('../supabase');
  const { data, error } = await supabase
    .from('organizations')
    .select('default_ai_provider, default_model, enabled_models')
    .eq('id', organizationId)
    .single();
  if (error) throw new Error(`Failed to load organization: ${error.message}`);

  if (requestedModelId) {
    const meta = getModelById(requestedModelId);
    if (!meta) throw new Error(`Unknown model: ${requestedModelId}`);
    const enabled: string[] | null = (data?.enabled_models as string[] | null) ?? null;
    if (enabled && !enabled.includes(requestedModelId)) {
      throw new Error(`Model not enabled for this organization: ${requestedModelId}`);
    }
    return { provider: meta.provider, model: meta.id };
  }

  if (data?.default_model) {
    const meta = getModelById(data.default_model);
    if (meta) return { provider: meta.provider, model: meta.id };
  }

  const provider = (data?.default_ai_provider as AIProvider) ?? 'anthropic';
  return { provider, model: DEFAULT_MODELS[provider] };
}

export async function getLanguageModelForOrg(
  organizationId: string,
  modelId?: string,
): Promise<LanguageModel> {
  const { provider, model } = await resolveOrgModel(organizationId, modelId);
  const apiKey = getPlatformKeyForProvider(provider);
  if (!apiKey) {
    throw new Error(
      `Platform API key for ${provider} is not configured. Set ${envVarFor(provider)} on the backend, or pick a different provider in Organization Settings > AI.`
    );
  }
  return getLanguageModel({ providerType: provider, apiKey, model });
}

export async function getProviderInfoForOrg(
  organizationId: string,
  modelId?: string,
): Promise<{
  provider: AIProvider;
  model: string;
  monthlyCostCap: number;
}> {
  const { provider, model } = await resolveOrgModel(organizationId, modelId);
  return {
    provider,
    model,
    monthlyCostCap: DEFAULT_MONTHLY_COST_CAP_USD,
  };
}

export function getEmbeddingModel() {
  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) throw new Error('GOOGLE_AI_API_KEY required for memory embeddings');
  return createGoogleGenerativeAI({ apiKey })('text-embedding-004');
}
