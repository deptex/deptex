import { AIProvider, AIProviderError, ChatResult, Message, ChatOptions, ToolDef, ToolCallResult, StreamChunk } from './types';
import { decryptApiKey } from './encryption';
import { DEFAULT_MODELS } from './models';
import { OpenAIProvider } from './providers/openai-provider';
import { AnthropicProvider } from './providers/anthropic-provider';
import { GoogleProvider } from './providers/google-provider';

function createProvider(providerName: string, apiKey: string, model?: string, baseURL?: string): AIProvider {
  switch (providerName) {
    case 'openai':
      return new OpenAIProvider(apiKey, model);
    case 'anthropic':
      return new AnthropicProvider(apiKey, model);
    case 'google':
      return new GoogleProvider(apiKey, model);
    case 'custom':
      return new OpenAIProvider(apiKey, model || 'gpt-4o', baseURL);
    default:
      throw new AIProviderError(`Unknown provider: ${providerName}`, 'unknown', providerName, false);
  }
}

export async function getProviderForOrg(orgId: string): Promise<AIProvider> {
  const { supabase } = await import('../supabase');

  const { data: providers } = await supabase
    .from('organization_ai_providers')
    .select('*')
    .eq('organization_id', orgId)
    .order('is_default', { ascending: false })
    .limit(1);

  if (!providers?.length) {
    throw new AIProviderError(
      'No AI provider configured for this organization. Configure one in Organization Settings > AI Configuration.',
      'auth_failed', 'none', false
    );
  }

  const row = providers[0];
  const apiKey = decryptApiKey(row.encrypted_api_key, row.encryption_key_version);
  const model = row.model_preference || (DEFAULT_MODELS as Record<string, string>)[row.provider] || 'gpt-4o';
  const baseURL = row.api_base_url || undefined;

  return createProvider(row.provider, apiKey, model, baseURL);
}

export async function getProviderConfigForOrg(orgId: string): Promise<{ provider: string; model: string } | null> {
  const { supabase } = await import('../supabase');

  const { data: providers } = await supabase
    .from('organization_ai_providers')
    .select('provider, model_preference, is_default')
    .eq('organization_id', orgId)
    .order('is_default', { ascending: false })
    .limit(1);

  if (!providers?.length) return null;
  const row = providers[0];
  const model = row.model_preference || (DEFAULT_MODELS as Record<string, string>)[row.provider] || 'gpt-4o';
  return { provider: row.provider, model };
}

class PlatformStubProvider implements AIProvider {
  async chat(): Promise<ChatResult> {
    return { content: 'AI features are temporarily unavailable. Please try again later.', usage: { inputTokens: 0, outputTokens: 0 }, model: 'stub' };
  }
  async chatWithTools(): Promise<ToolCallResult> {
    return { content: 'AI features are temporarily unavailable.', usage: { inputTokens: 0, outputTokens: 0 }, model: 'stub', toolCalls: [] };
  }
  async *streamChat(): AsyncIterable<StreamChunk> {
    yield { type: 'text', content: 'AI features are temporarily unavailable. Please try again later.' };
    yield { type: 'done', usage: { inputTokens: 0, outputTokens: 0 } };
  }
}

let platformProvider: AIProvider | null = null;

export function getPlatformProvider(): AIProvider {
  if (platformProvider) return platformProvider;

  const apiKey = process.env.GOOGLE_AI_API_KEY;
  if (!apiKey) {
    console.warn('[AI] GOOGLE_AI_API_KEY not set — platform AI features will return stub responses');
    platformProvider = new PlatformStubProvider();
    return platformProvider;
  }

  platformProvider = new GoogleProvider(apiKey, 'gemini-2.5-flash');
  return platformProvider;
}

export function createProviderFromKey(providerName: string, apiKey: string, model?: string, baseURL?: string): AIProvider {
  const defaultModel = (DEFAULT_MODELS as Record<string, string>)[providerName];
  return createProvider(providerName, apiKey, model || defaultModel, baseURL);
}
