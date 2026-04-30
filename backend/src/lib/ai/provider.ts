import { AIProvider, ChatResult, ToolCallResult, StreamChunk } from './types';
import { GoogleProvider } from './providers/google-provider';

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
