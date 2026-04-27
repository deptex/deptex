import OpenAI from 'openai';
import { AIProvider, AIProviderError, Message, ChatOptions, ChatResult, ToolDef, ToolCallResult, StreamChunk } from '../types';

export class OpenAIProvider implements AIProvider {
  private client: OpenAI;
  private defaultModel: string;

  constructor(apiKey: string, model?: string, baseURL?: string) {
    this.client = new OpenAI({
      apiKey,
      ...(baseURL ? { baseURL: baseURL.replace(/\/$/, '') } : {}),
    });
    this.defaultModel = model || 'gpt-4o';
  }

  private mapMessages(messages: Message[]): OpenAI.Chat.Completions.ChatCompletionMessageParam[] {
    return messages.map(m => ({
      role: m.role as any,
      content: m.content ?? '',
      ...(m.name ? { name: m.name } : {}),
      ...(m.tool_call_id ? { tool_call_id: m.tool_call_id } : {}),
    }));
  }

  private mapError(err: any): never {
    const msg = err?.message || String(err);
    const status = err?.status || err?.response?.status;

    if (status === 401 || msg.includes('Incorrect API key'))
      throw new AIProviderError(msg, 'auth_failed', 'openai', false);
    if (status === 429)
      throw new AIProviderError(msg, 'rate_limited', 'openai', true);
    if (status === 402 || msg.includes('quota'))
      throw new AIProviderError(msg, 'quota_exceeded', 'openai', false);
    if (msg.includes('does not exist') || msg.includes('model_not_found'))
      throw new AIProviderError(msg, 'model_not_found', 'openai', false);
    if (msg.includes('maximum context length'))
      throw new AIProviderError(msg, 'context_too_long', 'openai', false);

    throw new AIProviderError(msg, 'unknown', 'openai', false);
  }

  async chat(messages: Message[], options?: ChatOptions): Promise<ChatResult> {
    try {
      const model = options?.model || this.defaultModel;
      const completion = await this.client.chat.completions.create({
        model,
        messages: this.mapMessages(messages),
        ...(options?.temperature != null ? { temperature: options.temperature } : {}),
        ...(options?.maxTokens ? { max_tokens: options.maxTokens } : {}),
      });

      const choice = completion.choices[0];
      return {
        content: choice?.message?.content || '',
        usage: {
          inputTokens: completion.usage?.prompt_tokens ?? 0,
          outputTokens: completion.usage?.completion_tokens ?? 0,
        },
        model: completion.model,
      };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }

  async chatWithTools(messages: Message[], tools: ToolDef[], options?: ChatOptions): Promise<ToolCallResult> {
    try {
      const model = options?.model || this.defaultModel;
      const completion = await this.client.chat.completions.create({
        model,
        messages: this.mapMessages(messages),
        tools: tools as any,
        tool_choice: 'auto',
        ...(options?.temperature != null ? { temperature: options.temperature } : {}),
        ...(options?.maxTokens ? { max_tokens: options.maxTokens } : {}),
      });

      const choice = completion.choices[0];
      const toolCalls = (choice?.message?.tool_calls || []).map(tc => ({
        name: tc.function.name,
        arguments: JSON.parse(tc.function.arguments || '{}'),
        id: tc.id,
      }));

      return {
        content: choice?.message?.content || '',
        usage: {
          inputTokens: completion.usage?.prompt_tokens ?? 0,
          outputTokens: completion.usage?.completion_tokens ?? 0,
        },
        model: completion.model,
        toolCalls,
      };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }

  async *streamChat(messages: Message[], options?: ChatOptions): AsyncIterable<StreamChunk> {
    try {
      const model = options?.model || this.defaultModel;
      const stream = await this.client.chat.completions.create({
        model,
        messages: this.mapMessages(messages),
        stream: true,
        ...(options?.temperature != null ? { temperature: options.temperature } : {}),
        ...(options?.maxTokens ? { max_tokens: options.maxTokens } : {}),
      });

      let inputTokens = 0;
      let outputTokens = 0;

      for await (const chunk of stream) {
        const delta = chunk.choices[0]?.delta;
        if (delta?.content) {
          yield { type: 'text', content: delta.content };
        }
        if (delta?.tool_calls?.[0]) {
          const tc = delta.tool_calls[0];
          yield {
            type: 'tool_call',
            toolCall: { name: tc.function?.name || '', arguments: tc.function?.arguments || '', id: tc.id || '' },
          };
        }
        if (chunk.usage) {
          inputTokens = chunk.usage.prompt_tokens ?? inputTokens;
          outputTokens = chunk.usage.completion_tokens ?? outputTokens;
        }
      }

      yield { type: 'done', usage: { inputTokens, outputTokens } };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }
}
