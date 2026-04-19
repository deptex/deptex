import Anthropic from '@anthropic-ai/sdk';
import { AIProvider, AIProviderError, Message, ChatOptions, ChatResult, ToolDef, ToolCallResult, StreamChunk } from '../types';

export class AnthropicProvider implements AIProvider {
  private client: Anthropic;
  private defaultModel: string;

  constructor(apiKey: string, model?: string) {
    this.client = new Anthropic({ apiKey });
    this.defaultModel = model || 'claude-sonnet-4-20250514';
  }

  private prepareMessages(messages: Message[]): { system: string; msgs: Array<{ role: 'user' | 'assistant'; content: string }> } {
    let system = '';
    const msgs: Array<{ role: 'user' | 'assistant'; content: string }> = [];

    for (const m of messages) {
      if (m.role === 'system') {
        system += (system ? '\n\n' : '') + (m.content || '');
      } else if (m.role === 'user' || m.role === 'assistant') {
        msgs.push({ role: m.role, content: m.content || '' });
      } else if (m.role === 'tool') {
        msgs.push({ role: 'user', content: `[Tool result for ${m.tool_call_id || 'unknown'}]: ${m.content || ''}` });
      }
    }

    return { system, msgs };
  }

  private mapTools(tools: ToolDef[]): Anthropic.Tool[] {
    return tools.map(t => ({
      name: t.function.name,
      description: t.function.description,
      input_schema: t.function.parameters as Anthropic.Tool.InputSchema,
    }));
  }

  private mapError(err: any): never {
    const msg = err?.message || String(err);
    const status = err?.status;

    if (status === 401 || msg.includes('invalid x-api-key'))
      throw new AIProviderError(msg, 'auth_failed', 'anthropic', false);
    if (status === 429)
      throw new AIProviderError(msg, 'rate_limited', 'anthropic', true);
    if (msg.includes('billing') || msg.includes('credit'))
      throw new AIProviderError(msg, 'quota_exceeded', 'anthropic', false);
    if (msg.includes('model') && msg.includes('not'))
      throw new AIProviderError(msg, 'model_not_found', 'anthropic', false);
    if (msg.includes('too long') || msg.includes('token'))
      throw new AIProviderError(msg, 'context_too_long', 'anthropic', false);

    throw new AIProviderError(msg, 'unknown', 'anthropic', false);
  }

  async chat(messages: Message[], options?: ChatOptions): Promise<ChatResult> {
    try {
      const { system, msgs } = this.prepareMessages(messages);
      const model = options?.model || this.defaultModel;
      const response = await this.client.messages.create({
        model,
        max_tokens: options?.maxTokens || 4096,
        system: system || undefined,
        messages: msgs,
        ...(options?.temperature != null ? { temperature: options.temperature } : {}),
      });

      const textBlocks = response.content.filter(b => b.type === 'text');
      return {
        content: textBlocks.map(b => (b as any).text).join(''),
        usage: {
          inputTokens: response.usage.input_tokens,
          outputTokens: response.usage.output_tokens,
        },
        model: response.model,
      };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }

  async chatWithTools(messages: Message[], tools: ToolDef[], options?: ChatOptions): Promise<ToolCallResult> {
    try {
      const { system, msgs } = this.prepareMessages(messages);
      const model = options?.model || this.defaultModel;
      const response = await this.client.messages.create({
        model,
        max_tokens: options?.maxTokens || 4096,
        system: system || undefined,
        messages: msgs,
        tools: this.mapTools(tools),
        ...(options?.temperature != null ? { temperature: options.temperature } : {}),
      });

      const textBlocks = response.content.filter(b => b.type === 'text');
      const toolUseBlocks = response.content.filter(b => b.type === 'tool_use');

      const toolCalls = toolUseBlocks.map(b => {
        const tu = b as any;
        return {
          name: tu.name as string,
          arguments: tu.input as Record<string, any>,
          id: tu.id as string,
        };
      });

      return {
        content: textBlocks.map(b => (b as any).text).join(''),
        usage: {
          inputTokens: response.usage.input_tokens,
          outputTokens: response.usage.output_tokens,
        },
        model: response.model,
        toolCalls,
      };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }

  async *streamChat(messages: Message[], options?: ChatOptions): AsyncIterable<StreamChunk> {
    try {
      const { system, msgs } = this.prepareMessages(messages);
      const model = options?.model || this.defaultModel;

      const stream = this.client.messages.stream({
        model,
        max_tokens: options?.maxTokens || 4096,
        system: system || undefined,
        messages: msgs,
        ...(options?.temperature != null ? { temperature: options.temperature } : {}),
      });

      let inputTokens = 0;
      let outputTokens = 0;

      for await (const event of stream) {
        if (event.type === 'content_block_delta') {
          const delta = (event as any).delta;
          if (delta?.type === 'text_delta' && delta.text) {
            yield { type: 'text', content: delta.text };
          }
        }
        if (event.type === 'message_delta') {
          const usage = (event as any).usage;
          if (usage) {
            outputTokens = usage.output_tokens ?? outputTokens;
          }
        }
        if (event.type === 'message_start') {
          const msg = (event as any).message;
          if (msg?.usage) {
            inputTokens = msg.usage.input_tokens ?? inputTokens;
          }
        }
      }

      yield { type: 'done', usage: { inputTokens, outputTokens } };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }
}
