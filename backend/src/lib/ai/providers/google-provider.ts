import { GoogleGenerativeAI, GenerativeModel, Content, FunctionDeclaration, SchemaType } from '@google/generative-ai';
import { AIProvider, AIProviderError, Message, ChatOptions, ChatResult, ToolDef, ToolCallResult, StreamChunk } from '../types';

export class GoogleProvider implements AIProvider {
  private genAI: GoogleGenerativeAI;
  private defaultModel: string;

  constructor(apiKey: string, model?: string) {
    this.genAI = new GoogleGenerativeAI(apiKey);
    this.defaultModel = model || 'gemini-2.5-flash';
  }

  private getModel(modelName?: string): GenerativeModel {
    return this.genAI.getGenerativeModel({ model: modelName || this.defaultModel });
  }

  private mapMessages(messages: Message[]): { systemInstruction: string; contents: Content[] } {
    let systemInstruction = '';
    const contents: Content[] = [];

    for (const m of messages) {
      if (m.role === 'system') {
        systemInstruction += (systemInstruction ? '\n\n' : '') + (m.content || '');
      } else if (m.role === 'user' || m.role === 'tool') {
        contents.push({ role: 'user', parts: [{ text: m.content || '' }] });
      } else if (m.role === 'assistant') {
        contents.push({ role: 'model', parts: [{ text: m.content || '' }] });
      }
    }

    return { systemInstruction, contents };
  }

  private mapTools(tools: ToolDef[]): FunctionDeclaration[] {
    return tools.map(t => ({
      name: t.function.name,
      description: t.function.description,
      parameters: this.convertJsonSchemaToGemini(t.function.parameters),
    }));
  }

  private convertJsonSchemaToGemini(schema: Record<string, any>): any {
    if (!schema) return { type: SchemaType.OBJECT, properties: {} };

    const result: any = {};
    if (schema.type === 'object') {
      result.type = SchemaType.OBJECT;
      result.properties = {};
      if (schema.properties) {
        for (const [key, value] of Object.entries(schema.properties)) {
          result.properties[key] = this.convertJsonSchemaToGemini(value as any);
        }
      }
      if (schema.required) result.required = schema.required;
    } else if (schema.type === 'string') {
      result.type = SchemaType.STRING;
      if (schema.description) result.description = schema.description;
    } else if (schema.type === 'number' || schema.type === 'integer') {
      result.type = SchemaType.NUMBER;
      if (schema.description) result.description = schema.description;
    } else if (schema.type === 'boolean') {
      result.type = SchemaType.BOOLEAN;
      if (schema.description) result.description = schema.description;
    } else if (schema.type === 'array') {
      result.type = SchemaType.ARRAY;
      if (schema.items) result.items = this.convertJsonSchemaToGemini(schema.items);
    }

    return result;
  }

  private mapError(err: any): never {
    const msg = err?.message || String(err);

    if (msg.includes('API_KEY_INVALID') || msg.includes('API key not valid'))
      throw new AIProviderError(msg, 'auth_failed', 'google', false);
    if (msg.includes('RESOURCE_EXHAUSTED') || msg.includes('429'))
      throw new AIProviderError(msg, 'rate_limited', 'google', true);
    if (msg.includes('quota') || msg.includes('billing'))
      throw new AIProviderError(msg, 'quota_exceeded', 'google', false);
    if (msg.includes('not found') || msg.includes('is not supported'))
      throw new AIProviderError(msg, 'model_not_found', 'google', false);
    if (msg.includes('too long') || msg.includes('token limit'))
      throw new AIProviderError(msg, 'context_too_long', 'google', false);

    throw new AIProviderError(msg, 'unknown', 'google', false);
  }

  async chat(messages: Message[], options?: ChatOptions): Promise<ChatResult> {
    try {
      const model = this.getModel(options?.model);
      const { systemInstruction, contents } = this.mapMessages(messages);

      // Gemini can reject system_instruction on generateContent; prepend as first user message instead
      const history = contents.slice(0, -1);
      if (systemInstruction) {
        history.unshift({ role: 'user', parts: [{ text: `[System instructions - follow these]\n\n${systemInstruction}` }] });
      }

      const chat = model.startChat({
        history,
      });

      const lastContent = contents[contents.length - 1];
      const result = await chat.sendMessage(lastContent?.parts?.map(p => (p as any).text).join('') || '');
      const response = result.response;

      return {
        content: response.text(),
        usage: {
          inputTokens: response.usageMetadata?.promptTokenCount ?? 0,
          outputTokens: response.usageMetadata?.candidatesTokenCount ?? 0,
        },
        model: options?.model || this.defaultModel,
      };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }

  async chatWithTools(messages: Message[], tools: ToolDef[], options?: ChatOptions): Promise<ToolCallResult> {
    try {
      const modelName = options?.model || this.defaultModel;
      const model = this.genAI.getGenerativeModel({
        model: modelName,
        tools: [{ functionDeclarations: this.mapTools(tools) }],
      });

      const { systemInstruction, contents } = this.mapMessages(messages);

      const chat = model.startChat({
        history: contents.slice(0, -1),
        ...(systemInstruction ? { systemInstruction } : {}),
      });

      const lastContent = contents[contents.length - 1];
      const result = await chat.sendMessage(lastContent?.parts?.map(p => (p as any).text).join('') || '');
      const response = result.response;

      const toolCalls: Array<{ name: string; arguments: Record<string, any>; id: string }> = [];
      for (const candidate of response.candidates || []) {
        for (const part of candidate.content?.parts || []) {
          if ((part as any).functionCall) {
            const fc = (part as any).functionCall;
            toolCalls.push({
              name: fc.name,
              arguments: fc.args || {},
              id: `call_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
            });
          }
        }
      }

      return {
        content: response.text() || '',
        usage: {
          inputTokens: response.usageMetadata?.promptTokenCount ?? 0,
          outputTokens: response.usageMetadata?.candidatesTokenCount ?? 0,
        },
        model: modelName,
        toolCalls,
      };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }

  async *streamChat(messages: Message[], options?: ChatOptions): AsyncIterable<StreamChunk> {
    try {
      const model = this.getModel(options?.model);
      const { systemInstruction, contents } = this.mapMessages(messages);

      // Gemini streaming does not support system_instruction (400 Bad Request). Prepend it as the first user message.
      const history = contents.slice(0, -1);
      const lastContent = contents[contents.length - 1];
      if (systemInstruction) {
        history.unshift({ role: 'user', parts: [{ text: `[System instructions - follow these]\n\n${systemInstruction}` }] });
      }

      const chat = model.startChat({
        history,
      });

      const result = await chat.sendMessageStream(lastContent?.parts?.map(p => (p as any).text).join('') || '');

      let inputTokens = 0;
      let outputTokens = 0;

      for await (const chunk of result.stream) {
        const text = chunk.text();
        if (text) {
          yield { type: 'text', content: text };
        }
        if (chunk.usageMetadata) {
          inputTokens = chunk.usageMetadata.promptTokenCount ?? inputTokens;
          outputTokens = chunk.usageMetadata.candidatesTokenCount ?? outputTokens;
        }
      }

      yield { type: 'done', usage: { inputTokens, outputTokens } };
    } catch (err: any) {
      if (err instanceof AIProviderError) throw err;
      this.mapError(err);
    }
  }
}
