export interface Message {
  role: 'system' | 'user' | 'assistant' | 'tool';
  content: string | null;
  name?: string;
  tool_call_id?: string;
}

export interface ChatOptions {
  model?: string;
  temperature?: number;
  maxTokens?: number;
}

export interface ChatResult {
  content: string;
  usage: { inputTokens: number; outputTokens: number };
  model: string;
}

export interface StreamChunk {
  type: 'text' | 'tool_call' | 'done' | 'error';
  content?: string;
  toolCall?: { name: string; arguments: string; id: string };
  usage?: { inputTokens: number; outputTokens: number };
}

export interface ToolDef {
  type: 'function';
  function: {
    name: string;
    description: string;
    parameters: Record<string, any>;
  };
}

export interface ToolCallResult extends ChatResult {
  toolCalls: Array<{ name: string; arguments: Record<string, any>; id: string }>;
}

export interface AIProvider {
  chat(messages: Message[], options?: ChatOptions): Promise<ChatResult>;
  chatWithTools(messages: Message[], tools: ToolDef[], options?: ChatOptions): Promise<ToolCallResult>;
  streamChat(messages: Message[], options?: ChatOptions): AsyncIterable<StreamChunk>;
}

export class AIProviderError extends Error {
  constructor(
    message: string,
    public code: 'auth_failed' | 'rate_limited' | 'quota_exceeded' | 'model_not_found' | 'context_too_long' | 'unknown',
    public provider: string,
    public retryable: boolean
  ) {
    super(message);
    this.name = 'AIProviderError';
  }
}
