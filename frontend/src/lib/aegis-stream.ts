import { api } from './api';

export interface AegisContext {
  type: 'project' | 'vulnerability' | 'dependency' | 'semgrep' | 'secret';
  id: string;
  projectId?: string;
}

export interface StreamCallbacks {
  onChunk: (text: string) => void;
  onToolStart: (name: string) => void;
  onToolResult: (name: string, summary: string) => void;
  onDone: (fullContent: string, threadId: string, usage?: { inputTokens: number; outputTokens: number }) => void;
  onError: (message: string, code?: string) => void;
}

export async function streamAegisMessage(
  orgId: string,
  threadId: string | null,
  message: string,
  context: AegisContext | null,
  callbacks: StreamCallbacks,
  signal?: AbortSignal,
): Promise<void> {
  const response = await api.streamAegisMessage(
    orgId,
    threadId,
    message,
    context ? { type: context.type, id: context.id, projectId: context.projectId } : undefined,
  );

  const reader = response.body?.getReader();
  if (!reader) {
    callbacks.onError('No response stream available');
    return;
  }

  const decoder = new TextDecoder();
  let buffer = '';

  try {
    while (true) {
      if (signal?.aborted) break;

      const { done, value } = await reader.read();
      if (done) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';

      let eventType = '';
      for (const line of lines) {
        if (line.startsWith('event: ')) {
          eventType = line.slice(7).trim();
        } else if (line.startsWith('data: ')) {
          const data = line.slice(6);
          try {
            const parsed = JSON.parse(data);

            switch (eventType) {
              case 'chunk':
                if (parsed.content) callbacks.onChunk(parsed.content);
                break;
              case 'tool_start':
                callbacks.onToolStart(parsed.name);
                break;
              case 'tool_result':
                callbacks.onToolResult(parsed.name, parsed.summary);
                break;
              case 'done':
                callbacks.onDone(parsed.fullContent || '', parsed.threadId || '', parsed.usage);
                break;
              case 'error':
                callbacks.onError(parsed.message || 'Unknown error', parsed.code);
                break;
              case 'heartbeat':
                break;
            }
          } catch {
            // Skip malformed JSON
          }
          eventType = '';
        }
      }
    }
  } finally {
    reader.releaseLock();
  }
}

export function sanitizeStreamingMarkdown(text: string): string {
  let result = text;

  const tripleBacktickCount = (result.match(/```/g) || []).length;
  if (tripleBacktickCount % 2 !== 0) {
    const lastIdx = result.lastIndexOf('```');
    result = result.substring(0, lastIdx);
  }

  const boldCount = (result.match(/\*\*/g) || []).length;
  if (boldCount % 2 !== 0) {
    const lastIdx = result.lastIndexOf('**');
    result = result.substring(0, lastIdx);
  }

  const backtickCount = (result.match(/(?<!`)`(?!`)/g) || []).length;
  if (backtickCount % 2 !== 0) {
    const lastIdx = result.lastIndexOf('`');
    if (lastIdx >= 0 && result[lastIdx - 1] !== '`' && result[lastIdx + 1] !== '`') {
      result = result.substring(0, lastIdx);
    }
  }

  return result;
}
