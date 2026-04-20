import { streamText, stepCountIs, convertToModelMessages, type StreamTextResult, type ToolSet, type UIMessage } from 'ai';
import { getAegisModel } from './provider';
import { getAegisTools } from './tools';
import { buildSystemPrompt } from './system-prompt';
import type { MessagePart } from './types';

export interface StreamChatParams {
  organizationId: string;
  orgName: string;
  userId: string;
  uiMessages: UIMessage[];
  onFinishPersist: (payload: { text: string; parts: MessagePart[] }) => Promise<void>;
}

export async function streamChat(params: StreamChatParams): Promise<StreamTextResult<ToolSet, never>> {
  const { organizationId, orgName, userId, uiMessages, onFinishPersist } = params;
  const tools = getAegisTools({ organizationId, userId });
  const messages = await convertToModelMessages(uiMessages);

  return streamText({
    model: getAegisModel(),
    system: buildSystemPrompt({ orgName, organizationId }),
    messages,
    tools,
    stopWhen: stepCountIs(15),
    temperature: 0.2,
    onFinish: async (event) => {
      const parts: MessagePart[] = [];
      let text = '';
      for (const step of event.steps ?? [event]) {
        for (const part of step.content ?? []) {
          if (part.type === 'text') {
            parts.push({ type: 'text', text: part.text });
            text += part.text;
          } else if (part.type === 'tool-call') {
            parts.push({
              type: 'tool-call',
              toolCallId: part.toolCallId,
              toolName: part.toolName,
              args: (part as any).input ?? (part as any).args ?? {},
            });
          } else if (part.type === 'tool-result') {
            parts.push({
              type: 'tool-result',
              toolCallId: part.toolCallId,
              toolName: part.toolName,
              result: (part as any).output ?? (part as any).result,
            });
          } else if (part.type === 'tool-error') {
            parts.push({
              type: 'tool-result',
              toolCallId: (part as any).toolCallId,
              toolName: (part as any).toolName,
              result: { error: String((part as any).error ?? 'tool error') },
              isError: true,
            });
          }
        }
      }
      try {
        await onFinishPersist({ text, parts });
      } catch (err) {
        console.error('[aegis] persist assistant message failed', err);
      }
    },
  });
}
