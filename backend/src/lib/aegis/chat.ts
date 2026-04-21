import { generateText } from 'ai';
import { getAegisModel } from './provider';
import { buildSystemPrompt } from './system-prompt';
import type { MessagePart } from './types';

export interface GenerateChatParams {
  organizationId: string;
  orgName: string;
  userId: string;
  senderName?: string | null;
  senderRole?: string | null;
  messages: Array<{ role: 'user' | 'assistant'; content: string }>;
}

export async function generateChat(
  params: GenerateChatParams,
): Promise<{ text: string; parts: MessagePart[] }> {
  const { organizationId, orgName, senderName, senderRole, messages } = params;

  const coreMessages = messages.map((m) => ({
    role: m.role as 'user' | 'assistant',
    content: m.content,
  }));

  const { text } = await generateText({
    model: getAegisModel(),
    system: buildSystemPrompt({ orgName, organizationId, senderName, senderRole }),
    messages: coreMessages,
    temperature: 0.2,
  });

  const result = text ?? '';
  const parts: MessagePart[] = result ? [{ type: 'text', text: result }] : [];
  return { text: result, parts };
}
