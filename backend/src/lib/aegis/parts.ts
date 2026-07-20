import type { MessagePart } from './types';

type StepLike = {
  text?: string;
  toolCalls?: Array<{
    toolCallId: string;
    toolName: string;
    input?: unknown;
  }>;
  toolResults?: Array<{
    toolCallId: string;
    toolName: string;
    output?: unknown;
  }>;
};

// Convert ToolLoopAgent step results into the MessagePart shape stored in
// aegis_chat_messages.metadata.parts. ChatPane.buildInitialMessages pairs
// tool-call/tool-result by toolCallId and emits a single dynamic-tool UI
// part per call for MessageBubble — so on history reload the streamed
// turn renders identically to a turn that came in via the streaming path.
export function stepsToMessageParts(steps: ReadonlyArray<unknown>): MessagePart[] {
  const parts: MessagePart[] = [];
  for (const stepUnknown of steps) {
    const step = stepUnknown as StepLike;

    if (typeof step.text === 'string' && step.text.length > 0) {
      parts.push({ type: 'text', text: step.text });
    }

    const resultByCallId = new Map<string, unknown>();
    for (const r of step.toolResults ?? []) {
      resultByCallId.set(r.toolCallId, r.output);
    }

    for (const call of step.toolCalls ?? []) {
      const args =
        call.input && typeof call.input === 'object'
          ? (call.input as Record<string, unknown>)
          : {};
      parts.push({
        type: 'tool-call',
        toolCallId: call.toolCallId,
        toolName: call.toolName,
        args,
      });

      if (resultByCallId.has(call.toolCallId)) {
        const output = resultByCallId.get(call.toolCallId);
        const isError =
          !!output &&
          typeof output === 'object' &&
          'error' in (output as Record<string, unknown>);
        parts.push({
          type: 'tool-result',
          toolCallId: call.toolCallId,
          toolName: call.toolName,
          result: output,
          ...(isError ? { isError: true } : {}),
        });
      }
    }
  }
  return parts;
}
