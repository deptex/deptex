// Shared part-shape helpers for Aegis chat. The same parts array surfaces
// in three real shapes — live `tool-<name>` from the Vercel AI SDK stream,
// `tool-call`/`tool-result` from the persisted message metadata, and the
// rehydrated `dynamic-tool` shape ChatPane builds in buildInitialMessages.
// Both MessageBubble's tool dispatcher and aegis-todos.deriveTodos go
// through these helpers so they can't drift out of sync and silently
// render-nothing on one of the three.

export function isToolPart(part: any): boolean {
  return (
    part?.type === 'dynamic-tool' ||
    (typeof part?.type === 'string' && part.type.startsWith('tool-'))
  );
}

export function toolNameFor(part: any): string {
  if (part?.toolName) return part.toolName as string;
  if (typeof part?.type === 'string' && part.type.startsWith('tool-')) {
    return part.type.replace(/^tool-/, '');
  }
  return 'tool';
}

export function toolArgs(part: any): any {
  return part?.args ?? part?.input ?? {};
}
