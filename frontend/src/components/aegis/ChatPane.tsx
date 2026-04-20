import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport, type UIMessage } from 'ai';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { aegisApi, type AegisMessage, type MessagePart } from '../../lib/aegis-api';
import { getAuthToken } from '../../lib/api';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { Loader2 } from 'lucide-react';

const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:3001';

interface ChatPaneProps {
  threadId: string;
  organizationId: string;
  initialMessage?: string;
  onThreadUpdated?: () => void;
}

function buildInitialMessages(stored: AegisMessage[]): UIMessage[] {
  return stored.map((msg) => {
    const parts: any[] = [];
    const rawParts: MessagePart[] = msg.metadata?.parts ?? [];

    const callById = new Map<string, { toolName: string; input: unknown }>();
    for (const p of rawParts) {
      if (p.type === 'tool-call') callById.set(p.toolCallId, { toolName: p.toolName, input: p.args });
    }

    let hasText = false;
    for (const p of rawParts) {
      if (p.type === 'text') {
        parts.push({ type: 'text', text: p.text });
        hasText = true;
      } else if (p.type === 'tool-call') {
        // emitted via paired tool-result below
      } else if (p.type === 'tool-result') {
        const call = callById.get(p.toolCallId);
        parts.push({
          type: 'dynamic-tool',
          toolName: p.toolName ?? call?.toolName ?? 'tool',
          toolCallId: p.toolCallId,
          state: p.isError ? 'output-error' : 'output-available',
          input: call?.input,
          output: p.isError ? undefined : p.result,
          errorText: p.isError ? String(p.result ?? 'error') : undefined,
        });
      }
    }

    if (!hasText && msg.content) parts.unshift({ type: 'text', text: msg.content });
    if (parts.length === 0) parts.push({ type: 'text', text: msg.content ?? '' });

    return { id: msg.id, role: msg.role, parts } as unknown as UIMessage;
  });
}

export function ChatPane({ threadId, organizationId, initialMessage, onThreadUpdated }: ChatPaneProps) {
  const [seed, setSeed] = useState<UIMessage[] | null>(null);
  const [seedError, setSeedError] = useState<string | null>(null);
  const initialSentRef = useRef(false);
  const autoTitleDoneRef = useRef(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    setSeed(null);
    setSeedError(null);
    initialSentRef.current = false;
    autoTitleDoneRef.current = false;
    aegisApi
      .getMessages(threadId)
      .then((msgs) => {
        if (cancelled) return;
        setSeed(buildInitialMessages(msgs));
      })
      .catch((err) => {
        if (cancelled) return;
        setSeedError(err?.message ?? 'Failed to load messages');
      });
    return () => { cancelled = true; };
  }, [threadId]);

  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: `${API_BASE_URL}/api/aegis/chat`,
        headers: async (): Promise<Record<string, string>> => {
          const token = await getAuthToken();
          return token ? { Authorization: `Bearer ${token}` } : {};
        },
        body: { threadId, organizationId },
      }),
    [threadId, organizationId],
  );

  const { messages, sendMessage, setMessages, status, error } = useChat({
    id: threadId,
    transport,
    messages: seed ?? undefined,
    onFinish: () => {
      if (!autoTitleDoneRef.current) {
        autoTitleDoneRef.current = true;
        aegisApi
          .autoTitle(threadId)
          .then(() => onThreadUpdated?.())
          .catch(() => {});
      }
    },
  });

  // Auto-send the queued initialMessage from the landing chat bar once seed loads.
  useEffect(() => {
    if (!seed || initialSentRef.current || !initialMessage) return;
    if (seed.length > 0) { initialSentRef.current = true; return; }
    initialSentRef.current = true;
    void sendMessage({ text: initialMessage });
  }, [seed, initialMessage, sendMessage]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, status]);

  const handleSubmit = useCallback((text: string) => {
    void sendMessage({ text });
  }, [sendMessage]);

  const isStreaming = status === 'streaming' || status === 'submitted';

  const handleEdit = useCallback(async (userId: string, newText: string) => {
    try {
      await aegisApi.truncateBelow(userId);
    } catch { /* ignore */ }
    setMessages((prev) => {
      const idx = prev.findIndex((m) => m.id === userId);
      return idx === -1 ? prev : prev.slice(0, idx);
    });
    autoTitleDoneRef.current = true;
    void sendMessage({ text: newText });
  }, [sendMessage, setMessages]);


  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 overflow-y-auto">
        {seed === null && !seedError && (
          <div className="flex h-full items-center justify-center text-sm text-foreground/60">
            <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading…
          </div>
        )}
        {seedError && (
          <div className="flex h-full items-center justify-center text-sm text-red-500">{seedError}</div>
        )}
        {seed !== null && (
          <div className="py-4">
            {messages.map((m) => (
              <MessageBubble
                key={m.id}
                message={m}
                disabled={isStreaming}
                onEdit={m.role === 'user' ? (newText) => void handleEdit(m.id, newText) : undefined}
              />
            ))}
            {isStreaming && messages[messages.length - 1]?.role === 'user' && (
              <div className="px-4 py-3">
                <div className="mx-auto max-w-3xl flex gap-3 items-center text-sm text-foreground/60">
                  <Loader2 className="h-3.5 w-3.5 animate-spin" /> Thinking…
                </div>
              </div>
            )}
            {error && (
              <div className="px-4 py-3">
                <div className="mx-auto max-w-3xl text-sm text-red-500">
                  {error.message || 'Something went wrong.'}
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>
        )}
      </div>
      <ChatInput onSubmit={handleSubmit} disabled={isStreaming} autoFocus />
    </div>
  );
}
