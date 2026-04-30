import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport, type UIMessage } from 'ai';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { aegisApi, type AegisMessage, type MessagePart } from '../../lib/aegis-api';
import { getAuthToken } from '../../lib/api';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';

const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:3001';

const AEGIS_PROMPTS = [
  "What's my security posture?",
  'How many reachable vulnerabilities does my org have?',
  'Which projects are at highest risk?',
  'Are any of my secrets exposed?',
  'Which dependencies should I update first?',
  'Show me my critical CVEs',
];

const TYPE_MS = 55;
const BACKSPACE_MS = 30;
const HOLD_MS = 2400;

function useTypewriterPlaceholder(phrases: string[], enabled: boolean) {
  const [index, setIndex] = useState(0);
  const [visible, setVisible] = useState(0);
  const [phase, setPhase] = useState<'typing' | 'hold' | 'backspacing'>('typing');
  const phrase = phrases[index];

  useEffect(() => {
    if (!enabled) return;
    if (phase === 'hold') {
      const t = setTimeout(() => setPhase('backspacing'), HOLD_MS);
      return () => clearTimeout(t);
    }
    if (phase === 'typing') {
      if (visible >= phrase.length) { setPhase('hold'); return; }
      const t = setTimeout(() => setVisible((v) => v + 1), TYPE_MS);
      return () => clearTimeout(t);
    }
    if (visible <= 0) {
      setIndex((i) => (i + 1) % phrases.length);
      setPhase('typing');
      return;
    }
    const t = setTimeout(() => setVisible((v) => v - 1), BACKSPACE_MS);
    return () => clearTimeout(t);
  }, [phase, visible, phrase.length, phrases.length, enabled]);

  return phrase.slice(0, visible);
}

interface ChatPaneProps {
  organizationId: string;
  threadId?: string;
  currentUserId: string;
  displayName: string;
  onThreadCreated: (threadId: string) => void;
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

    return {
      id: msg.id,
      role: msg.role,
      parts,
      userId: msg.userId,
      error: msg.metadata?.error,
    } as unknown as UIMessage;
  });
}

export function ChatPane({
  organizationId,
  threadId: propThreadId,
  currentUserId,
  displayName,
  onThreadCreated,
  onThreadUpdated,
}: ChatPaneProps) {
  // We track the thread ID that THIS mount is working with. The prop may arrive
  // later (after a silent URL update). We never reset state just because the
  // prop appeared — the parent changes `key` when it wants a fresh mount.
  const [selfThreadId, setSelfThreadId] = useState<string | undefined>(propThreadId);
  const activeThreadId = selfThreadId ?? propThreadId;
  const activeThreadIdRef = useRef(activeThreadId);
  useEffect(() => { activeThreadIdRef.current = activeThreadId; });

  const [seedLoaded, setSeedLoaded] = useState(!propThreadId);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const onThreadCreatedRef = useRef(onThreadCreated);
  const onThreadUpdatedRef = useRef(onThreadUpdated);
  useEffect(() => { onThreadCreatedRef.current = onThreadCreated; });
  useEffect(() => { onThreadUpdatedRef.current = onThreadUpdated; });

  // The transport owns the actual fetch. We wrap it so we can:
  //   1. attach the auth bearer dynamically (token may rotate during a session)
  //   2. shape the request body the way our route expects (the v3 route reads
  //      `message` as a single string, not the full `messages[]` array — the
  //      backend re-loads history from the DB for itself)
  //   3. capture the X-Thread-Id response header and surface it back to the
  //      parent for URL/sidebar updates
  const transport = useMemo(
    () =>
      new DefaultChatTransport({
        api: `${API_BASE_URL}/api/aegis/v3/stream`,
        prepareSendMessagesRequest: ({ messages, body }) => {
          const lastUser = [...messages].reverse().find((m) => m.role === 'user');
          const text = (lastUser?.parts ?? [])
            .filter((p: any) => p.type === 'text')
            .map((p: any) => p.text ?? '')
            .join('\n');
          return {
            body: {
              ...(body ?? {}),
              organizationId,
              threadId: activeThreadIdRef.current,
              message: text,
            },
          };
        },
        fetch: async (input, init) => {
          const token = await getAuthToken();
          const headers = new Headers(init?.headers);
          if (token) headers.set('Authorization', `Bearer ${token}`);
          headers.set('Content-Type', 'application/json');
          const response = await fetch(input, { ...init, headers });
          const tid = response.headers.get('X-Thread-Id');
          if (tid && tid !== activeThreadIdRef.current) {
            setSelfThreadId(tid);
            onThreadCreatedRef.current(tid);
          }
          return response;
        },
      }),
    [organizationId],
  );

  const { messages, setMessages, sendMessage, regenerate, stop, status, error, clearError } =
    useChat({
      transport,
      onFinish: () => {
        setIsRegenerating(false);
        onThreadUpdatedRef.current?.();
      },
      onError: (err) => {
        // Never surface backend error text to the chat — it leaks DB columns
        // and reads as a system failure to the user. Real cause is in the
        // server logs; the user always sees a generic message.
        console.error('[aegis] chat error', err);
        setIsRegenerating(false);
        setSendError('Something went wrong. Please try again.');
      },
    });

  const isStreaming = status === 'streaming' || status === 'submitted';

  // One-shot seed load: if we mounted with a threadId prop, load history.
  // Never runs again — fresh thread = fresh mount via parent `key`.
  useEffect(() => {
    if (!propThreadId) return;
    let cancelled = false;
    aegisApi
      .getMessages(propThreadId)
      .then((msgs) => {
        if (cancelled) return;
        setMessages(buildInitialMessages(msgs));
        setSeedLoaded(true);
      })
      .catch(() => {
        if (cancelled) return;
        setSeedLoaded(true);
      });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = useCallback(
    (text: string) => {
      const trimmed = text.trim();
      if (!trimmed || isStreaming) return;
      setSendError(null);
      clearError();
      void sendMessage({ text: trimmed });
    },
    [isStreaming, sendMessage, clearError],
  );

  const handleRegenerate = useCallback(async () => {
    const tid = activeThreadIdRef.current;
    if (!tid || isStreaming || isRegenerating) return;
    setSendError(null);
    setIsRegenerating(true);
    try {
      // Server-side cleanup: delete the trailing assistant error row so the
      // DB matches what useChat is about to redo locally.
      await aegisApi.regenerate(tid);
      // useChat.regenerate slices off the trailing assistant in local state
      // and POSTs the trimmed history to /stream — exactly what we want.
      await regenerate();
    } catch (err: any) {
      console.error('[aegis] regenerate error', err);
      setIsRegenerating(false);
      setSendError('Something went wrong. Please try again.');
    }
  }, [isStreaming, isRegenerating, regenerate]);

  const handleStop = useCallback(() => {
    void stop();
  }, [stop]);

  // Index of the latest assistant error message — only that bubble shows the
  // Regenerate button so stacked older errors stay read-only.
  const latestErrorIdx = useMemo(() => {
    for (let i = messages.length - 1; i >= 0; i--) {
      const m = messages[i] as any;
      if (m.role === 'assistant' && m.error) return i;
      if (m.role === 'user') break;
    }
    return -1;
  }, [messages]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isStreaming]);

  // Surface useChat errors that fire before any tokens stream — e.g. provider
  // 5xx on the first chunk, or a network drop. Always show the same generic
  // message; the real cause is logged server-side and in the browser console.
  useEffect(() => {
    if (error) {
      console.error('[aegis] useChat error', error);
      setSendError('Something went wrong. Please try again.');
    }
  }, [error]);

  const showLanding = !activeThreadId && messages.length === 0 && (seedLoaded || !propThreadId);
  const placeholder = useTypewriterPlaceholder(AEGIS_PROMPTS, showLanding);

  if (showLanding) {
    return (
      <div className="flex h-full flex-col items-center justify-center px-6">
        <div className="w-full max-w-2xl -mt-12">
          <div className="mb-8">
            <div className="text-base text-foreground/60 mb-1">Hi {displayName}</div>
            <h1 className="text-3xl font-semibold text-foreground tracking-tight">
              What can I help you secure?
            </h1>
          </div>

          <div className="rounded-2xl bg-background-card border border-border">
            <ChatInput onSubmit={handleSubmit} placeholder={placeholder} autoFocus />
          </div>
          {sendError && (
            <div className="mt-3 text-sm text-red-500">{sendError}</div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 overflow-y-auto">
        <div className="py-4">
          {messages.map((m, i) => (
            <MessageBubble
              key={m.id}
              message={m}
              currentUserId={currentUserId}
              organizationId={organizationId}
              onRegenerate={i === latestErrorIdx ? handleRegenerate : undefined}
              isRegenerating={i === latestErrorIdx && isRegenerating}
            />
          ))}
          {isStreaming && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl flex items-center gap-3">
                <span
                  className="h-4 w-4 rounded-full bg-foreground/60 inline-block"
                  style={{ animation: 'aegis-thinking 1.6s ease-in-out infinite' }}
                />
                <button
                  type="button"
                  onClick={handleStop}
                  className="text-xs font-medium text-foreground/60 hover:text-foreground underline underline-offset-2"
                >
                  Stop
                </button>
              </div>
            </div>
          )}
          {sendError && !isStreaming && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl text-sm text-red-500">{sendError}</div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      </div>
      <div className="px-4 pb-4">
        <div className="mx-auto max-w-3xl">
          <div className="rounded-2xl bg-background-card border border-border">
            <ChatInput onSubmit={handleSubmit} disabled={isStreaming} placeholder="Ask anything" autoFocus />
          </div>
        </div>
      </div>

    </div>
  );
}
