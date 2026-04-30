import { type UIMessage } from 'ai';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { aegisApi, type AegisMessage, type AegisThread, type MessagePart } from '../../lib/aegis-api';
import { getAuthToken } from '../../lib/api';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { supabase } from '../../lib/supabase';
import { useAuth } from '../../contexts/AuthContext';

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
  const { user } = useAuth();
  // We track the thread ID that THIS mount is working with. The prop may arrive
  // later (after a silent URL update). We never reset state just because the
  // prop appeared — the parent changes `key` when it wants a fresh mount.
  const [selfThreadId, setSelfThreadId] = useState<string | undefined>(propThreadId);
  const activeThreadId = selfThreadId ?? propThreadId;

  const [messages, setMessages] = useState<UIMessage[]>([]);
  const [seedLoaded, setSeedLoaded] = useState(!propThreadId);
  const [isGenerating, setIsGenerating] = useState(false);
  const [isRegenerating, setIsRegenerating] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Keep latest onThreadUpdated in a ref so the Realtime effect doesn't tear
  // down on every parent render.
  const onThreadUpdatedRef = useRef(onThreadUpdated);
  useEffect(() => { onThreadUpdatedRef.current = onThreadUpdated; });

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

  const handleSubmit = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isGenerating) return;
    setSendError(null);

    const tempId = `temp-${Date.now()}`;
    const tempMsg: UIMessage = {
      id: tempId,
      role: 'user',
      parts: [{ type: 'text', text: trimmed }],
      userId: currentUserId,
    } as unknown as UIMessage;
    setMessages((prev) => [...prev, tempMsg]);
    setIsGenerating(true);

    try {
      const token = await getAuthToken();
      const response = await fetch(`${API_BASE_URL}/api/aegis/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ organizationId, threadId: activeThreadId, message: trimmed }),
      });
      if (!response.ok) {
        const err = await response.json().catch(() => ({}));
        throw new Error((err as any).error || 'Failed to send message');
      }
      const data = (await response.json()) as { threadId: string };
      if (!activeThreadId && data.threadId) {
        setSelfThreadId(data.threadId);
        onThreadCreated(data.threadId);
      }
    } catch (err: any) {
      setIsGenerating(false);
      setMessages((prev) => prev.filter((m) => m.id !== tempId));
      setSendError(err?.message ?? 'Failed to send message');
    }
  }, [organizationId, activeThreadId, currentUserId, isGenerating, onThreadCreated]);

  const handleRegenerate = useCallback(async () => {
    if (!activeThreadId || isGenerating || isRegenerating) return;
    setSendError(null);
    setIsRegenerating(true);
    setIsGenerating(true);
    // Optimistically drop the trailing assistant error bubble so the typing
    // indicator can take its place — the backend will delete it server-side.
    setMessages((prev) => {
      for (let i = prev.length - 1; i >= 0; i--) {
        const m = prev[i] as any;
        if (m.role === 'assistant' && m.error) {
          return prev.filter((_, idx) => idx !== i);
        }
        if (m.role === 'user') break;
      }
      return prev;
    });

    try {
      await aegisApi.regenerate(activeThreadId);
    } catch (err: any) {
      setIsGenerating(false);
      setIsRegenerating(false);
      setSendError(err?.message ?? 'Failed to regenerate response');
    }
  }, [activeThreadId, isGenerating, isRegenerating]);

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
  }, [messages, isGenerating]);

  // Realtime subscription on aegis_chat_messages for this thread.
  // Kicks in once we have an activeThreadId (either from prop or from a
  // just-created thread). Doesn't depend on onThreadUpdated — uses the ref.
  useEffect(() => {
    if (!activeThreadId) return;
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;

    (async () => {
      // Ensure Realtime uses the authenticated user's JWT. Without this, the
      // first channel after page-load can race the auth wiring and subscribe
      // as anon — RLS then filters out every postgres_changes event.
      const { data: { session } } = await supabase.auth.getSession();
      await (supabase.realtime as any).setAuth(session?.access_token ?? null);
      if (cancelled) return;

      channel = supabase
        .channel(`aegis-thread-${activeThreadId}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'aegis_chat_messages', filter: `thread_id=eq.${activeThreadId}` },
        (payload) => {
          const row = payload.new as any;
          if (row.role === 'user' && row.user_id === currentUserId) return;
          setMessages((prev) => {
            if (prev.some((m) => m.id === row.id)) return prev;
            const [uiMsg] = buildInitialMessages([
              {
                id: row.id,
                threadId: row.thread_id,
                role: row.role,
                userId: row.user_id ?? null,
                content: row.content ?? '',
                metadata: row.metadata ?? { parts: [] },
                createdAt: row.created_at,
              },
            ]);
            return [...prev, uiMsg];
          });
          if (row.role === 'assistant') {
            setIsGenerating(false);
            setIsRegenerating(false);
            onThreadUpdatedRef.current?.();
          }
        },
      )
      .subscribe();
    })();

    return () => {
      cancelled = true;
      if (channel) supabase.removeChannel(channel);
    };
  }, [activeThreadId, currentUserId]);

  const showLanding = !activeThreadId && messages.length === 0;
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
          {isGenerating && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl">
                <span
                  className="h-4 w-4 rounded-full bg-foreground/60 inline-block"
                  style={{ animation: 'aegis-thinking 1.6s ease-in-out infinite' }}
                />
              </div>
            </div>
          )}
          {sendError && (
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
            <ChatInput onSubmit={handleSubmit} disabled={isGenerating} placeholder="Ask anything" autoFocus />
          </div>
        </div>
      </div>

    </div>
  );
}
