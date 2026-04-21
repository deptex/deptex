import { type UIMessage } from 'ai';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { aegisApi, type AegisMessage, type AegisThread, type MessagePart } from '../../lib/aegis-api';
import { getAuthToken } from '../../lib/api';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { ParticipantsPanel } from './ParticipantsPanel';
import { AddPeopleModal } from './AddPeopleModal';
import { TypingIndicator } from './TypingIndicator';
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
  thread?: AegisThread;
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

    return { id: msg.id, role: msg.role, parts, userId: msg.userId } as unknown as UIMessage;
  });
}

export function ChatPane({
  organizationId,
  threadId: propThreadId,
  thread,
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
  const [sendError, setSendError] = useState<string | null>(null);
  const [participantsOpen, setParticipantsOpen] = useState(false);
  const [addPeopleOpen, setAddPeopleOpen] = useState(false);
  const [typingUsers, setTypingUsers] = useState<Record<string, { displayName: string; lastPing: number }>>({});
  const [participantNames, setParticipantNames] = useState<Record<string, string>>({});
  const bottomRef = useRef<HTMLDivElement>(null);
  const typingChannelRef = useRef<ReturnType<typeof supabase.channel> | null>(null);
  const lastTypingSentRef = useRef(0);

  // Keep latest onThreadUpdated in a ref so the Realtime effect doesn't tear
  // down on every parent render.
  const onThreadUpdatedRef = useRef(onThreadUpdated);
  useEffect(() => { onThreadUpdatedRef.current = onThreadUpdated; });

  const myDisplayName = useMemo(() => {
    const full = user?.user_metadata?.full_name as string | undefined;
    if (full) return full;
    if (user?.email) return user.email.split('@')[0];
    return 'Someone';
  }, [user]);

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

  const emitTyping = useCallback((typing: boolean) => {
    const channel = typingChannelRef.current;
    if (!channel) return;
    const now = Date.now();
    if (typing && now - lastTypingSentRef.current < 2000) return;
    lastTypingSentRef.current = typing ? now : 0;
    channel.send({
      type: 'broadcast',
      event: 'typing',
      payload: { userId: currentUserId, typing, displayName: myDisplayName },
    });
  }, [currentUserId, myDisplayName]);

  const handleSubmit = useCallback(async (text: string) => {
    const trimmed = text.trim();
    if (!trimmed || isGenerating) return;
    emitTyping(false);
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
  }, [organizationId, activeThreadId, currentUserId, isGenerating, emitTyping, onThreadCreated]);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
  }, [messages, isGenerating]);

  // Load participant names when we have an active thread.
  useEffect(() => {
    if (!activeThreadId) return;
    let cancelled = false;
    aegisApi.listParticipants(activeThreadId)
      .then((list) => {
        if (cancelled) return;
        const map: Record<string, string> = {};
        for (const p of list) map[p.userId] = p.displayName ?? p.email ?? 'Teammate';
        setParticipantNames(map);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [activeThreadId, thread?.participantCount]);

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

  // Typing broadcast channel.
  useEffect(() => {
    if (!activeThreadId) return;
    const channel = supabase.channel(`aegis-typing-${activeThreadId}`, { config: { broadcast: { self: false } } });
    channel
      .on('broadcast', { event: 'typing' }, (payload) => {
        const data = (payload as any).payload as { userId: string; typing: boolean; displayName: string };
        if (!data || data.userId === currentUserId) return;
        setTypingUsers((prev) => {
          if (!data.typing) {
            const next = { ...prev };
            delete next[data.userId];
            return next;
          }
          return { ...prev, [data.userId]: { displayName: data.displayName, lastPing: Date.now() } };
        });
      })
      .subscribe();
    typingChannelRef.current = channel;
    return () => {
      supabase.removeChannel(channel);
      typingChannelRef.current = null;
    };
  }, [activeThreadId, currentUserId]);

  useEffect(() => {
    if (Object.keys(typingUsers).length === 0) return;
    const interval = setInterval(() => {
      setTypingUsers((prev) => {
        const now = Date.now();
        let changed = false;
        const next: typeof prev = {};
        for (const [uid, entry] of Object.entries(prev)) {
          if (now - entry.lastPing < 3000) next[uid] = entry;
          else changed = true;
        }
        return changed ? next : prev;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [typingUsers]);

  const handleInputChange = useCallback(() => {
    emitTyping(true);
  }, [emitTyping]);

  const handleEdit = useCallback(async (messageId: string, newText: string) => {
    try {
      await aegisApi.truncateBelow(messageId);
    } catch { /* ignore */ }
    setMessages((prev) => {
      const idx = prev.findIndex((m) => m.id === messageId);
      return idx === -1 ? prev : prev.slice(0, idx);
    });
    void handleSubmit(newText);
  }, [handleSubmit]);

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
          {!seedLoaded && activeThreadId && (
            <div className="flex h-full items-center justify-center text-sm text-foreground/40">Loading…</div>
          )}
          {messages.map((m) => (
            <MessageBubble
              key={m.id}
              message={m}
              currentUserId={currentUserId}
              participantNames={participantNames}
              disabled={isGenerating}
              onEdit={!m.id.startsWith('temp-') && m.role === 'user' && (m as any).userId === currentUserId ? (newText) => void handleEdit(m.id, newText) : undefined}
            />
          ))}
          {isGenerating && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl flex gap-3 items-center text-sm text-foreground/60">
                <span className="flex gap-1">
                  <span className="h-1.5 w-1.5 rounded-full bg-foreground/40 animate-bounce [animation-delay:0ms]" />
                  <span className="h-1.5 w-1.5 rounded-full bg-foreground/40 animate-bounce [animation-delay:150ms]" />
                  <span className="h-1.5 w-1.5 rounded-full bg-foreground/40 animate-bounce [animation-delay:300ms]" />
                </span>
              </div>
            </div>
          )}
          {sendError && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl text-sm text-red-500">{sendError}</div>
            </div>
          )}
          <TypingIndicator
            users={Object.entries(typingUsers).map(([userId, entry]) => ({ userId, displayName: entry.displayName }))}
          />
          <div ref={bottomRef} />
        </div>
      </div>
      <ChatInput onSubmit={handleSubmit} onChange={handleInputChange} disabled={isGenerating} autoFocus />

      {activeThreadId && (
        <>
          <ParticipantsPanel
            open={participantsOpen}
            onOpenChange={setParticipantsOpen}
            threadId={activeThreadId}
            currentUserId={currentUserId}
            isCreator={thread?.isCreator ?? false}
            onOpenAddPeople={() => { setParticipantsOpen(false); setAddPeopleOpen(true); }}
            onParticipantsChanged={() => onThreadUpdated?.()}
          />
          <AddPeopleModal
            open={addPeopleOpen}
            onOpenChange={setAddPeopleOpen}
            organizationId={organizationId}
            threadId={activeThreadId}
            onAdded={() => onThreadUpdated?.()}
          />
        </>
      )}
    </div>
  );
}
