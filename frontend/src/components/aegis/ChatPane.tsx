import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport, type UIMessage } from 'ai';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { aegisApi, type AegisMessage, type AegisThread, type MessagePart } from '../../lib/aegis-api';
import { getAuthToken } from '../../lib/api';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { ParticipantsPanel } from './ParticipantsPanel';
import { AddPeopleModal } from './AddPeopleModal';
import { TypingIndicator } from './TypingIndicator';
import { Loader2, Users } from 'lucide-react';
import { supabase } from '../../lib/supabase';
import { useAuth } from '../../contexts/AuthContext';

const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:3001';

interface ChatPaneProps {
  threadId: string;
  organizationId: string;
  thread?: AegisThread;
  currentUserId: string;
  initialMessage?: string;
  onThreadUpdated?: () => void;
  onLeaveThread?: () => void;
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

    // Stash userId as an extra (non-standard) field so MessageBubble can show
    // authorship in shared threads. The AI SDK doesn't read this.
    return { id: msg.id, role: msg.role, parts, userId: msg.userId } as unknown as UIMessage;
  });
}

export function ChatPane({ threadId, organizationId, thread, currentUserId, initialMessage, onThreadUpdated }: ChatPaneProps) {
  const { user } = useAuth();
  const [seed, setSeed] = useState<UIMessage[] | null>(null);
  const [seedError, setSeedError] = useState<string | null>(null);
  const [participantsOpen, setParticipantsOpen] = useState(false);
  const [addPeopleOpen, setAddPeopleOpen] = useState(false);
  const [typingUsers, setTypingUsers] = useState<Record<string, { displayName: string; lastPing: number }>>({});
  const [participantNames, setParticipantNames] = useState<Record<string, string>>({});
  const initialSentRef = useRef(false);
  const autoTitleDoneRef = useRef(false);
  const bottomRef = useRef<HTMLDivElement>(null);
  const typingChannelRef = useRef<ReturnType<typeof supabase.channel> | null>(null);
  const lastTypingSentRef = useRef(0);

  const myDisplayName = useMemo(() => {
    const full = user?.user_metadata?.full_name as string | undefined;
    if (full) return full;
    if (user?.email) return user.email.split('@')[0];
    return 'Someone';
  }, [user]);

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

  // Load participant display names for authorship rendering in shared threads.
  useEffect(() => {
    let cancelled = false;
    aegisApi.listParticipants(threadId)
      .then((list) => {
        if (cancelled) return;
        const map: Record<string, string> = {};
        for (const p of list) map[p.userId] = p.displayName ?? p.email ?? 'Teammate';
        setParticipantNames(map);
      })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [threadId, thread?.participantCount]);

  // Realtime: merge messages from other participants.
  useEffect(() => {
    const channel = supabase
      .channel(`aegis-thread-${threadId}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'aegis_chat_messages', filter: `thread_id=eq.${threadId}` },
        (payload) => {
          const row = payload.new as any;
          // Skip my own messages (already in local state via useChat).
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
        },
      )
      .subscribe();
    return () => { supabase.removeChannel(channel); };
  }, [threadId, currentUserId, setMessages]);

  // Typing broadcast channel.
  useEffect(() => {
    const channel = supabase.channel(`aegis-typing-${threadId}`, { config: { broadcast: { self: false } } });
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
  }, [threadId, currentUserId]);

  // Expire stale typing entries (no ping in 3s).
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

  const handleSubmit = useCallback((text: string) => {
    emitTyping(false);
    void sendMessage({ text });
  }, [sendMessage, emitTyping]);

  const handleInputChange = useCallback(() => {
    emitTyping(true);
  }, [emitTyping]);

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


  const participantCount = thread?.participantCount ?? 1;
  const isShared = participantCount > 1;

  return (
    <div className="flex h-full flex-col">
      {thread && (
        <div className="flex items-center justify-between px-6 py-3 border-b border-border">
          <div className="text-sm font-medium text-foreground/90 truncate">{thread.title}</div>
          <button
            type="button"
            onClick={() => setParticipantsOpen(true)}
            className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-foreground/60 hover:text-foreground hover:bg-background-subtle/60 transition-colors"
            title="Participants"
          >
            <Users className="h-3.5 w-3.5" />
            {isShared ? `${participantCount}` : 'Share'}
          </button>
        </div>
      )}
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
                currentUserId={currentUserId}
                participantNames={participantNames}
                disabled={isStreaming}
                onEdit={m.role === 'user' && (m as any).userId === currentUserId ? (newText) => void handleEdit(m.id, newText) : undefined}
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
            <TypingIndicator
              users={Object.entries(typingUsers).map(([userId, entry]) => ({ userId, displayName: entry.displayName }))}
            />
            <div ref={bottomRef} />
          </div>
        )}
      </div>
      <ChatInput onSubmit={handleSubmit} onChange={handleInputChange} disabled={isStreaming} autoFocus />

      <ParticipantsPanel
        open={participantsOpen}
        onOpenChange={setParticipantsOpen}
        threadId={threadId}
        currentUserId={currentUserId}
        isCreator={thread?.isCreator ?? false}
        onOpenAddPeople={() => { setParticipantsOpen(false); setAddPeopleOpen(true); }}
        onParticipantsChanged={() => onThreadUpdated?.()}
      />
      <AddPeopleModal
        open={addPeopleOpen}
        onOpenChange={setAddPeopleOpen}
        organizationId={organizationId}
        threadId={threadId}
        onAdded={() => onThreadUpdated?.()}
      />
    </div>
  );
}
