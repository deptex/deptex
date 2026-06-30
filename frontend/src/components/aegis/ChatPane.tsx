import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport, type UIMessage } from 'ai';
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Trash2 } from 'lucide-react';
import { aegisApi, type AegisMessage, type AegisThread, type MessagePart } from '../../lib/aegis-api';
import { api, getAuthToken, type AIModelMetadata } from '../../lib/api';
import { cn } from '../../lib/utils';
import { MessageBubble } from './MessageBubble';
import { ChatInput } from './ChatInput';
import { ChatTodos } from './ChatTodos';
import { ThreadIcon } from './ThreadIcon';
import type { TopUpReason } from '../billing/TopUpModal';

const API_BASE_URL = (import.meta as any).env?.VITE_API_BASE_URL || 'http://localhost:3001';

// Lazy so the Stripe.js module-eval load (TopUpModal → TopUpForm → stripe-client)
// only runs when a user actually opens the top-up modal — not on every Aegis page.
const TopUpModal = lazy(() =>
  import('../billing/TopUpModal').then((m) => ({ default: m.TopUpModal })),
);

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

function formatRelative(iso: string): string {
  const ts = Date.parse(iso);
  if (!Number.isFinite(ts)) return '';
  const diffMs = Date.now() - ts;
  const sec = Math.max(0, Math.floor(diffMs / 1000));
  if (sec < 60) return 'just now';
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  const wk = Math.floor(day / 7);
  if (wk < 5) return `${wk}w ago`;
  const mo = Math.floor(day / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(day / 365)}y ago`;
}

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
  // Threads to show in the landing screen's Recents list. Filtered + sorted
  // here so we don't duplicate logic between sidebar and landing.
  recents?: AegisThread[];
  onSelectRecent?: (threadId: string) => void;
  // Billing: gates the in-chat "Top up" CTA on a cost_cap block, and prefills
  // the add-card form. Sourced from OrganizationLayout's userPermissions.
  canManageBilling?: boolean;
  userEmail?: string | null;
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
  recents,
  onSelectRecent,
  canManageBilling,
  userEmail,
}: ChatPaneProps) {
  // We track the thread ID that THIS mount is working with. The prop may arrive
  // later (after a silent URL update). We never reset state just because the
  // prop appeared — the parent changes `key` when it wants a fresh mount.
  // For a brand-new chat (no propThreadId) we generate the UUID up front and
  // send it on every request. This is the only way to make Stop+resend rock
  // solid: a server-issued id arrives via response headers, which can be
  // missed if the user aborts the fetch before headers round-trip; a
  // client-generated id is known before the request even leaves.
  const [selfThreadId] = useState<string | undefined>(
    () => propThreadId ?? crypto.randomUUID(),
  );
  const activeThreadId = selfThreadId ?? propThreadId;
  const activeThreadIdRef = useRef(activeThreadId);
  useEffect(() => { activeThreadIdRef.current = activeThreadId; });
  // Only call onThreadCreated once per mount — and only for chats that started
  // fresh (no propThreadId). Existing threads obviously don't need a sidebar
  // optimistic insert.
  const notifiedThreadCreatedRef = useRef(!!propThreadId);

  const [isRegenerating, setIsRegenerating] = useState(false);
  const [sendError, setSendError] = useState<string | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // In-chat top-up modal, opened from a cost_cap error bubble's "Top up" CTA.
  const [topUp, setTopUp] = useState<{ open: boolean; reason: TopUpReason }>({
    open: false,
    reason: 'manual',
  });

  // Send queue: messages submitted while a previous response is still
  // streaming get parked here and dispatched FIFO when the in-flight stream
  // resolves. Items have a stable id so deletes can target the right one
  // (vs. relying on text equality, which breaks if a user queues two
  // identical follow-ups).
  const [sendQueue, setSendQueue] = useState<{ id: string; text: string }[]>([]);
  const sendQueueRef = useRef<{ id: string; text: string }[]>([]);
  useEffect(() => { sendQueueRef.current = sendQueue; });
  // Synchronous in-flight flag. The useChat `status` value lives in React
  // state, so a fast double-submit can fire two sendMessage calls before the
  // first one's status='submitted' has propagated — two parallel POSTs, both
  // with no threadId, server creates two separate threads. Setting a ref the
  // moment we dispatch closes that race.
  const inFlightRef = useRef(false);

  // Per-org model picker state. Catalog comes from the AI settings endpoint
  // (only enabled models surface in the picker). Selection persists to
  // localStorage per-org so each org remembers its last pick across reloads.
  // Per-thread sticky: a deliberate model switch survives a page reload of
  // the same conversation, but a new chat (no threadId yet) always renders
  // with the live org default — so changing the default in settings takes
  // effect for the next chat you open.
  const threadModelStorageKey = (tid: string) => `aegis:selected-model:thread:${tid}`;
  const readThreadStored = (tid: string | undefined): string | null => {
    if (!tid) return null;
    try { return localStorage.getItem(threadModelStorageKey(tid)); } catch { return null; }
  };
  const pickInitialModelId = (
    res: { models: AIModelMetadata[]; enabledModels: string[]; defaultModel: string },
    enabled: AIModelMetadata[],
    tid: string | undefined,
  ): string | null => {
    const stored = readThreadStored(tid);
    return (
      (stored && enabled.find((m) => m.id === stored)?.id) ||
      enabled.find((m) => m.id === res.defaultModel)?.id ||
      enabled[0]?.id ||
      null
    );
  };

  // Seed from the synchronous cache peek so a warm cache (recent visit to
  // another thread / settings page) renders the picker on first paint instead
  // of flashing the skeleton.
  const initialCached = api.peekAIModels(organizationId);
  const initialEnabled = initialCached
    ? initialCached.models.filter((m) => initialCached.enabledModels.includes(m.id))
    : [];
  const [enabledModels, setEnabledModels] = useState<AIModelMetadata[]>(initialEnabled);
  const [selectedModelId, setSelectedModelIdState] = useState<string | null>(
    initialCached ? pickInitialModelId(initialCached, initialEnabled, propThreadId) : null,
  );
  const [modelsLoading, setModelsLoading] = useState(!initialCached);
  const selectedModelIdRef = useRef<string | null>(null);
  useEffect(() => { selectedModelIdRef.current = selectedModelId; });

  const setSelectedModelId = useCallback(
    (id: string) => {
      setSelectedModelIdState(id);
      const tid = activeThreadIdRef.current;
      if (tid) {
        try { localStorage.setItem(threadModelStorageKey(tid), id); } catch { /* quota / private mode */ }
      }
    },
    [],
  );

  // When a brand-new thread gets a server-issued id (after the first send),
  // pin the user's current pick to it so a refresh of that thread restores
  // the same model.
  useEffect(() => {
    if (!activeThreadId || !selectedModelId) return;
    try { localStorage.setItem(threadModelStorageKey(activeThreadId), selectedModelId); } catch { /* */ }
  }, [activeThreadId, selectedModelId]);

  useEffect(() => {
    let cancelled = false;
    if (!api.peekAIModels(organizationId)) setModelsLoading(true);
    api.getAIModels(organizationId).then((res) => {
      if (cancelled) return;
      const enabled = res.models.filter((m) => res.enabledModels.includes(m.id));
      setEnabledModels(enabled);
      setSelectedModelIdState((current) => current ?? pickInitialModelId(res, enabled, activeThreadIdRef.current));
    }).catch(() => { /* picker stays hidden — backend uses org default */ })
      .finally(() => { if (!cancelled) setModelsLoading(false); });
    return () => { cancelled = true; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [organizationId]);

  // Cross-tab sync: when settings is edited (here or in another tab), refresh
  // the enabled list. Keep the user's pick if it's still enabled; otherwise
  // fall back to the (possibly new) org default. Mid-conversation we never
  // reset just because the org default changed — only because the model the
  // user picked was disabled out from under them.
  useEffect(() => {
    return api.subscribeAIModels((orgId, value) => {
      if (orgId !== organizationId) return;
      const enabled = value.models.filter((m) => value.enabledModels.includes(m.id));
      setEnabledModels(enabled);
      setSelectedModelIdState((current) => {
        if (current && enabled.some((m) => m.id === current)) return current;
        return pickInitialModelId(value, enabled, activeThreadIdRef.current);
      });
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [organizationId]);

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
              modelId: selectedModelIdRef.current ?? undefined,
            },
          };
        },
        fetch: async (input, init) => {
          const token = await getAuthToken();
          const headers = new Headers(init?.headers);
          if (token) headers.set('Authorization', `Bearer ${token}`);
          headers.set('Content-Type', 'application/json');
          return fetch(input, { ...init, headers });
        },
      }),
    [organizationId],
  );

  // Forward-declared so the useChat onFinish closure (which is built before
  // sendMessage exists) can call the latest sendMessage to drain the queue.
  const sendMessageRef = useRef<((arg: { text: string }) => Promise<void> | void) | null>(null);

  const { messages, setMessages, sendMessage, regenerate, stop, status, error, clearError, resumeStream } =
    useChat({
      // Pin the chat id to the threadId so the SDK's reconnectToStream calls
      // GET `${api}/${threadId}/stream` — that's the resume endpoint we added
      // to `backend/src/routes/aegis-v3.ts`. For brand-new chats this is the
      // client-generated UUID created at mount; the server uses the same id
      // in `getOrCreateThread`, so the reconnect URL always lands on the
      // right thread even before the first response.
      id: activeThreadId,
      transport,
      onFinish: () => {
        inFlightRef.current = false;
        setIsRegenerating(false);
        onThreadUpdatedRef.current?.();
        // Drain one queued message per finished stream. The next stream's
        // onFinish picks up the one after, which keeps drain serialised
        // without us tracking explicit "in-flight" state.
        const next = sendQueueRef.current[0];
        if (next) {
          setSendQueue((q) => q.slice(1));
          // Defer to a microtask so useChat's internal state has settled
          // (status is still mid-transition the moment onFinish fires).
          queueMicrotask(() => {
            inFlightRef.current = true;
            void sendMessageRef.current?.({ text: next.text });
          });
        }
      },
      onError: (err) => {
        // Never surface backend error text to the chat — it leaks DB columns
        // and reads as a system failure to the user. Real cause is in the
        // server logs; the user always sees a generic message.
        console.error('[aegis] chat error', err);
        inFlightRef.current = false;
        setIsRegenerating(false);
        setSendError('Something went wrong. Please try again.');
        // Without this, useChat's transient `error` clears on the next submit
        // and the error bubble vanishes — even though the backend persisted a
        // matching row. Mirror it locally so the bubble (and Regenerate) stay
        // put across follow-up sends. On a fresh mount, buildInitialMessages
        // restores the same `error` flag from DB metadata.
        setMessages((prev) => {
          const errorPart = {
            type: 'text' as const,
            text: 'Something went wrong while generating a response.',
          };
          const last = prev[prev.length - 1] as any;
          if (last?.role === 'assistant') {
            return prev.map((m, i) =>
              i === prev.length - 1
                ? ({ ...(m as any), error: { type: 'transient' } } as UIMessage)
                : m,
            );
          }
          return [
            ...prev,
            {
              id: `error-${Date.now()}`,
              role: 'assistant',
              parts: [errorPart],
              error: { type: 'transient' },
            } as unknown as UIMessage,
          ];
        });
      },
    });

  const isStreaming = status === 'streaming' || status === 'submitted';
  useEffect(() => { sendMessageRef.current = sendMessage; });

  // On unmount (thread switch), abort the local SSE fetch. The server-side
  // resumable-stream tee keeps writing to Redis regardless of socket state, so
  // when the user navigates back, the seed-load + resumeStream() useEffect
  // reconnects and replays whatever ran while they were away. Without this,
  // the browser holds zombie SSE sockets open per thread switch — the new
  // ChatPane mounts fine, but the orphaned old fetch keeps consuming memory
  // and (in some browsers) blocks navigation back to the original thread.
  useEffect(() => {
    return () => {
      try { stop(); } catch { /* no-op when not streaming */ }
    };
  }, [stop]);

  // Seed load + live resume. On mount we fetch the thread's messages once.
  // If the most recent persisted message is a user turn, the assistant
  // response is either still streaming server-side (user navigated away
  // mid-stream and came back) or already finished but not yet flushed to DB.
  //
  // resumeStream() hits the GET reconnect endpoint, which:
  //   * 204s when there's no active stream → no-op, the seed-load is the
  //     final state
  //   * replays every captured SSE byte from Redis when the stream is live
  //     → the SDK splices the partial assistant message in and continues
  //     streaming new bytes as they land
  //
  // We always call resumeStream — even if the seed-load shows a finished
  // assistant turn — because Redis is the authoritative source for "is the
  // stream still going right now" and a 204 is cheap. Resume is also a
  // backstop for the rare case where the stream finished after seed-load
  // started but before it returned (the assistant row might be missing
  // from the DB read but already done in Redis).
  useEffect(() => {
    if (!propThreadId) return;
    let cancelled = false;
    (async () => {
      try {
        const msgs = await aegisApi.getMessages(propThreadId);
        if (cancelled) return;
        setMessages(buildInitialMessages(msgs));
      } catch {
        /* leave whatever is on screen on load failure */
      }
      if (cancelled) return;
      try {
        await resumeStream();
      } catch (err) {
        // resumeStream failures are non-fatal — the user can resend or the
        // tail-state on the server will land via the next interaction.
        console.warn('[aegis] resumeStream failed', err);
      }
    })();
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSubmit = useCallback(
    (text: string) => {
      const trimmed = text.trim();
      if (!trimmed) return;
      // First send of a brand-new chat: notify the parent so the URL
      // updates and an optimistic "New chat" entry slides into the sidebar.
      // Done here (not in transport.fetch) because the threadId is now
      // client-generated and known up front — and a Stop click before the
      // fetch resolves would otherwise rob us of the chance.
      if (!notifiedThreadCreatedRef.current && activeThreadIdRef.current) {
        notifiedThreadCreatedRef.current = true;
        onThreadCreatedRef.current(activeThreadIdRef.current);
      }
      // Use the synchronous ref, not React state, so a fast double-submit
      // can't slip a second sendMessage through before status flips.
      if (inFlightRef.current || sendQueueRef.current.length > 0) {
        setSendQueue((q) => [...q, { id: `q-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`, text: trimmed }]);
        return;
      }
      inFlightRef.current = true;
      setSendError(null);
      clearError();
      void sendMessage({ text: trimmed });
    },
    [sendMessage, clearError],
  );

  const handleRemoveFromQueue = useCallback((id: string) => {
    setSendQueue((q) => q.filter((item) => item.id !== id));
  }, []);

  const handleRegenerate = useCallback(async () => {
    const tid = activeThreadIdRef.current;
    if (!tid || isStreaming || isRegenerating || inFlightRef.current) return;
    setSendError(null);
    setIsRegenerating(true);
    inFlightRef.current = true;
    try {
      // Server-side cleanup: delete the trailing assistant error row so the
      // DB matches what useChat is about to redo locally.
      await aegisApi.regenerate(tid);
      // useChat.regenerate slices off the trailing assistant in local state
      // and POSTs the trimmed history to /stream — exactly what we want.
      await regenerate();
    } catch (err: any) {
      console.error('[aegis] regenerate error', err);
      inFlightRef.current = false;
      setIsRegenerating(false);
      setSendError('Something went wrong. Please try again.');
    }
  }, [isStreaming, isRegenerating, regenerate]);

  // After a confirmed top-up, re-run the blocked turn automatically. Regenerate
  // slices off the trailing cost_cap error bubble and re-POSTs the user's
  // question — no re-typing — and the server re-checks the (now funded) balance.
  const handleCredited = useCallback(() => {
    void handleRegenerate();
  }, [handleRegenerate]);

  const handleStop = useCallback(() => {
    // useChat's stop() aborts the underlying fetch but doesn't reliably fire
    // onFinish/onError, so clear the inFlight flag here. Without this, a
    // subsequent submit would queue forever (handleSubmit only fires when
    // inFlightRef is false) — and the queue drains in onFinish, which never
    // runs for an aborted stream.
    void stop();
    inFlightRef.current = false;
    setIsRegenerating(false);
    // Title gen runs in parallel with the model on the server (decoupled
    // from the response stream), so a stop click doesn't cancel it. Trigger
    // the same poll-for-title flow we'd run on natural completion so the
    // sidebar swaps "New chat" for the real title once it lands.
    onThreadUpdatedRef.current?.();
  }, [stop]);

  // Show the thinking dot whenever the stream is in flight and there's no
  // self-evident visible affordance for the user. Suppressed only by
  // (a) actively-typing text content — the typing animation IS the
  // indicator — and (b) request_fix / revise_fix in flight, which render
  // PlanCardSkeleton. set_todos resolves immediately and produces the
  // strip, but the agent then often pauses to think before its next
  // visible action — those gaps fall into the default-true branch so the
  // dot reappears between actions instead of going dark.
  const showThinkingDot = useMemo(() => {
    if (status === 'submitted') return true;
    if (status !== 'streaming') return false;
    const last = messages[messages.length - 1] as any;
    if (!last || last.role !== 'assistant') return true;
    const parts = (last.parts ?? []) as any[];
    if (parts.length === 0) return true;
    const lastPart = parts[parts.length - 1];
    if (lastPart?.type === 'text' && (lastPart.text ?? '').trim().length > 0) return false;
    const lastPartType = typeof lastPart?.type === 'string' ? lastPart.type : '';
    const lastToolName = lastPart?.toolName ?? (lastPartType.startsWith('tool-') ? lastPartType.replace(/^tool-/, '') : '');
    if ((lastToolName === 'request_fix' || lastToolName === 'revise_fix') && lastPart?.state !== 'output-error') return false;
    return true;
  }, [status, messages]);

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

  // Landing only shows for chats that mounted fresh (no propThreadId) and
  // haven't sent their first message yet. activeThreadId is now always set
  // (we generate the UUID at mount), so we gate on the prop instead.
  const showLanding = !propThreadId && messages.length === 0;
  const placeholder = useTypewriterPlaceholder(AEGIS_PROMPTS, showLanding);

  if (showLanding) {
    const visibleRecents = (recents ?? [])
      .filter((t) => !t.archivedAt)
      .slice()
      .sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))
      .slice(0, 3);
    return (
      <div className="h-full overflow-y-auto custom-scrollbar px-6 pt-20 pb-12">
        <div className="mx-auto w-full max-w-2xl">
          <div className="mb-6">
            <div className="text-sm text-foreground/60 mb-1">Hi {displayName}</div>
            <h1 className="text-2xl font-semibold text-foreground tracking-tight">
              What can I help you secure?
            </h1>
          </div>

          <div className="rounded-2xl bg-background-card border border-border">
            <ChatInput
              onSubmit={handleSubmit}
              placeholder={placeholder}
              autoFocus
              models={enabledModels}
              selectedModelId={selectedModelId}
              onSelectModel={setSelectedModelId}
              modelsLoading={modelsLoading}
            />
          </div>
          {sendError && (
            <div className="mt-3 text-sm text-foreground/60">{sendError}</div>
          )}

          {visibleRecents.length > 0 && onSelectRecent && (
            <div className="mt-10">
              <div className="flex items-baseline justify-between mb-3">
                <h2 className="text-xs font-medium uppercase tracking-wider text-foreground/60">
                  Recents
                </h2>
              </div>
              <ul className="flex flex-col gap-2">
                {visibleRecents.map((t) => (
                  <li key={t.id}>
                    <button
                      type="button"
                      onClick={() => onSelectRecent(t.id)}
                      className="group w-full flex items-center gap-3.5 rounded-xl border border-border bg-background-card px-4 py-3.5 text-left transition-all hover:border-foreground/20 hover:bg-background-card/60 hover:shadow-sm"
                    >
                      <ThreadIcon fixStatus={t.fixStatus} archived={!!t.archivedAt} />
                      <span className="flex-1 min-w-0 flex flex-col">
                        <span className="truncate text-sm font-medium text-foreground leading-snug">
                          {t.title || 'Untitled chat'}
                        </span>
                        <span className="text-xs text-foreground/55 tabular-nums leading-snug mt-0.5">
                          {formatRelative(t.updatedAt)}
                        </span>
                      </span>
                      <ChevronRight className="h-4 w-4 shrink-0 text-foreground/30 transition-all group-hover:text-foreground/70 group-hover:translate-x-0.5" />
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex-1 overflow-y-auto custom-scrollbar">
        <div className="py-4">
          {messages.map((m, i) => (
            <MessageBubble
              key={m.id}
              message={m}
              currentUserId={currentUserId}
              organizationId={organizationId}
              onRegenerate={i === latestErrorIdx ? handleRegenerate : undefined}
              isRegenerating={i === latestErrorIdx && isRegenerating}
              onTopUp={(reason) => setTopUp({ open: true, reason })}
              canManageBilling={canManageBilling}
            />
          ))}
          {showThinkingDot && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl">
                <span
                  className="h-4 w-4 rounded-full bg-foreground/60 inline-block"
                  style={{ animation: 'aegis-thinking 1.6s ease-in-out infinite' }}
                />
              </div>
            </div>
          )}
          {sendError && !isStreaming && (
            <div className="px-4 py-3">
              <div className="mx-auto max-w-3xl text-sm text-foreground/60">{sendError}</div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      </div>
      <div className="px-4 pb-4">
        <div className="mx-auto max-w-3xl">
          <ChatTodos messages={messages} streaming={status === 'streaming'} />
          <SendQueuePanel queue={sendQueue} onRemove={handleRemoveFromQueue} />
          <div className="rounded-2xl bg-background-card border border-border">
            <ChatInput
              onSubmit={handleSubmit}
              placeholder={isStreaming || sendQueue.length > 0 ? 'Add a follow-up' : 'Ask anything'}
              autoFocus
              models={enabledModels}
              selectedModelId={selectedModelId}
              onSelectModel={setSelectedModelId}
              modelsLoading={modelsLoading}
              isStreaming={isStreaming}
              onStop={handleStop}
            />
          </div>
        </div>
      </div>

      <Suspense fallback={null}>
        {topUp.open && (
          <TopUpModal
            open={topUp.open}
            reason={topUp.reason}
            organizationId={organizationId}
            canManageBilling={!!canManageBilling}
            userEmail={userEmail ?? null}
            onOpenChange={(o) => setTopUp((s) => ({ ...s, open: o }))}
            onCredited={handleCredited}
          />
        )}
      </Suspense>
    </div>
  );
}

function SendQueuePanel({
  queue,
  onRemove,
}: {
  queue: { id: string; text: string }[];
  onRemove: (id: string) => void;
}) {
  const [collapsed, setCollapsed] = useState(false);
  if (queue.length === 0) return null;
  return (
    <div className="mb-2 rounded-2xl border border-border bg-background-card shadow-lg overflow-hidden">
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="flex w-full items-center gap-2 px-4 py-2 text-xs font-medium text-foreground-secondary hover:text-foreground transition-colors"
      >
        <svg
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth={2}
          strokeLinecap="round"
          strokeLinejoin="round"
          className={cn('h-3.5 w-3.5 transition-transform', collapsed && '-rotate-90')}
        >
          <path d="M6 9l6 6 6-6" />
        </svg>
        <span>{queue.length} Queued</span>
      </button>
      <div
        className={cn(
          'grid transition-[grid-template-rows] duration-200 ease-out',
          collapsed ? 'grid-rows-[0fr]' : 'grid-rows-[1fr]',
        )}
      >
        <div className="overflow-hidden">
          <ul className="px-2 pb-1">
            {queue.map((item) => (
              <li
                key={item.id}
                className="group flex items-start gap-3 rounded-md px-2 py-1 hover:bg-background-subtle transition-colors"
              >
                <span className="mt-1 h-3 w-3 shrink-0 rounded-full border border-foreground/40" />
                <span className="flex-1 text-sm leading-snug text-foreground whitespace-pre-wrap break-words">
                  {item.text}
                </span>
                <button
                  type="button"
                  onClick={() => onRemove(item.id)}
                  aria-label="Remove from queue"
                  className="-mt-0.5 inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-md text-foreground/50 opacity-0 transition-all hover:bg-background-card hover:text-foreground group-hover:opacity-100 focus:opacity-100"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}
