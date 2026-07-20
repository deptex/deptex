import { useChat } from '@ai-sdk/react';
import { DefaultChatTransport, type UIMessage } from 'ai';
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, Trash2 } from 'lucide-react';
import { aegisApi, type AegisMessage, type AegisTask, type AegisThread, type MessagePart, type TaskRunStatus } from '../../lib/aegis-api';
import type { SlashCommand, ContextUsage } from './ChatInput';
import { api, getAuthToken, type AIModelMetadata } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { cn } from '../../lib/utils';
import { MessageBubble } from './MessageBubble';
import { TaskHeader } from './TaskHeader';
import { ChatInput } from './ChatInput';
import { Skeleton } from '../ui/skeleton';
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

// A task's fix row is "running" (agent working) in any of these states.
const TASK_RUNNING_STATUSES = new Set(['approved', 'planning', 'executing']);
// Follow-up poll fallback (for when realtime silently stalls): cadence, the cap
// if a run never even starts (wake failed / queued behind another), and the
// hard ceiling while a run is genuinely going (realtime covers anything longer).
const FOLLOWUP_POLL_MS = 3500;
// A snappier cadence until the run is confirmed running, so the thinking dot /
// Stop reconcile quickly right after a send (the wake RPC has already flipped
// the fix row by the time this fires).
const FOLLOWUP_STARTUP_POLL_MS = 900;
const FOLLOWUP_NEVER_STARTED_CAP_MS = 90_000;
const FOLLOWUP_MAX_MS = 15 * 60_000;

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
  // Task threads are driven by an autonomous server-side agent loop, not the
  // user's SSE stream — so they won't see new messages unless we subscribe.
  // When true, ChatPane realtime-reloads the thread on each new persisted
  // message. Off (default) for normal chats so their useChat flow is untouched.
  liveReload?: boolean;
  // The task this chat belongs to (task threads only). When present, a compact
  // task row is pinned above the conversation; clicking it opens the detail
  // panel via onOpenTaskDetails.
  task?: AegisTask | null;
  // True while the parent's task list is still unresolved (listTasks in flight
  // or failed), i.e. `task` above may be null only because task-ness is
  // UNKNOWN. handleSubmit fails existing-thread sends closed while this is set.
  tasksLoading?: boolean;
  onOpenTaskDetails?: () => void;
  // Billing: gates the in-chat "Top up" CTA on a cost_cap block, and prefills
  // the add-card form. Sourced from OrganizationLayout's userPermissions.
  canManageBilling?: boolean;
  userEmail?: string | null;
  // Fired once, when the thread's history finishes loading (or fails). Lets the
  // parent hold the task side-panel closed until the conversation is on screen,
  // so it doesn't sit open over the loading skeleton.
  onFirstLoad?: () => void;
}

// The task chat's slash palette (rendered by ChatInput; executed in ChatPane).
const TASK_SLASH_COMMANDS: SlashCommand[] = [
  { name: 'status', description: 'Show run status — step, context %, elapsed' },
  { name: 'retry', description: 'Re-run this task from where it stopped' },
];
const RETRY_TEXT = 'Please try this again.';

function formatRunStatus(s: TaskRunStatus): string {
  if (!s.run) {
    return s.taskStatus === 'working' ? 'Starting up — no telemetry yet.' : `Task ${s.taskStatus}. No active run.`;
  }
  const r = s.run;
  const parts: string[] = [`Run: ${r.fixStatus}`];
  if (r.step != null) parts.push(`step ${r.step}`);
  if (r.contextPct != null) parts.push(`context ${Math.round(r.contextPct * 100)}%`);
  if (r.startedAt) {
    const secs = Math.max(0, Math.round((Date.now() - new Date(r.startedAt).getTime()) / 1000));
    parts.push(`${secs < 60 ? `${secs}s` : `${Math.round(secs / 60)}m`} elapsed`);
  }
  if (r.prNumber) parts.push(`PR #${r.prNumber}`);
  return parts.join(' · ');
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
    let hasStep = false;
    for (const p of rawParts) {
      if (p.type === 'text') {
        parts.push({ type: 'text', text: p.text });
        hasText = true;
      } else if ((p as any).type === 'step') {
        // A fix-worker tool-use step (gray icon + label line; optional command
        // renders as a terminal line when expanded).
        parts.push({
          type: 'step',
          icon: (p as any).icon,
          label: (p as any).label,
          command: (p as any).command,
          diff: (p as any).diff,
          output: (p as any).output,
        });
        hasStep = true;
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

    // A `step` part carries its own label, so don't also prepend `content` (which
    // mirrors that label) as a duplicate text line. A card message (tool-result,
    // no text/step) still surfaces its content as the caption above the card.
    if (!hasText && !hasStep && msg.content) parts.unshift({ type: 'text', text: msg.content });
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

// Shown while an existing thread's history is being fetched. A stand-in for the
// conversation — alternating assistant text blocks (left) and user bubbles
// (right) on the same centered max-w-3xl column and alignment as real
// MessageBubbles — so the load resolves into place instead of the pane sitting
// empty with the task header already popped in. Runs long and fades downward
// (the app-wide `mask-image` treatment used by the tables/settings skeletons)
// so it reads as "conversation loading", not a fixed block.
const CHAT_SKELETON_TURNS: { assistant: string[]; user: string }[] = [
  { assistant: ['w-1/2', 'w-4/5', 'w-2/3'], user: 'w-2/5' },
  { assistant: ['w-3/4', 'w-5/6', 'w-1/2'], user: 'w-1/3' },
  { assistant: ['w-2/3', 'w-4/5'], user: 'w-1/2' },
];

function ChatSkeleton() {
  return (
    <div
      aria-busy="true"
      aria-label="Loading conversation"
      className="py-4 opacity-70 pointer-events-none select-none"
      style={{
        maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
        WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
      }}
    >
      {CHAT_SKELETON_TURNS.map((turn, i) => (
        <div key={i}>
          <div className="px-4 py-2">
            <div className="mx-auto max-w-3xl space-y-2.5">
              {turn.assistant.map((w, j) => (
                <Skeleton key={j} className={`h-3.5 ${w}`} />
              ))}
            </div>
          </div>
          <div className="px-4 py-2">
            <div className="mx-auto max-w-3xl flex justify-end">
              <Skeleton className={`h-9 rounded-2xl ${turn.user}`} />
            </div>
          </div>
        </div>
      ))}
    </div>
  );
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
  liveReload = false,
  task,
  tasksLoading = false,
  onOpenTaskDetails,
  canManageBilling,
  userEmail,
  onFirstLoad,
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
  const onFirstLoadRef = useRef(onFirstLoad);
  useEffect(() => { onThreadCreatedRef.current = onThreadCreated; });
  useEffect(() => { onThreadUpdatedRef.current = onThreadUpdated; });
  useEffect(() => { onFirstLoadRef.current = onFirstLoad; });

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

  // The seed-load gate. An existing thread must fetch its history before it can
  // render — until then show a chat skeleton rather than an empty pane with the
  // task header already popped in (the "started task shows before the chat
  // loads" jump). A brand-new chat (no propThreadId) has nothing to fetch, so
  // it starts un-gated and goes straight to the landing.
  const [messagesLoading, setMessagesLoading] = useState<boolean>(!!propThreadId);

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
    // Brand-new chat: nothing to fetch, so it's "loaded" immediately — signal
    // ready so the parent doesn't wait on a load that never happens.
    if (!propThreadId) {
      onFirstLoadRef.current?.();
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const msgs = await aegisApi.getMessages(propThreadId);
        if (cancelled) return;
        setMessages(buildInitialMessages(msgs));
      } catch {
        /* leave whatever is on screen on load failure */
      } finally {
        // Reveal the conversation (and the task header) as one, whether the
        // fetch succeeded or failed — a failed load falls through to the normal
        // empty/error rendering, never a stuck skeleton. Signal the parent so
        // the task side-panel can slide in now (not over the skeleton).
        if (!cancelled) {
          setMessagesLoading(false);
          onFirstLoadRef.current?.();
        }
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

  // Live "task is running" signal for the thinking dot. The worker narrates via
  // realtime inserts (not useChat's status), so the dot must key off the fix
  // row's status — project_security_fixes is in the realtime publication. Dot on
  // while any of the thread's fixes is queued/executing; off once they resolve.
  const [taskWorking, setTaskWorking] = useState(false);
  // A follow-up sent while the agent is mid-run is persisted + queued (the worker
  // drains it when the current run ends). Surfaced so the bubble doesn't read as ignored.
  const [taskQueuedHint, setTaskQueuedHint] = useState(false);
  // Client-side output of a slash command (/status, /retry) — an ephemeral,
  // non-persisted line above the composer (the thread reloads from the DB, so a
  // fake chat message wouldn't survive).
  const [commandOutput, setCommandOutput] = useState<string | null>(null);
  // Live context-window usage for the composer's ring meter (task threads).
  const [contextUsage, setContextUsage] = useState<ContextUsage | null>(null);
  // Bumped each time a task follow-up is sent — arms the realtime-independent
  // poll fallback below so the reply always lands even if the realtime socket
  // has silently stalled (the "nothing came until I refreshed" bug).
  const [followupPollNonce, setFollowupPollNonce] = useState(0);
  useEffect(() => {
    if (!taskWorking) setTaskQueuedHint(false); // run ended → pickup imminent
  }, [taskWorking]);

  // Context-window telemetry for the composer ring. Poll fast while the agent
  // is running (the fill moves per step), and once when idle to show the last
  // run's usage. Task threads only — a regular chat has no per-run window meter.
  useEffect(() => {
    const taskId = task?.id;
    if (!liveReload || !taskId) {
      setContextUsage(null);
      return;
    }
    let cancelled = false;
    const load = () => {
      aegisApi.getTaskRunStatus(taskId, organizationId).then(
        (s) => {
          if (cancelled) return;
          const r = s.run;
          setContextUsage(
            r && r.contextWindow && r.contextPct != null
              ? { tokens: r.contextTokens, window: r.contextWindow, pct: r.contextPct }
              : null,
          );
        },
        () => {
          /* transient — keep the last value */
        },
      );
    };
    load();
    const interval = taskWorking ? window.setInterval(load, 3000) : undefined;
    return () => {
      cancelled = true;
      if (interval !== undefined) window.clearInterval(interval);
    };
  }, [liveReload, task?.id, organizationId, taskWorking, followupPollNonce]);
  useEffect(() => {
    if (!liveReload || !propThreadId) {
      setTaskWorking(false);
      return;
    }
    let cancelled = false;
    const evaluate = async () => {
      const { data } = await supabase
        .from('project_security_fixes')
        .select('status')
        .eq('thread_id', propThreadId);
      if (!cancelled) setTaskWorking((data ?? []).some((r: { status: string }) => TASK_RUNNING_STATUSES.has(r.status)));
    };
    void evaluate();
    const channel = supabase
      .channel(`aegis-task-fix-${propThreadId}`)
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'project_security_fixes', filter: `thread_id=eq.${propThreadId}` },
        () => void evaluate(),
      )
      .subscribe();
    return () => {
      cancelled = true;
      supabase.removeChannel(channel);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveReload, propThreadId]);

  // Live narration for task threads. The task's agent loop runs server-side and
  // persists each beat to aegis_chat_messages (already in the realtime
  // publication); subscribe and reload the thread as beats land. Gated to
  // liveReload so normal chats (driven by useChat/SSE) are never reloaded out
  // from under an in-flight stream. We also skip while inFlightRef is set —
  // the rare case where a user is actively sending in a task thread.
  useEffect(() => {
    if (!liveReload || !propThreadId) return;
    const channel = supabase
      .channel(`aegis-task-msgs-${propThreadId}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'aegis_chat_messages', filter: `thread_id=eq.${propThreadId}` },
        async () => {
          if (inFlightRef.current) return;
          try {
            const msgs = await aegisApi.getMessages(propThreadId);
            setMessages(buildInitialMessages(msgs));
          } catch {
            /* transient — next beat reloads anyway */
          }
        },
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [liveReload, propThreadId]);

  // Realtime-independent fallback for the narration. Supabase's postgres_changes
  // socket can silently stall (dropped connection, an access token that expired
  // while the tab sat open) and stop delivering INSERTs until a manual refresh
  // forces a reconnect — which looked like "I asked a follow-up and nothing came
  // back until I refreshed". Armed on each task send (followupPollNonce): poll
  // the thread directly until its run settles, reloading messages AND recomputing
  // taskWorking, so both the reply and the thinking dot land regardless of the
  // socket. Cheap reads, self-limiting, and it stops shortly after the run ends.
  useEffect(() => {
    if (!liveReload || !propThreadId || followupPollNonce === 0) return;
    let cancelled = false;
    let sawRunning = false;
    let settledStreak = 0;
    const startedAt = Date.now();
    let timer: ReturnType<typeof setTimeout> | undefined;

    const tick = async () => {
      // Don't fight an in-flight useChat stream (task threads don't use one, but
      // guard anyway) — just reschedule.
      if (!cancelled && !inFlightRef.current) {
        try {
          const [msgs, fixes] = await Promise.all([
            aegisApi.getMessages(propThreadId),
            supabase.from('project_security_fixes').select('status').eq('thread_id', propThreadId),
          ]);
          if (cancelled) return;
          setMessages(buildInitialMessages(msgs));
          const running = (fixes.data ?? []).some((r: { status: string }) => TASK_RUNNING_STATUSES.has(r.status));
          const elapsed = Date.now() - startedAt;
          if (running) {
            setTaskWorking(true);
            sawRunning = true;
            settledStreak = 0;
          } else {
            settledStreak += 1;
            // Only turn the dot OFF once the run has actually been seen running
            // (so a read during the wake/boot gap — row not yet 'approved' —
            // doesn't blink off the optimistic "starting…" state), or after the
            // never-started grace window (wake genuinely failed / queued).
            if (sawRunning || elapsed > FOLLOWUP_NEVER_STARTED_CAP_MS) setTaskWorking(false);
          }
        } catch {
          /* transient — the next tick retries */
        }
      }
      if (cancelled) return;
      const elapsed = Date.now() - startedAt;
      // Stop once: the run started and has been settled two ticks (terminal beat
      // captured), OR it never started within the idle cap, OR the hard ceiling.
      const done =
        (sawRunning && settledStreak >= 2) ||
        (!sawRunning && elapsed > FOLLOWUP_NEVER_STARTED_CAP_MS) ||
        elapsed > FOLLOWUP_MAX_MS;
      if (!done) timer = setTimeout(tick, sawRunning ? FOLLOWUP_POLL_MS : FOLLOWUP_STARTUP_POLL_MS);
    };
    // First tick fires quickly so the run state reconciles fast (the wake RPC
    // has already flipped the fix row); cadence relaxes once it's running.
    timer = setTimeout(tick, FOLLOWUP_STARTUP_POLL_MS);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [followupPollNonce, liveReload, propThreadId]);

  // Slash-command execution for task threads. /status reads live run telemetry;
  // /retry wakes the agent to re-attempt (reusing the follow-up wake path).
  const runTaskCommand = useCallback(
    async (raw: string) => {
      if (!task) return;
      const cmd = raw.trim().slice(1).split(/\s+/)[0].toLowerCase();
      if (cmd === 'status') {
        setCommandOutput('Checking status…');
        try {
          const s = await aegisApi.getTaskRunStatus(task.id, organizationId);
          setCommandOutput(formatRunStatus(s));
        } catch {
          setCommandOutput('Could not fetch status right now.');
        }
        return;
      }
      if (cmd === 'retry') {
        if (task.status === 'working') {
          setCommandOutput('This task is already running — no need to retry.');
          return;
        }
        setCommandOutput(null);
        setSendError(null);
        setTaskWorking(true);
        setFollowupPollNonce((n) => n + 1);
        setMessages((prev) => [
          ...prev,
          { id: `local-${Date.now()}`, role: 'user', parts: [{ type: 'text', text: RETRY_TEXT }] } as unknown as UIMessage,
        ]);
        try {
          const res = await aegisApi.sendTaskMessage(task.id, organizationId, RETRY_TEXT);
          if (res.queued) setTaskQueuedHint(true);
        } catch {
          setSendError('Something went wrong. Please try again.');
        }
        return;
      }
      setCommandOutput('Unknown command. Try /status or /retry.');
    },
    [task, organizationId, setMessages, setTaskWorking, setFollowupPollNonce],
  );

  const handleSubmit = useCallback(
    (text: string) => {
      const trimmed = text.trim();
      if (!trimmed) return;
      // Fail closed while task-ness is unresolved. `task` derives from the
      // parent's async listTasks(), so an existing thread with task=null might
      // BE a task thread whose list simply hasn't loaded (direct URL load, or
      // a failed fetch). Misrouting a task follow-up to the chat agent is the
      // split-brain this feature exists to kill — block the send rather than
      // fall through. Brand-new chats (no propThreadId) can't be task threads.
      if (tasksLoading && propThreadId && !task) {
        setSendError('Still loading this conversation — try again in a moment.');
        return;
      }
      // Task threads: the message goes to the task's own agent (wake/queue), never the
      // chat agent. Optimistic bubble here (useChat isn't involved on this path); the
      // realtime reload reconciles it against the persisted row.
      if (liveReload && task) {
        setSendError(null);
        // Slash commands (/status, /retry) are handled client-side, never sent
        // to the agent as a message.
        if (trimmed.startsWith('/')) {
          void runTaskCommand(trimmed);
          return;
        }
        setCommandOutput(null);
        setMessages((prev) => [
          ...prev,
          {
            id: `local-${Date.now()}`,
            role: 'user',
            parts: [{ type: 'text', text: trimmed }],
          } as unknown as UIMessage,
        ]);
        // Instant feedback: a follow-up wakes the agent, so flip the thinking
        // dot + in-input Stop ON right now instead of waiting for a poll/realtime
        // read to notice the fix row went running (the "mic stays for a few
        // seconds" lag). The poll below reconciles — and won't blink it back off
        // during the wake/boot gap.
        setTaskWorking(true);
        // Arm the poll fallback immediately so the reply lands even if realtime
        // is dead (the "nothing until refresh" bug).
        setFollowupPollNonce((n) => n + 1);
        void aegisApi
          .sendTaskMessage(task.id, organizationId, trimmed)
          .then((res) => {
            if (res.queued) setTaskQueuedHint(true);
          })
          .catch(() => setSendError('Something went wrong. Please try again.'));
        return;
      }
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
    [
      sendMessage,
      clearError,
      liveReload,
      task,
      tasksLoading,
      propThreadId,
      organizationId,
      setMessages,
      setTaskWorking,
      setFollowupPollNonce,
      runTaskCommand,
    ],
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

  // Stop for a WORKER-side task run: the run isn't a useChat stream, so
  // useChat.stop() can't touch it. Cancel the task instead — the same call
  // TaskDetailPanel's Stop button makes — which rejects the task's in-flight
  // agent fix rows; the worker aborts at its next step boundary and
  // `taskWorking` flips off via the existing fix-row subscription. Best-effort:
  // a failure is swallowed (the worker also halts on its own budget/stall).
  const taskStoppingRef = useRef(false);
  const handleTaskStop = useCallback(async () => {
    if (!task || taskStoppingRef.current) return;
    taskStoppingRef.current = true;
    try {
      await aegisApi.cancelTask(task.id, organizationId);
    } catch {
      /* best-effort — see above */
    } finally {
      taskStoppingRef.current = false;
    }
  }, [task, organizationId]);

  // The composite "something is running" signal for the bottom input: a chat
  // SSE stream OR the task's worker run. Drives the Stop affordance and the
  // 'Add a follow-up' placeholder so task runs behave like chat streams.
  const taskRunActive = liveReload && taskWorking;

  // Show the thinking dot whenever the stream is in flight and there's no
  // self-evident visible affordance for the user. Suppressed only by
  // (a) actively-typing text content — the typing animation IS the
  // indicator — and (b) request_fix / revise_fix in flight, which render
  // PlanCardSkeleton. set_todos resolves immediately and produces the
  // strip, but the agent then often pauses to think before its next
  // visible action — those gaps fall into the default-true branch so the
  // dot reappears between actions instead of going dark.
  const showThinkingDot = useMemo(() => {
    // A task worker is actively running (it narrates via realtime, not useChat) —
    // show the dot between its beats so a task chat "thinks" like a normal chat.
    if (taskWorking) return true;
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
  }, [status, messages, taskWorking]);

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
        {messagesLoading ? (
          <ChatSkeleton />
        ) : (
        <div className="py-4">
          {task && <TaskHeader task={task} onOpenDetails={onOpenTaskDetails} />}
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
        )}
      </div>
      <div className="px-4 pb-4">
        <div className="mx-auto max-w-3xl">
          <ChatTodos messages={messages} streaming={status === 'streaming'} />
          <SendQueuePanel queue={sendQueue} onRemove={handleRemoveFromQueue} />
          {taskQueuedHint && (
            <div className="mb-2 px-4 text-xs text-foreground-secondary">
              Queued — I'll pick this up when the current run finishes.
            </div>
          )}
          {commandOutput && (
            <div className="mb-2 flex items-center justify-between gap-3 rounded-lg border border-border bg-background-subtle/50 px-3 py-2 text-xs text-foreground-secondary">
              <span className="font-mono">{commandOutput}</span>
              <button
                type="button"
                onClick={() => setCommandOutput(null)}
                className="shrink-0 text-foreground-secondary hover:text-foreground"
                aria-label="Dismiss"
              >
                ✕
              </button>
            </div>
          )}
          <div className="rounded-2xl bg-background-card border border-border">
            <ChatInput
              onSubmit={handleSubmit}
              placeholder={isStreaming || taskRunActive || sendQueue.length > 0 ? 'Add a follow-up' : 'Ask anything'}
              autoFocus
              models={enabledModels}
              selectedModelId={selectedModelId}
              onSelectModel={setSelectedModelId}
              modelsLoading={modelsLoading}
              isStreaming={isStreaming || taskRunActive}
              onStop={taskRunActive ? handleTaskStop : handleStop}
              slashCommands={liveReload && task ? TASK_SLASH_COMMANDS : undefined}
              contextUsage={contextUsage}
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
