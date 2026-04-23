import { useEffect, useMemo, useRef, useState } from 'react';
import { z } from 'zod';
import { PerfectCursor } from '../../lib/perfectCursor';
import type { RealtimeChannel } from '@supabase/supabase-js';
import { supabase } from '../../lib/supabase';
import { api } from '../../lib/api';

const DRAG_SEND_INTERVAL_MS = 40;
// Long safety fallback: cursors auto-expire if we haven't heard from the user
// in this window (covers crashes / network drops).
const EXPIRY_MS = 60000;
const EXPIRY_CHECK_MS = 5000;
const HEARTBEAT_MS = 15000;
// Admins fan-out to N+1 channels; higher throttle reduces broadcast volume.
const CURSOR_SEND_INTERVAL_MS_MEMBER = 80;
const CURSOR_SEND_INTERVAL_MS_ADMIN = 150;

// Inbound payload schemas — validate and strip unknown fields on receive.
const CursorPayloadSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().min(1),
  x: z.number().finite(),
  y: z.number().finite(),
  seq: z.number().int().nonnegative(),
});

const DragStartSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().optional(),
  nodeId: z.string().min(1).max(256),
  seq: z.number().int().nonnegative(),
  canDrag: z.boolean().optional(),
});

const DragMoveSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().optional(),
  moves: z.array(
    z.object({
      nodeId: z.string().min(1).max(256),
      x: z.number().finite(),
      y: z.number().finite(),
    }),
  ).max(200),
  seq: z.number().int().nonnegative(),
});

const DragStopSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().optional(),
  nodeId: z.string().min(1).max(256),
  seq: z.number().int().nonnegative(),
});

const CursorLeaveSchema = z.object({
  userId: z.string().min(1),
  sessionId: z.string().optional(),
  seq: z.number().int().nonnegative(),
});

const CanvasSettingsSchema = z.object({
  enabled: z.boolean(),
});

type CursorPayload = z.infer<typeof CursorPayloadSchema>;

export interface RemoteCursor {
  userId: string;
  /** Per-tab session id. Different tabs of the same user show as separate cursors. */
  sessionId: string;
  name: string;
  avatarUrl: string | null;
  role: string | null;
  roleLabel: string | null;
  roleColor: string | null;
  /** Interpolated position in flow-space. */
  x: number;
  y: number;
}

interface CursorEntry {
  pc: PerfectCursor;
  userId: string;
  sessionId: string;
  pos: { x: number; y: number };
  lastSeen: number;
  lastSeq: number;
}

interface RosterEntry {
  name: string;
  avatarUrl: string | null;
  role: string | null;
  roleLabel: string | null;
  roleColor: string | null;
}

export interface LocalIdentity {
  userId: string;
  name: string;
  avatarUrl: string | null;
  role: string | null;
  roleLabel: string | null;
  roleColor: string | null;
}

export interface NodePositionUpdate {
  nodeId: string;
  x: number;
  y: number;
}

export interface RemoteDragStartMessage {
  userId: string;
  sessionId?: string;
  nodeId: string;
  seq: number;
  /** False when the sender lacks manage_teams_and_projects — drag won't persist server-side. */
  canDrag?: boolean;
}

export interface RemoteDragMoveMessage {
  userId: string;
  sessionId?: string;
  moves: NodePositionUpdate[];
  seq: number;
}

export interface RemoteDragStopMessage {
  userId: string;
  sessionId?: string;
  nodeId: string;
  seq: number;
}

export interface CursorLeaveMessage {
  userId: string;
  sessionId?: string;
  seq: number;
}

export interface CanvasChannelOptions {
  onRemoteDragStart?: (msg: RemoteDragStartMessage) => void;
  onRemoteDragMove?: (msg: RemoteDragMoveMessage) => void;
  onRemoteDragStop?: (msg: RemoteDragStopMessage) => void;
  /** Called when the owner broadcasts an org-level cursor enable/disable. */
  onOrgSettingsChange?: (enabled: boolean) => void;
}

export interface CanvasAccess {
  /** Teams the local user is an actual `team_members` row for. Used for
   *  cursor send fan-out (admins only publish to teams they're in). */
  myActualTeamIds: string[];
  /** Every team the local user can SEE (all teams in org for admins,
   *  only member teams otherwise). Used for subscribing. */
  visibleTeamIds: string[];
  /** True if the local user has manage_teams_and_projects (or is owner). */
  isOrgAdmin: boolean;
  /** projectId -> owning teamId. Used to route drag events to the right team channel. */
  projectTeamMap: Record<string, string>;
}

function orgTopic(orgId: string) { return `org-canvas:${orgId}:org`; }
function adminsTopic(orgId: string) { return `org-canvas:${orgId}:admins`; }
function teamTopic(orgId: string, teamId: string) { return `org-canvas:${orgId}:team:${teamId}`; }

/**
 * Resolve the team channel (if any) that a drag event should route to.
 * Team nodes are `team-{teamId}`, project nodes are `project-{projectId}`
 * and get routed via projectTeamMap. Returns null for org-center (admins-only).
 */
function resolveDragTeamId(nodeId: string, projectTeamMap: Record<string, string>): string | null {
  if (nodeId.startsWith('team-')) return nodeId.slice('team-'.length);
  if (nodeId.startsWith('project-')) {
    const pid = nodeId.slice('project-'.length);
    return projectTeamMap[pid] ?? null;
  }
  return null;
}

/**
 * Opens Supabase Broadcast channels for the org canvas and handles both
 * cursor streaming + node drag streaming with server-side permission
 * enforcement via realtime.messages RLS.
 *
 * Security model:
 *   - Inbound payloads are validated with Zod; invalid messages are dropped silently.
 *   - Cursor payloads carry only (userId, sessionId, x, y, seq). Identity fields
 *     (name, avatar, role) are never trusted from the wire; they are re-derived on
 *     each render from a server-fetched org member roster.
 *   - The DB INSERT policy enforces payload.userId = auth.uid(), so userId is attested.
 *
 * Topology (unchanged):
 *   - Admins subscribe to `org-canvas:{orgId}:admins` and all team channels.
 *   - Members subscribe to their own team channels.
 *   - Fan-out: admins publish to :admins + their actual team channels; members to their teams.
 */
export function useOrgCanvasCursors(
  orgId: string | undefined,
  me: LocalIdentity | null,
  access: CanvasAccess | null,
  options: CanvasChannelOptions = {},
) {
  const [cursors, setCursors] = useState<RemoteCursor[]>([]);
  // crypto.randomUUID() is available in all modern browsers (Chromium 92+, FF 95+, Safari 15.4+).
  const mySessionId = useRef(crypto.randomUUID());
  const entriesRef = useRef(new Map<string, CursorEntry>());
  const rosterRef = useRef(new Map<string, RosterEntry>());
  const sendCursorRef = useRef<(payload: { x: number; y: number }) => void>(() => {});
  const sendDragStartRef = useRef<(nodeId: string) => void>(() => {});
  const sendDragMoveRef = useRef<(moves: NodePositionUpdate[]) => void>(() => {});
  const sendDragStopRef = useRef<(nodeId: string) => void>(() => {});
  const sendLeaveRef = useRef<() => void>(() => {});
  const sendOrgSettingsRef = useRef<(enabled: boolean) => void>(() => {});
  const lastCursorSentRef = useRef(0);
  const lastDragSentRef = useRef(0);
  const lastLocalPosRef = useRef<{ x: number; y: number } | null>(null);
  const lastBroadcastAtRef = useRef(0);
  const seqRef = useRef(0);
  const rafRef = useRef<number | null>(null);

  const optionsRef = useRef(options);
  optionsRef.current = options;

  const myActualTeamsKey = access ? [...access.myActualTeamIds].sort().join(',') : '';
  const visibleTeamsKey = access ? [...access.visibleTeamIds].sort().join(',') : '';
  const isAdmin = access?.isOrgAdmin ?? false;
  const projectTeamMapRef = useRef<Record<string, string>>({});
  projectTeamMapRef.current = access?.projectTeamMap ?? {};

  // Fetch org member roster once per orgId. Identity (name/avatar/role) is re-derived
  // from this server-sourced map on receive rather than trusting client-declared fields.
  useEffect(() => {
    if (!orgId) return;
    let cancelled = false;
    api.getOrganizationMembers(orgId).then((members) => {
      if (cancelled) return;
      const map = new Map<string, RosterEntry>();
      for (const m of members) {
        map.set(m.user_id, {
          name: m.full_name || m.email || m.user_id,
          avatarUrl: m.avatar_url ?? null,
          role: m.role ?? null,
          roleLabel: m.role_display_name ?? null,
          roleColor: m.role_color ?? null,
        });
      }
      rosterRef.current = map;
    }).catch(() => {});
    return () => { cancelled = true; };
  }, [orgId]);

  useEffect(() => {
    if (!orgId || !me || !access) return;

    const cursorSendIntervalMs = isAdmin ? CURSOR_SEND_INTERVAL_MS_ADMIN : CURSOR_SEND_INTERVAL_MS_MEMBER;

    const subscribedTopics: string[] = [
      orgTopic(orgId),
      ...access.visibleTeamIds.map((tid) => teamTopic(orgId, tid)),
    ];
    if (isAdmin) subscribedTopics.push(adminsTopic(orgId));

    const cursorPublishTopics: string[] = isAdmin
      ? [adminsTopic(orgId), ...access.myActualTeamIds.map((tid) => teamTopic(orgId, tid))]
      : access.myActualTeamIds.map((tid) => teamTopic(orgId, tid));

    const channels: RealtimeChannel[] = [];
    const channelByTopic = new Map<string, RealtimeChannel>();

    // Build snapshot resolving identity from the server-fetched roster, not payloads.
    const buildSnapshot = (): RemoteCursor[] => {
      const snap: RemoteCursor[] = [];
      entriesRef.current.forEach((entry) => {
        const r = rosterRef.current.get(entry.userId);
        snap.push({
          userId: entry.userId,
          sessionId: entry.sessionId,
          name: r?.name ?? 'Unknown',
          avatarUrl: r?.avatarUrl ?? null,
          role: r?.role ?? null,
          roleLabel: r?.roleLabel ?? null,
          roleColor: r?.roleColor ?? null,
          x: entry.pos.x,
          y: entry.pos.y,
        });
      });
      return snap;
    };

    const startTick = () => {
      if (rafRef.current != null) return;
      const tick = () => {
        if (entriesRef.current.size === 0) {
          rafRef.current = null;
          return;
        }
        setCursors(buildSnapshot());
        rafRef.current = requestAnimationFrame(tick);
      };
      rafRef.current = requestAnimationFrame(tick);
    };

    const handleCursor = (raw: unknown) => {
      const result = CursorPayloadSchema.safeParse(raw);
      if (!result.success) return;
      const p = result.data;
      if (p.sessionId === mySessionId.current) return;
      const key = p.sessionId || p.userId;
      let entry = entriesRef.current.get(key);
      if (!entry) {
        const created: CursorEntry = {
          pc: new PerfectCursor(([x, y]: number[]) => {
            const e = entriesRef.current.get(key);
            if (e) e.pos = { x, y };
          }),
          userId: p.userId,
          sessionId: p.sessionId,
          pos: { x: p.x, y: p.y },
          lastSeen: Date.now(),
          lastSeq: p.seq,
        };
        entriesRef.current.set(key, created);
        entry = created;
        startTick();
      } else {
        // Dedupe across channels: only apply if this seq is newer.
        if (p.seq <= entry.lastSeq) return;
        entry.lastSeq = p.seq;
        entry.lastSeen = Date.now();
      }
      entry.pc.addPoint([p.x, p.y]);
    };

    const dragSeqBySession = new Map<string, number>();
    const isFresh = (p: { userId: string; sessionId?: string; seq: number }) => {
      if (p.sessionId === mySessionId.current) return false;
      const key = p.sessionId || p.userId;
      const last = dragSeqBySession.get(key) ?? -1;
      if (p.seq <= last) return false;
      dragSeqBySession.set(key, p.seq);
      return true;
    };

    const handleDragStart = (raw: unknown) => {
      const result = DragStartSchema.safeParse(raw);
      if (!result.success) return;
      if (!isFresh(result.data)) return;
      optionsRef.current.onRemoteDragStart?.(result.data);
    };
    const handleDragMove = (raw: unknown) => {
      const result = DragMoveSchema.safeParse(raw);
      if (!result.success) return;
      if (!isFresh(result.data)) return;
      optionsRef.current.onRemoteDragMove?.(result.data);
    };
    const handleDragStop = (raw: unknown) => {
      const result = DragStopSchema.safeParse(raw);
      if (!result.success) return;
      if (!isFresh(result.data)) return;
      optionsRef.current.onRemoteDragStop?.(result.data);
    };
    const handleLeave = (raw: unknown) => {
      const result = CursorLeaveSchema.safeParse(raw);
      if (!result.success) return;
      const p = result.data;
      if (p.sessionId === mySessionId.current) return;
      const key = p.sessionId || p.userId;
      const entry = entriesRef.current.get(key);
      if (!entry) return;
      entry.pc.dispose();
      entriesRef.current.delete(key);
      setCursors(buildSnapshot());
    };

    for (const topic of subscribedTopics) {
      const channel = supabase.channel(topic, {
        config: {
          broadcast: { self: false },
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          private: true,
        } as any,
      });
      channel.on('broadcast', { event: 'cursor' }, (msg) => handleCursor(msg.payload));
      channel.on('broadcast', { event: 'drag-start' }, (msg) => handleDragStart(msg.payload));
      channel.on('broadcast', { event: 'drag-move' }, (msg) => handleDragMove(msg.payload));
      channel.on('broadcast', { event: 'drag-stop' }, (msg) => handleDragStop(msg.payload));
      channel.on('broadcast', { event: 'cursor-leave' }, (msg) => handleLeave(msg.payload));
      channel.on('broadcast', { event: 'canvas-settings' }, (msg) => {
        const result = CanvasSettingsSchema.safeParse(msg.payload);
        if (result.success) optionsRef.current.onOrgSettingsChange?.(result.data.enabled);
      });
      channel.subscribe((status) => {
        if (status === 'CHANNEL_ERROR' || status === 'TIMED_OUT') {
          console.warn(`[canvas] channel ${topic} failed to subscribe: ${status}`);
        }
      });
      channels.push(channel);
      channelByTopic.set(topic, channel);
    }

    const fanOut = (event: string, payload: object, topics: string[]) => {
      for (const topic of topics) {
        const ch = channelByTopic.get(topic);
        if (!ch) continue;
        ch.send({ type: 'broadcast', event, payload });
      }
    };

    const broadcastCursor = (x: number, y: number) => {
      lastBroadcastAtRef.current = Date.now();
      // Identity fields (name, avatarUrl, role, roleLabel, roleColor) are intentionally
      // omitted. Receivers re-derive them from the server-fetched roster by userId.
      const payload: CursorPayload = {
        userId: me.userId,
        sessionId: mySessionId.current,
        x,
        y,
        seq: ++seqRef.current,
      };
      fanOut('cursor', payload, cursorPublishTopics);
    };

    sendCursorRef.current = (payload) => {
      lastLocalPosRef.current = payload;
      const now = Date.now();
      if (now - lastCursorSentRef.current < cursorSendIntervalMs) return;
      lastCursorSentRef.current = now;
      broadcastCursor(payload.x, payload.y);
    };

    // Drag routing: team-prefix nodes + projects under a team route to that team's
    // channel. Org-center and ungrouped nodes route to :org (admin write only).
    const dragTargets = (nodeIds: string[]): string[] => {
      const targets = new Set<string>();
      for (const nid of nodeIds) {
        const tid = resolveDragTeamId(nid, projectTeamMapRef.current);
        if (tid) targets.add(teamTopic(orgId, tid));
        else targets.add(orgTopic(orgId));
      }
      return Array.from(targets);
    };

    sendDragStartRef.current = (nodeId) => {
      lastDragSentRef.current = 0;
      const payload: RemoteDragStartMessage = {
        userId: me.userId,
        sessionId: mySessionId.current,
        nodeId,
        seq: ++seqRef.current,
        canDrag: isAdmin,
      };
      fanOut('drag-start', payload, dragTargets([nodeId]));
    };

    sendDragMoveRef.current = (moves) => {
      const now = Date.now();
      if (now - lastDragSentRef.current < DRAG_SEND_INTERVAL_MS) return;
      lastDragSentRef.current = now;
      const payload: RemoteDragMoveMessage = {
        userId: me.userId,
        sessionId: mySessionId.current,
        moves,
        seq: ++seqRef.current,
      };
      fanOut('drag-move', payload, dragTargets(moves.map((m) => m.nodeId)));
    };

    sendDragStopRef.current = (nodeId) => {
      const payload: RemoteDragStopMessage = {
        userId: me.userId,
        sessionId: mySessionId.current,
        nodeId,
        seq: ++seqRef.current,
      };
      fanOut('drag-stop', payload, dragTargets([nodeId]));
    };

    sendLeaveRef.current = () => {
      lastLocalPosRef.current = null;
      const payload: CursorLeaveMessage = {
        userId: me.userId,
        sessionId: mySessionId.current,
        seq: ++seqRef.current,
      };
      fanOut('cursor-leave', payload, cursorPublishTopics);
    };

    // Owner broadcasts org-level cursor toggle on :org so all members update instantly.
    // Only admins can write to :org (RLS enforced), so non-owner calls are no-ops.
    sendOrgSettingsRef.current = (enabled: boolean) => {
      const orgCh = channelByTopic.get(orgTopic(orgId));
      orgCh?.send({ type: 'broadcast', event: 'canvas-settings', payload: { enabled } });
    };

    const heartbeatInterval = setInterval(() => {
      const pos = lastLocalPosRef.current;
      if (!pos) return;
      if (Date.now() - lastBroadcastAtRef.current < HEARTBEAT_MS) return;
      broadcastCursor(pos.x, pos.y);
    }, HEARTBEAT_MS);

    const expiryInterval = setInterval(() => {
      const now = Date.now();
      const staleKeys: string[] = [];
      entriesRef.current.forEach((entry, key) => {
        if (now - entry.lastSeen > EXPIRY_MS) staleKeys.push(key);
      });
      if (staleKeys.length === 0) return;
      for (const key of staleKeys) {
        entriesRef.current.get(key)?.pc.dispose();
        entriesRef.current.delete(key);
      }
      setCursors(buildSnapshot());
    }, EXPIRY_CHECK_MS);

    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
      clearInterval(expiryInterval);
      clearInterval(heartbeatInterval);
      // Best-effort leave broadcast so peers drop us immediately rather than
      // waiting for the 60s safety expiry.
      try {
        const payload: CursorLeaveMessage = {
          userId: me.userId,
          sessionId: mySessionId.current,
          seq: ++seqRef.current,
        };
        for (const topic of cursorPublishTopics) {
          const ch = channelByTopic.get(topic);
          ch?.send({ type: 'broadcast', event: 'cursor-leave', payload });
        }
      } catch { /* channels may already be closed */ }
      entriesRef.current.forEach((e) => e.pc.dispose());
      entriesRef.current.clear();
      sendCursorRef.current = () => {};
      sendDragStartRef.current = () => {};
      sendDragMoveRef.current = () => {};
      sendDragStopRef.current = () => {};
      sendLeaveRef.current = () => {};
      sendOrgSettingsRef.current = () => {};
      lastLocalPosRef.current = null;
      for (const ch of channels) {
        ch.unsubscribe();
        supabase.removeChannel(ch);
      }
    };
  }, [
    orgId,
    me?.userId,
    myActualTeamsKey,
    visibleTeamsKey,
    isAdmin,
  ]);

  const channelApi = useMemo(
    () => ({
      sendLocal: (x: number, y: number) => sendCursorRef.current({ x, y }),
      sendDragStart: (nodeId: string) => sendDragStartRef.current(nodeId),
      sendDragMove: (moves: NodePositionUpdate[]) => sendDragMoveRef.current(moves),
      sendDragStop: (nodeId: string) => sendDragStopRef.current(nodeId),
      sendLeave: () => sendLeaveRef.current(),
      sendOrgSettings: (enabled: boolean) => sendOrgSettingsRef.current(enabled),
    }),
    [],
  );

  return { remoteCursors: cursors, ...channelApi };
}
