import { useEffect, useMemo, useRef } from 'react';
import { useViewport, type Node } from '@xyflow/react';
import { Lock } from 'lucide-react';
import type { RemoteCursor } from './useOrgCanvasCursors';
import { RoleBadge } from '../RoleBadge';

function isSafeImageUrl(url: string | null | undefined): url is string {
  if (typeof url !== 'string' || !url) return false;
  try {
    const parsed = new URL(url, window.location.href);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

interface Props {
  remoteCursors: RemoteCursor[];
  onLocalCursorMove: (flowX: number, flowY: number) => void;
  onLocalCursorLeave?: () => void;
  /** userId -> nodeId of the node that user is currently dragging. */
  remoteDraggers: Record<string, string>;
  /** All graph nodes; used to look up live positions of dragged nodes. */
  graphNodes: Node[];
}

/**
 * Presentational multiplayer cursor layer. Must be a child of ReactFlow so it
 * has viewport context. Tracks the local pointer on the pane and emits
 * flow-space coordinates via onLocalCursorMove; renders remote cursors passed
 * in from the page-level channel hook.
 */
export function OrgCanvasCursors({
  remoteCursors,
  onLocalCursorMove,
  onLocalCursorLeave,
  remoteDraggers,
  graphNodes,
}: Props) {
  const viewport = useViewport();
  const viewportRef = useRef(viewport);
  viewportRef.current = viewport;
  const containerRef = useRef<HTMLDivElement>(null);
  const onMoveRef = useRef(onLocalCursorMove);
  onMoveRef.current = onLocalCursorMove;
  const onLeaveRef = useRef(onLocalCursorLeave);
  onLeaveRef.current = onLocalCursorLeave;

  // Use the same key derivation as remoteDraggers (sessionId || userId) so the
  // anonymous-drag-pill guard correctly matches entries keyed by sessionId.
  const knownDraggerKeys = useMemo(
    () => new Set(remoteCursors.map((c) => c.sessionId || c.userId)),
    [remoteCursors],
  );

  const nodeBoxById = useMemo(() => {
    const m = new Map<string, { x: number; y: number; width: number; height: number }>();
    for (const n of graphNodes) {
      const style = n.style as { width?: number | string; height?: number | string } | undefined;
      const w = typeof style?.width === 'number' ? style.width : (n.width ?? 220);
      const h = typeof style?.height === 'number' ? style.height : (n.height ?? 88);
      m.set(n.id, { x: n.position.x, y: n.position.y, width: w, height: h });
    }
    return m;
  }, [graphNodes]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const pane = el.parentElement;
    if (!pane) return;

    const handleMove = (e: PointerEvent) => {
      const rect = pane.getBoundingClientRect();
      const sx = e.clientX - rect.left;
      const sy = e.clientY - rect.top;
      const vp = viewportRef.current;
      const zoom = vp.zoom || 1;
      const fx = (sx - vp.x) / zoom;
      const fy = (sy - vp.y) / zoom;
      onMoveRef.current(fx, fy);
    };

    const handleLeave = () => {
      onLeaveRef.current?.();
    };

    pane.addEventListener('pointermove', handleMove);
    pane.addEventListener('pointerleave', handleLeave);
    window.addEventListener('blur', handleLeave);
    return () => {
      pane.removeEventListener('pointermove', handleMove);
      pane.removeEventListener('pointerleave', handleLeave);
      window.removeEventListener('blur', handleLeave);
    };
  }, []);

  return (
    <div
      ref={containerRef}
      className="pointer-events-none absolute inset-0 overflow-hidden"
      style={{ zIndex: 5 }}
      aria-hidden
    >
      {remoteCursors.map((c) => {
        const vp = viewportRef.current;
        const zoom = vp.zoom || 1;
        const draggerKey = c.sessionId || c.userId;
        const draggedNodeId = remoteDraggers[draggerKey];

        if (draggedNodeId) {
          // Dragging a node we can see: hide the arrow, show only the label
          // centered above the top edge of the dragged node (Figma-style
          // claim indicator). If the dragged node isn't in our view (e.g.
          // permission-gated or offscreen data), fall through to the normal
          // cursor render so the remote user doesn't vanish from the canvas.
          const box = nodeBoxById.get(draggedNodeId);
          if (box) {
            const centerX = (box.x + box.width / 2) * zoom + vp.x;
            const topY = box.y * zoom + vp.y;
            return (
              <div
                key={draggerKey}
                className="absolute top-0 left-0"
                style={{ transform: `translate(${centerX}px, ${topY}px)` }}
              >
                <div className="absolute left-1/2 -translate-x-1/2 -translate-y-full">
                  <CursorLabel cursor={c} compact attached />
                </div>
              </div>
            );
          }
        }

        const sx = c.x * zoom + vp.x;
        const sy = c.y * zoom + vp.y;
        return (
          <div
            key={draggerKey}
            className="absolute top-0 left-0"
            style={{ transform: `translate(${sx}px, ${sy}px)` }}
          >
            <CursorArrow />
            <CursorLabel cursor={c} />
          </div>
        );
      })}
      {/* Anonymous drag indicators: someone is dragging a node we can see,
          but we don't have their cursor metadata (e.g. an admin whose
          cursor isn't routed to this team's channel). Show a generic
          "locked" pill attached to the node top so the UI doesn't look
          like the node is moving on its own. */}
      {Object.entries(remoteDraggers).map(([draggerKey, nodeId]) => {
        if (knownDraggerKeys.has(draggerKey)) return null;
        const box = nodeBoxById.get(nodeId);
        if (!box) return null;
        const vp = viewportRef.current;
        const zoom = vp.zoom || 1;
        const centerX = (box.x + box.width / 2) * zoom + vp.x;
        const topY = box.y * zoom + vp.y;
        return (
          <div
            key={`anon-${draggerKey}`}
            className="absolute top-0 left-0"
            style={{ transform: `translate(${centerX}px, ${topY}px)` }}
          >
            <div className="absolute left-1/2 -translate-x-1/2 -translate-y-full">
              <AnonymousDragPill />
            </div>
          </div>
        );
      })}
    </div>
  );
}

function AnonymousDragPill() {
  return (
    <div
      className="inline-flex items-center gap-1 rounded-md border border-border bg-background-card-header/95 backdrop-blur-sm px-1.5 py-0.5 whitespace-nowrap select-none"
      style={{ boxShadow: '0 0 0 1.5px rgba(212, 212, 212, 0.5), 0 0 0 4px rgba(212, 212, 212, 0.04)' }}
    >
      <Lock className="h-3 w-3 text-muted-foreground" strokeWidth={2} />
      <span className="text-[11px] font-medium text-muted-foreground leading-none">Being moved</span>
    </div>
  );
}

function CursorArrow() {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 18 18"
      fill="none"
      style={{ filter: 'drop-shadow(0 1px 2px rgba(0,0,0,0.45))', display: 'block' }}
      aria-hidden
    >
      <path
        d="M2 1.5 L2 14 L5.5 10.5 L8 16 L10.5 15 L8 9.5 L13 9.5 Z"
        fill="#0a0a0a"
        stroke="rgba(255,255,255,0.55)"
        strokeWidth="1.1"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function CursorLabel({
  cursor,
  compact = false,
  attached = false,
}: { cursor: RemoteCursor; compact?: boolean; attached?: boolean }) {
  const safeName = typeof cursor.name === 'string' ? cursor.name : '';
  const initial = safeName.trim().charAt(0).toUpperCase() || '?';
  const attachedRing = attached
    ? { boxShadow: '0 0 0 1.5px rgba(212, 212, 212, 0.5), 0 0 0 4px rgba(212, 212, 212, 0.04)' }
    : undefined;
  return (
    <div
      className={`${compact ? '' : 'absolute left-4 top-4'} inline-flex items-center gap-1.5 rounded-md border border-border bg-background-card-header/95 backdrop-blur-sm pl-0.5 pr-1.5 py-0.5 ${attached ? '' : 'shadow-lg'} whitespace-nowrap select-none`}
      style={attachedRing}
    >
      <span className="flex h-[18px] w-[18px] shrink-0 items-center justify-center overflow-hidden rounded-full bg-muted/60">
        {isSafeImageUrl(cursor.avatarUrl) ? (
          <img
            src={cursor.avatarUrl}
            alt=""
            className="h-full w-full object-cover"
            referrerPolicy="no-referrer"
            onError={(e) => {
              (e.currentTarget as HTMLImageElement).style.display = 'none';
            }}
          />
        ) : (
          <span className="text-[10px] font-semibold text-muted-foreground leading-none">{initial}</span>
        )}
      </span>
      <span className="text-[11px] font-medium text-foreground leading-none">{safeName}</span>
      {cursor.roleLabel && cursor.role && (
        <RoleBadge
          role={cursor.role}
          roleDisplayName={cursor.roleLabel}
          roleColor={cursor.roleColor}
          className="!px-1 !py-0 !text-[9px] !leading-[14px]"
        />
      )}
    </div>
  );
}
