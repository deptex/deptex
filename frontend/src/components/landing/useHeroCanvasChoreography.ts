/**
 * useHeroCanvasChoreography — scripts a "teammate" on the hero Overview graph so
 * the showcase feels alive (founder 2026-06-17). It drives the SAME inputs the
 * real OrganizationOverviewPage feeds OrgCanvasCursors during a live multiplayer
 * session — a `RemoteCursor[]` array and a `remoteDraggers` map — plus moves the
 * dragged node via setNodes + the `remote-dragging` className. So the animation
 * is byte-for-byte the real thing.
 *
 * Choreography (one cursor, two visits per loop):
 *   • Visit A — Maya glides up from the bottom, picks up storefront-api (white
 *     claim ring, label on the node top, arrow hidden), carries it straight UP
 *     into open space, DROPS it there, and slides back down off the bottom.
 *   • ~15s idle — the node just sits in its new spot.
 *   • Visit B — Maya comes back, picks it up, and moves it back to where it was.
 *   • ~15s idle — then the loop repeats.
 *
 * Everything is a scripted timeline on one rAF clock (the rAF timestamp is the
 * only clock — no Date.now). Node + cursor coords are React Flow flow-space, the
 * same space the layout emits, so positions line up with the real nodes.
 */
import { useEffect, useRef, useState } from "react";
import type { Dispatch, SetStateAction } from "react";
import type { Node } from "@xyflow/react";
import type { RemoteCursor } from "../vulnerabilities-graph/useOrgCanvasCursors";

const easeInOut = (t: number) =>
  t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
const lerp = (a: number, b: number, t: number) => a + (b - a) * t;
const clamp01 = (t: number) => (t < 0 ? 0 : t > 1 ? 1 : t);
const seg = (t: number, a: number, b: number) => clamp01((t - a) / (b - a));

type Pt = { x: number; y: number };
const lerpPt = (a: Pt, b: Pt, t: number): Pt => ({ x: lerp(a.x, b.x, t), y: lerp(a.y, b.y, t) });

// The project that gets picked up. HOME must match heroDemo's storefront-api
// canvasPosition (top-left flow coords); DEST is the same column, straight UP.
const DRAG_NODE_ID = "project-storefront-api";
const HOME: Pt = { x: -300, y: 320 };
const DEST: Pt = { x: -300, y: 80 };
const HALF = 30; // OVERVIEW_PROJECT_NODE_* is 60×60 → center is +30,+30
const center = (p: Pt): Pt => ({ x: p.x + HALF, y: p.y + HALF });
// Cursor enters from / leaves to the BOTTOM (well below the visible canvas).
const BOTTOM_Y = 600;

type CursorIdentity = Omit<RemoteCursor, "x" | "y">;
const MAYA: CursorIdentity = {
  userId: "maya",
  sessionId: "maya",
  name: "Maya",
  avatarUrl: null,
  role: "member",
  roleLabel: "Member",
  roleColor: "#60a5fa",
};

// ── One visit's local timeline (ms) ──────────────────────────────────────────
const APPROACH_END = 1500; // rise from bottom → node centre
const DRAG_END = 3300; // carry node from → to
const SETTLE_END = 3700; // beat on the dropped node
const LEAVE_END = 4900; // descend back off the bottom (= visit duration)

// ── Full loop = visit A · idle · visit B · idle ──────────────────────────────
const GAP = 10000;
const A_END = LEAVE_END;
const B_START = A_END + GAP;
const B_END = B_START + LEAVE_END;
const CYCLE = B_END + GAP;

const EMPTY_DRAGGERS: Record<string, string> = {};

interface VisitState {
  node: Pt;
  dragging: boolean;
  cursor: Pt;
}

/** Resolve node position, drag state, and cursor position for a visit that
 *  carries the node from `from` to `to`, at visit-local time `tau`. */
function visit(tau: number, from: Pt, to: Pt): VisitState {
  const fromC = center(from);
  const toC = center(to);
  if (tau < APPROACH_END) {
    const enterStart: Pt = { x: fromC.x, y: BOTTOM_Y };
    return { node: from, dragging: false, cursor: lerpPt(enterStart, fromC, easeInOut(seg(tau, 0, APPROACH_END))) };
  }
  if (tau < DRAG_END) {
    const node = lerpPt(from, to, easeInOut(seg(tau, APPROACH_END, DRAG_END)));
    return { node, dragging: true, cursor: center(node) };
  }
  if (tau < SETTLE_END) {
    return { node: to, dragging: false, cursor: toC };
  }
  const exitEnd: Pt = { x: toC.x, y: BOTTOM_Y };
  return { node: to, dragging: false, cursor: lerpPt(toC, exitEnd, easeInOut(seg(tau, SETTLE_END, LEAVE_END))) };
}

export function useHeroCanvasChoreography(
  setNodes: Dispatch<SetStateAction<Node[]>>,
) {
  const [cursors, setCursors] = useState<RemoteCursor[]>([]);
  const [draggers, setDraggers] = useState<Record<string, string>>(EMPTY_DRAGGERS);
  const startRef = useRef<number | null>(null);
  const rafRef = useRef<number | null>(null);
  const lastPos = useRef<Pt>(HOME);
  const lastDragging = useRef(false);
  const lastCount = useRef(0);

  useEffect(() => {
    const tick = (now: number) => {
      if (startRef.current == null) startRef.current = now;
      const t = (now - startRef.current) % CYCLE;

      // Resolve this frame's node position, drag state, and (optional) cursor.
      let nodePos: Pt = HOME;
      let dragging = false;
      let cursor: Pt | null = null;
      if (t < A_END) {
        const s = visit(t, HOME, DEST);
        nodePos = s.node;
        dragging = s.dragging;
        cursor = s.cursor;
      } else if (t < B_START) {
        nodePos = DEST; // dropped — sits up high while idle
      } else if (t < B_END) {
        const s = visit(t - B_START, DEST, HOME);
        nodePos = s.node;
        dragging = s.dragging;
        cursor = s.cursor;
      } else {
        nodePos = HOME; // back home, idle
      }

      // ── Move the node only when it actually changed ────────────────────────
      if (
        nodePos.x !== lastPos.current.x ||
        nodePos.y !== lastPos.current.y ||
        dragging !== lastDragging.current
      ) {
        const p = nodePos;
        const d = dragging;
        setNodes((nodes) =>
          nodes.map((n) =>
            n.id === DRAG_NODE_ID
              ? { ...n, position: { x: p.x, y: p.y }, className: d ? "remote-dragging" : undefined }
              : n,
          ),
        );
        lastPos.current = nodePos;
        lastDragging.current = dragging;
      }

      // ── Cursor + draggers ──────────────────────────────────────────────────
      const list: RemoteCursor[] = cursor ? [{ ...MAYA, x: cursor.x, y: cursor.y }] : [];
      // Avoid churn while the canvas is fully idle (cursor gone).
      if (!(list.length === 0 && lastCount.current === 0)) {
        setCursors(list);
      }
      lastCount.current = list.length;

      const nextDraggers = dragging ? { maya: DRAG_NODE_ID } : EMPTY_DRAGGERS;
      setDraggers((prev) => (prev.maya === nextDraggers.maya ? prev : nextDraggers));

      rafRef.current = requestAnimationFrame(tick);
    };

    rafRef.current = requestAnimationFrame(tick);
    return () => {
      if (rafRef.current != null) cancelAnimationFrame(rafRef.current);
      setNodes((nodes) =>
        nodes.map((n) =>
          n.id === DRAG_NODE_ID
            ? { ...n, position: { x: HOME.x, y: HOME.y }, className: undefined }
            : n,
        ),
      );
    };
  }, [setNodes]);

  return { cursors, draggers };
}
