# Feature Brief — Org Overview Graph: Multiplayer Canvas

**Status:** Discovery complete. Ready for planning phase.
**Author:** Henry + Claude
**Date:** 2026-04-18
**Target surface:** `OrganizationOverviewPage.tsx` — General tab graph

---

## 1. One-liner

Turn the static, hard-coded organization overview graph into a shared, Figma-inspired multiplayer canvas — draggable team/project nodes with persisted positions, live teammate cursors, and a cursor-reactive background dot grid that makes the page feel alive.

---

## 2. Problem statement

The org overview graph today is visually polished but emotionally flat:

- Nodes are laid out by a fixed Fibonacci algorithm; users can't personalize or arrange it.
- There's no sense of "other people are here" — it's a dashboard, not a canvas.
- Hover/interaction feedback is minimal; the graph doesn't *react* to the user.
- The layout recomputes every render, so even if we added drag-to-move it wouldn't persist.

This is the primary screen org admins land on. Making it feel like a living, shared space significantly upgrades the perceived quality of the product and gives Deptex a brand moment on the most-viewed page.

---

## 3. Competitive landscape

| Pattern | Who does it | What we'll steal |
|---|---|---|
| Live multiplayer cursors with interpolation | Figma, tldraw, Linear | Supabase Realtime **Broadcast** channel, ~80ms throttle, `perfect-cursors` library for spline interpolation between samples |
| Cursor-reactive background dot grid | Google Stitch, Linear marketing, Aceternity UI | **Canvas 2D layer synced to React Flow viewport** — replaces `<Background variant={Dots}>` (which is NOT cursor-reactive); radius/opacity falloff as gaussian over ~150px |
| Drag juice | Figma, Miro, tldraw | CSS-only `.dragging` class → `transform: scale(1.02-1.05)` + shadow grow + 150ms spring settle on drop |
| Shared persisted layout | Figma, Miro | Nullable `canvas_position_x/y` on existing `teams` + `projects` tables; write-once on spawn, update on drag |
| Team-as-group container | (deferred) | Not in scope for this phase. Both "parent node" (React Flow native) and "faded backdrop rectangle" approaches remain options for a later phase. |

**Key technical insight:** React Flow's `<Background variant={Dots}>` renders a static SVG `<pattern>` — it cannot be made cursor-reactive. The last attempt failed because it added *new* dots on top of the existing grid instead of replacing the background entirely. This time: replace the background with a Canvas 2D component, sync to `useViewport()`, redraw on `pointermove`.

---

## 4. User stories

- **As an org admin with `manage_teams_and_projects`**, I can drag any team or project on the canvas and my arrangement persists for everyone in the org.
- **As a team member without that permission**, I can view the canvas, see my teammates' cursors live, and feel the dot grid respond to my cursor — but I cannot drag nodes.
- **As any viewer**, when I move my mouse across the canvas, the nearby background dots thicken/brighten in a soft radial falloff around my cursor.
- **As any viewer**, when a teammate I can see moves their mouse, I see their live cursor with name + avatar label.
- **As a team member**, if an org owner (not on my team) drags a team I *can* see, the node animates to its new position with a "being moved by someone" glow — without exposing the owner's cursor.
- **As an admin**, when I drag a team, its child projects translate rigidly with it (like a group).
- **As an admin**, when I drag a single project, only that project moves; its parent team stays put.

---

## 5. Data model

### Schema changes

```sql
-- Migration: backend/database/phase_XX_canvas_layout.sql
ALTER TABLE teams
  ADD COLUMN canvas_position_x REAL NULL,
  ADD COLUMN canvas_position_y REAL NULL,
  ADD COLUMN canvas_position_updated_at TIMESTAMPTZ NULL,
  ADD COLUMN canvas_position_updated_by UUID NULL REFERENCES users(id);

ALTER TABLE projects
  ADD COLUMN canvas_position_x REAL NULL,
  ADD COLUMN canvas_position_y REAL NULL,
  ADD COLUMN canvas_position_updated_at TIMESTAMPTZ NULL,
  ADD COLUMN canvas_position_updated_by UUID NULL REFERENCES users(id);
```

### Semantics

- **NULL position** = node has never been placed. Compute on first render, write back immediately. Should only be NULL between node creation and first load.
- **Non-NULL position** = authoritative. Never recomputed.
- **Deletion** = cascade removes rows, which removes positions. No orphans.
- **Node addition after layout saved**: compute new position via Fibonacci-next-slot or non-overlap scan → persist immediately → everyone sees the same spot.

### Why nullable columns (not a separate table)

- Positions are tightly coupled to the team/project lifetime (cascade on delete is free).
- No need for "multiple canvases per org" (YAGNI).
- Minimal code surface — reads the team/project and has everything it needs.

### Trade-off noted

The org center node is not movable and has no position column — always rendered at (0, 0).

---

## 6. API endpoints

### New routes (`backend/src/routes/organization-canvas.ts`)

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `PATCH` | `/api/organizations/:orgId/canvas/teams/:teamId/position` | Bearer + `manage_teams_and_projects` | Persist a team's new (x, y). Idempotent. |
| `PATCH` | `/api/organizations/:orgId/canvas/projects/:projectId/position` | Bearer + `manage_teams_and_projects` | Persist a project's new (x, y). |
| `POST` | `/api/organizations/:orgId/canvas/positions:batch` | Bearer + `manage_teams_and_projects` | Batch update — used when dragging a team moves N projects together. Atomic. |

### Realtime channel

- **Channel name:** `org-canvas:{orgId}`
- **Transport:** Supabase Realtime **Broadcast** (not Presence — Presence is rate-limited and does reconciliation we don't need).
- **Throttle:** ~80ms client-side on cursor broadcasts.

### Event payloads

```ts
type CanvasEvent =
  | { type: 'cursor_move'; userId: string; x: number; y: number }
  | { type: 'node_drag_start'; userId: string; nodeType: 'team' | 'project'; nodeId: string }
  | { type: 'node_drag_move'; userId: string; nodeType: 'team' | 'project'; nodeId: string; x: number; y: number }
  | { type: 'node_drag_end'; userId: string; nodeType: 'team' | 'project'; nodeId: string; x: number; y: number }
  | { type: 'node_position_saved'; nodeType: 'team' | 'project'; nodeId: string; x: number; y: number }
```

### Visibility filtering

Supabase Broadcast is pub/sub — all channel subscribers receive all events. **Client-side filtering** decides what to render based on the viewer's RBAC:

- `cursor_move` events: render only if the broadcasting user is in one of my teams, OR I have `manage_teams_and_projects`.
- `node_drag_*` events: render if I can see the node (same rule as reading the team/project today).
- **Ghost drag**: if I receive a `node_drag_move` for a node I *can* see, but the `userId`'s cursor is *not* visible to me → render the node motion with a "being moved by someone" glow, no cursor.

Cursor positions are low-sensitivity (mouse x/y on a page). Client-side filtering is adequate. Server enforcement happens on the `PATCH` position endpoints (which are the only way changes actually persist).

---

## 7. Frontend views & components

### New components

- `frontend/src/components/organization-graph/ReactiveDotBackground.tsx`
  - Canvas 2D component mounted behind `<ReactFlow>`.
  - Subscribes to `useViewport()` for pan/zoom sync.
  - Listens to `pointermove` on the flow pane, redraws dots with radius/opacity = gaussian of distance to cursor (~150px radius).
  - World-locked: dots pan/zoom with the canvas.

- `frontend/src/components/organization-graph/MultiplayerCursors.tsx`
  - Renders other users' cursors as absolutely-positioned overlays on top of React Flow.
  - Uses `perfect-cursors` for spline interpolation between throttled samples.
  - Each cursor: shape (arrow) + avatar + name label, constant screen-pixel size (scales with zoom inversely).
  - Filters which cursors to render based on RBAC visibility.

- `frontend/src/components/organization-graph/useCursorBroadcast.ts`
  - Hook that throttles the user's own pointer position and pushes to the `org-canvas:{orgId}` Broadcast channel every ~80ms.

- `frontend/src/components/organization-graph/useCanvasLayout.ts`
  - Hook that loads saved positions, exposes `setPosition(nodeType, nodeId, x, y)` which does an optimistic local update + `PATCH` to the API + Realtime notification.

- `frontend/src/components/organization-graph/useCanvasChannel.ts`
  - Hook that subscribes to the realtime channel and dispatches incoming events to the cursors, drag ghosts, and position updates.

### Modified components

- `frontend/src/app/pages/OrganizationOverviewPage.tsx`
  - Replace `<Background variant={Dots}>` with `<ReactiveDotBackground />`.
  - Add `<MultiplayerCursors />` overlay.
  - Wire `onNodeDragStart`, `onNodeDrag`, `onNodeDragStop` handlers to broadcast + persist.
  - Gate drag with `manage_teams_and_projects` check — pass `draggable` per-node.

- `frontend/src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts`
  - Consume saved positions from `teams.canvas_position_*` / `projects.canvas_position_*` when present.
  - Fall back to Fibonacci only for nodes with NULL positions — and those NULL cases should persist immediately after first render.

- `frontend/src/components/vulnerabilities-graph/VulnProjectNode.tsx`
  - Add `dragging` class hooks for scale + shadow.
  - Add "being moved by someone" glow state when remote-drag-active.

### Styling & interaction details

| Element | Spec |
|---|---|
| Dot grid base | Existing look: 16px gap, 1.2px radius, `rgba(148,163,184,0.3)` |
| Dot cursor-reactive effect | Within ~150px of cursor: radius up to 2.4px, opacity up to 0.8, gaussian falloff. Your cursor only. |
| Drag juice | Subtle per Q16: ~2–3% scale, soft shadow grow, 150ms ease on drop. Tunable during implementation. |
| Cursor | Arrow shape, constant screen-size (zoom-inverse), avatar + name label, hashed color from userId. Idle behavior TBD at implementation. |
| Ghost drag glow | Node-local pulse/glow ring, 2s fade when remote drag ends. |
| Pan/zoom | Per-user viewport. Enabled. Standard React Flow pan + zoom. |

---

## 8. User flows

### First-time admin load
1. Admin opens General tab.
2. `useCanvasLayout` fetches teams + projects with position columns.
3. Any node with NULL position gets a computed Fibonacci position AND a backend write to persist it immediately.
4. Graph renders. Dot grid mounts. Realtime channel subscribes.
5. Admin drags team A from (100, 50) to (400, 200) → optimistic local update → broadcast `node_drag_move` events throttled → on drop, PATCH persists + broadcasts `node_position_saved`.
6. All viewers with access to team A see it move in real-time. If they can see the admin's cursor, they see the cursor too. If not, they see ghost glow.

### Team member load (without drag permission)
1. Same data fetch.
2. Graph renders, all nodes have `draggable: false` (enforced client-side; backend enforces on PATCH).
3. User moves mouse → dot grid reacts around cursor → own cursor broadcast via Realtime.
4. User sees teammates' cursors interpolating smoothly; does not see cursors of org-admins outside their teams.
5. User cannot drag but sees admin-driven movement live.

### New team added after layout saved
1. Admin creates team via existing UI.
2. On next General-tab render (or via Realtime on team creation), the layout hook detects NULL position → computes Fibonacci-next-slot (or non-overlap placement) → persists immediately.
3. New team appears at that spot for everyone. Admin can drag to relocate.

### Node deletion
1. Team/project deleted via existing flow → cascade removes position columns.
2. No special handling needed.

---

## 9. Edge cases & error handling

| Case | Behavior |
|---|---|
| Two admins drag the same team concurrently | Last-writer-wins on the PATCH. Broadcast reflects most recent state. Small visual jitter acceptable. |
| Admin drags a team, loses connection mid-drag | Optimistic local update stays; on reconnect, the viewer either sends the drop position (if drag completed offline) or reverts to server state. |
| Admin drops node far off-screen | Allowed. Per-user pan will let them scroll back to find it. Consider adding a "center on this node" affordance in the team sidebar in a later phase. |
| Overlap of two nodes after drop | Allowed. Soft 2s overlap glow, no physics. Last-moved sits on top. |
| User with no teams (just member) | Sees the org canvas with zero visible teammate cursors. Dot effect works. Can't drag. |
| Rapid new-team creation (e.g., 10 in a row) | Each gets Fibonacci-next-slot. Placement can cluster — accept for v1. Admin can re-arrange. |
| Realtime channel disconnects | Graceful: cursors fade out, drag broadcasts stop. Saved positions still load from DB. Reconnect auto-resubscribes. |
| Browser doesn't support `pointermove` precision or Canvas 2D | Canvas 2D is universally supported. No fallback needed. |
| Huge org (hundreds of projects) | Canvas 2D + React Flow handles this. Cursor broadcasts scale with users online, not nodes. Monitor perf; if dot redraw hitches at zoom, switch to WebGL. |
| Team's parent position changed via drag → child projects need to follow | Handled atomically via the batch position endpoint. Broadcast as a single multi-node event. |

---

## 10. Non-functional requirements

| Category | Target |
|---|---|
| Scale | Hundreds of projects per org. ~30+ concurrent viewers on popular orgs. |
| Cursor broadcast throttle | ~80ms send rate, 60fps rendering via interpolation |
| Canvas 2D redraw budget | 60fps on 1920×1080 with ~3600 dots + up to 30 overlay cursors |
| Realtime latency | p95 < 200ms for cursor visibility |
| Drag-save latency | Optimistic local + async PATCH; don't block UI on server response |
| RBAC enforcement | Server-side on PATCH; client-side for visibility filtering |
| Browser support | Same as rest of the app — modern evergreen only |

---

## 11. RBAC requirements

### Drag (write)
- **Required permission:** `manage_teams_and_projects` (org-level)
- Enforced:
  - Client: `draggable` set per-node based on permission
  - Backend: PATCH endpoints call `requireOrgPermission('manage_teams_and_projects')`
- Future option: extract as dedicated `manage_canvas_layout` permission. Out of scope for v1.

### Cursor visibility
- **Viewers with `manage_teams_and_projects`:** See all cursors in the org.
- **Other viewers:** See cursors only of users who share at least one team with them. Org admins whose teams they're not in → hidden.
- Client-side filter at cursor render time.

### Node visibility
- Same rules as the rest of the app (existing `view_all_teams_and_projects` / team membership logic). No new rules.

### "Being moved" ghost glow
- Shown on any node visible to the viewer when the node is receiving a `node_drag_move` event, regardless of whether the dragger's cursor is visible.

---

## 12. Dependencies

### External libraries to add

- `perfect-cursors` — spline interpolation for cursor rendering (tldraw).

### Existing systems this builds on

- **Supabase Realtime** — already in use (see `OrganizationOverviewPage.tsx:705-754` for existing `project_repositories` subscription pattern).
- **React Flow (@xyflow/react)** — already rendering the graph.
- **RBAC middleware** — `requireOrgPermission` / `checkOrgAccess` (established pattern).
- **Current layout engine** (`useOrganizationVulnerabilitiesGraphLayout.ts`) — retained, now with saved-position overrides.

### Not used

- Liveblocks / Yjs — overkill given Supabase Broadcast is sufficient.
- Framer Motion on nodes — would fight React Flow's transform math. Pure CSS on `.dragging` class.

---

## 13. Success criteria

**Gut-feel only** — no analytics or KPIs in this phase. Specifically:

- The dot effect "feels right" under Henry's browser test.
- Dragging a team feels juicy without being loud.
- Two browsers open side-by-side clearly show teammate cursors and node movement.
- No jank or frame drops on a typical org graph.
- No feature flag. Ship when it's ready.

Done = all of:
- Reactive dot background replaces static one, reacts to your own cursor, pans/zooms with canvas.
- Nodes are draggable for permitted users, positions persist, NULL=spawn-and-save semantics hold.
- Team drag moves child projects rigidly.
- Multiplayer cursors render with interpolation and visibility rules.
- Ghost glow on remote-dragged nodes whose mover is invisible to you.
- Per-user pan/zoom enabled.

---

## 14. Open questions (decide during implementation)

1. **Spawn placement algorithm:** Pure Fibonacci-next-slot (simpler) vs. non-overlap scan (nicer for crowded orgs). Both acceptable. Default to Fibonacci; revisit if it looks bad.
2. **Cursor idle behavior:** Fade after N seconds (tldraw) vs. persist indefinitely (Figma). Play with both; default to "persist like Figma".
3. **Drag juice intensity:** Start at ~2–3% scale, soft shadow. Tune in browser with Henry until it feels right.
4. **Role badge in cursor label:** Try `[avatar] Name · Role` vs. `[avatar] Name`. A/B visually.
5. **Cursor shape:** Figma-arrow (familiar) vs. custom Deptex shape. Try Figma-style first.
6. **Whether to add a "being moved by someone" text label** next to the ghost glow, or just visual glow alone.
7. **Z-order on overlap:** Probably last-moved-on-top; tune if it feels wrong.

---

## 15. Scope

### In scope (this phase, shipped together)

- Replaced background: cursor-reactive Canvas 2D dot grid (your cursor only, world-locked).
- Drag-to-move for teams and projects, gated by `manage_teams_and_projects`.
- Team drag translates child projects rigidly.
- Saved positions via nullable columns + PATCH endpoints.
- Fibonacci seed on spawn, written once.
- Multiplayer cursors via Supabase Broadcast + `perfect-cursors`, with RBAC visibility filtering.
- Ghost-drag glow for invisible-cursor movers.
- Per-user pan + zoom enabled.
- Drag juice (subtle scale + shadow + spring settle).

### Out of scope (future phases)

- Team-as-container visual redesign (faded backdrop card, or table-of-projects view inside a team).
- Shared viewport / "follow a teammate" mode.
- Cursor chat / reactions / emoji.
- Audit log of node moves.
- Reset-to-auto-layout button.
- Dedicated `manage_canvas_layout` permission.
- Node movement affecting dot grid density (only your own cursor for v1).
- Mobile/touch drag gestures (desktop-first).

### Shipping

- No feature flag.
- No rollout gate.
- Ship when it works end-to-end and passes Henry's browser test.
- Implementation will follow the established iteration cadence: one visible piece at a time, browser sign-off, iterate — not a monolithic PR.
