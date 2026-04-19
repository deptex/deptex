# Org Graph Multiplayer Canvas — Implementation Plan

**Source brief:** `.cursor/plans/feature-brief-org-graph-multiplayer.md`
**Author:** Henry + Claude
**Date:** 2026-04-18
**Target surface:** `frontend/src/app/pages/OrganizationOverviewPage.tsx` — General tab graph

---

## Overview

Transform the static org overview graph into a Figma-inspired multiplayer canvas with four coordinated upgrades: (1) a Canvas 2D reactive dot background that lights up around your cursor, (2) persisted drag-to-move for teams and projects gated behind `manage_teams_and_projects`, with team drag rigidly carrying child projects, (3) live teammate cursors via Supabase Broadcast + `perfect-cursors` spline interpolation, and (4) a "being moved by someone" ghost state for remote drags whose cursor you can't see. We add nullable position columns to existing `teams` and `projects` tables (NULL = Fibonacci-seeded at spawn, then persisted once), a new dedicated route file for canvas position mutations, and a set of new frontend hooks/components under `components/organization-graph/`. Pan and zoom become per-user; nothing else about the existing page changes.

---

## Competitive Research & Design Rationale

From the interview's competitive sweep (full details in the feature brief):

- **Cursors:** Figma/tldraw/Linear all run on ~10–20 Hz wire broadcasts with client-side spline interpolation at 60fps. We'll mirror that using Supabase's **Broadcast** channel (not Presence — Presence is rate-limited to 50 msg/s on Pro and does diff-reconciliation we don't need) at an ~80ms throttle, and `perfect-cursors` (Steve Ruiz / tldraw) for interpolation. Liveblocks and Yjs were evaluated and rejected as overkill — we already have Supabase Realtime.
- **Reactive dot grid:** React Flow's `<Background variant={Dots}>` is a static SVG `<pattern>` and **cannot** be made cursor-reactive. We must replace it with a Canvas 2D layer behind React Flow, synced to `useViewport()` so dots remain anchored to world coordinates while the cursor-proximity effect works in screen space. This is why the prior attempt "just added new dots" — the structural constraint was never addressed.
- **Drag juice:** React Flow exposes `node.dragging` — the cheap, correct path is a CSS-only `.dragging` class with `transform: scale(~1.03)` + shadow grow, plus a 150ms ease on drop. Framer Motion on node wrappers fights React Flow's transform math and should be avoided.
- **Shared vs per-user layout:** Figma/Miro use shared persisted layout; Linear uses per-user. For a security dashboard that represents org structure, we land on **shared-persisted + per-user viewport**: one admin arranges, everyone sees the same map; pan/zoom is personal.
- **Team-as-container redesign:** Explicitly **deferred** — both "parent nodes" (React Flow native, has gotchas) and "faded backdrop rectangle" remain open for a future phase.

---

## Codebase Analysis

### Existing patterns we'll follow

**Backend route template** (`backend/src/routes/teams.ts:1-15`):
```typescript
import express from 'express';
import { supabase } from '../lib/supabase';
import { authenticateUser, AuthRequest } from '../middleware/auth';
const router = express.Router();
router.use(authenticateUser);
```
Supabase is a module-level singleton (`backend/src/lib/supabase.ts`), imported directly — no `req.supabase`.

**Inline RBAC pattern** (`backend/src/routes/teams.ts:308-310, 517-527`):
```typescript
const { data: orgMembership } = await supabase
  .from('organization_members').select('role')
  .eq('organization_id', orgId).eq('user_id', userId).single();
const { data: orgRole } = await supabase
  .from('organization_roles').select('permissions')
  .eq('organization_id', orgId).eq('name', orgMembership.role).single();
const hasPermission = orgRole?.permissions?.manage_teams_and_projects === true;
if (!hasPermission) return res.status(403).json({ error: '…' });
```
The codebase does **not** have a `requireOrgPermission` middleware helper — each route inlines this. We'll follow the pattern rather than introduce a new abstraction (scope creep).

**Route mounting** (`backend/src/index.ts:128-142`):
```typescript
app.use('/api/organizations', organizationsRouter);
app.use('/api/organizations', teamsRouter);
```
Multiple routers can share the same prefix. We'll mount ours at `/api/organizations`.

**Migration style** (`backend/database/phase18_epd_scoring.sql`):
```sql
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS canvas_position_x NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_y NUMERIC(12,2);
```
`ADD COLUMN IF NOT EXISTS`, `NUMERIC(precision, scale)`, no quotes on identifiers, descriptive filename (smaller features don't use phase numbers — compare `findings_status.sql`, `backfill_last_extracted_at.sql`).

**RLS reality:** `teams` and `projects` already have table-level RLS checking org membership. New nullable columns inherit these policies — **no policy changes required**. Backend service role key bypasses RLS anyway.

**Frontend permission access** (`frontend/src/app/pages/OrganizationLayout.tsx:56-111`):
```typescript
userPermissions?.manage_teams_and_projects === true
```
Available via the `OrganizationLayout` outlet context. Cached in `localStorage` at `org_permissions_${orgId}`.

**Frontend API client** (`frontend/src/lib/api.ts`):
```typescript
async patchFoo(...): Promise<...> {
  return fetchWithAuth(`/api/organizations/${orgId}/...`, {
    method: 'PATCH', body: JSON.stringify(updates),
  });
}
```

**Existing Realtime hook** (`frontend/src/hooks/useRealtimeStatus.ts:88-135`):
```typescript
const channel = supabase
  .channel(`project-repo-status-${projectId}`)
  .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: '...', filter: '...' }, handler)
  .subscribe((status) => { if (status === 'SUBSCRIBED') { … } });
return () => supabase.removeChannel(channel);
```
Only `postgres_changes` is used today — **this feature introduces the codebase's first `broadcast` usage.** Pattern: same channel API, different event type.

**ReactFlow integration** (`OrganizationOverviewPage.tsx:2168-2202`):
Currently `nodesDraggable={false}`, no `onNodeDrag*` handlers, Background is inline inside ReactFlow. Graph state uses standard `useNodesState` / `useEdgesState`. We'll flip `nodesDraggable` per-user based on permission, and add `onNodeDragStart/Drag/Stop` handlers.

**Layout hook** (`frontend/src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts:100-213`):
```typescript
const goldenAngle = Math.PI * (3 - Math.sqrt(5));
const teamRingRadius = Math.max(900, 700 + totalRingItems * 100);
ungrouped.forEach((proj) => {
  const angle = ringIdx * goldenAngle;
  ringIdx++;
  const px = centerX + Math.cos(angle) * teamRingRadius;
  // …
});
```
We'll modify this hook to: for each team/project, consume `canvas_position_x/y` if non-null, else compute Fibonacci and **schedule a persistence write** so NULL positions never persist.

**Testing:** Jest + Supertest for backend (`backend/src/routes/__tests__/teams.test.ts`), Vitest for frontend (`frontend/src/app/pages/__tests__/*.test.tsx`).

### Reusable code

- `supabase` client singleton (`backend/src/lib/supabase.ts`) — do not re-import.
- `fetchWithAuth()` from `frontend/src/lib/api.ts` — all new API methods use this.
- `checkTeamAccess()` pattern for visibility checks on read (not needed for our write paths — we check org-level perms there).
- `useOrganizationOverviewGraphLayout` — extend, don't replace.
- `VulnProjectNode` / `GroupCenterNode` — extend with new dragging/ghost state props.

### Integration points

Files modified:
- `backend/src/index.ts` — mount new router.
- `frontend/src/app/pages/OrganizationOverviewPage.tsx` — replace Background, add cursor overlay, wire drag handlers, gate `nodesDraggable`, enable pan/zoom.
- `frontend/src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts` — honor saved positions, seed NULLs.
- `frontend/src/components/vulnerabilities-graph/VulnProjectNode.tsx` — dragging + ghost visual states.
- `frontend/src/lib/api.ts` — new methods.
- `frontend/src/lib/api.ts` types: add `canvas_position_x/y` to `Team` and `Project` types.

Files created:
- `backend/database/org_canvas_positions.sql`
- `backend/src/routes/organization-canvas.ts`
- `backend/src/routes/__tests__/organization-canvas.test.ts`
- `frontend/src/components/organization-graph/ReactiveDotBackground.tsx`
- `frontend/src/components/organization-graph/MultiplayerCursors.tsx`
- `frontend/src/components/organization-graph/useCursorBroadcast.ts`
- `frontend/src/components/organization-graph/useCanvasChannel.ts`
- `frontend/src/components/organization-graph/useCanvasLayout.ts`
- `frontend/src/components/organization-graph/cursorVisibility.ts`
- `frontend/src/components/organization-graph/canvasTypes.ts`
- `frontend/src/components/organization-graph/__tests__/cursorVisibility.test.ts`

---

## Data Model

### Migration: `backend/database/org_canvas_positions.sql`

```sql
-- Add persisted canvas coordinates to teams and projects for the
-- multiplayer org overview graph. NULL = needs seeding on first render;
-- non-NULL = authoritative, never recomputed.

ALTER TABLE teams
  ADD COLUMN IF NOT EXISTS canvas_position_x NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_y NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS canvas_position_updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS canvas_position_x NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_y NUMERIC(12,2),
  ADD COLUMN IF NOT EXISTS canvas_position_updated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS canvas_position_updated_by UUID REFERENCES auth.users(id) ON DELETE SET NULL;

-- No new indexes: lookups are always by team/project id (already indexed as PK).
-- No new RLS policies: existing table-level policies already gate read/write
-- by org membership, which is sufficient for these additive columns.
```

### Semantics

- **NULL** on load → layout hook computes Fibonacci position AND fires a persistence write immediately. Next load shows stable position.
- **Non-NULL** → authoritative. Never recomputed.
- **Cascade:** when a team/project is deleted, the columns vanish with the row. No orphan cleanup needed.
- **Volume:** a column add on two tables with at most tens of thousands of rows each. O(seconds) on production. No lock concerns for reads; the ALTER acquires ACCESS EXCLUSIVE briefly, standard Postgres behavior.

### Why nullable columns, not a new table

- Tied to team/project lifetime (free cascade).
- YAGNI on multi-canvas per org.
- One less join, simpler queries, smaller diff.

---

## API Design

### New endpoints

All in `backend/src/routes/organization-canvas.ts`, mounted at `/api/organizations` in `backend/src/index.ts`.

| Method | Route | Auth | Permission | Purpose |
|---|---|---|---|---|
| `PATCH` | `/api/organizations/:orgId/canvas/teams/:teamId/position` | Bearer | `manage_teams_and_projects` | Persist a team's new (x, y). Idempotent. |
| `PATCH` | `/api/organizations/:orgId/canvas/projects/:projectId/position` | Bearer | `manage_teams_and_projects` | Persist a project's new (x, y). |
| `POST` | `/api/organizations/:orgId/canvas/positions/batch` | Bearer | `manage_teams_and_projects` | Atomic multi-node update (team drag + children). Max 200 nodes per call. |
| `POST` | `/api/organizations/:orgId/canvas/seed` | Bearer | `manage_teams_and_projects` | Accepts a map of computed Fibonacci positions for nodes currently NULL. Writes only NULL rows (no overwrites). |

### Request / response types

```typescript
// PATCH team or project position
interface UpdatePositionRequest {
  canvas_position_x: number;
  canvas_position_y: number;
}
interface UpdatePositionResponse {
  id: string;
  canvas_position_x: number;
  canvas_position_y: number;
  canvas_position_updated_at: string; // ISO
}

// POST batch
interface BatchPositionRequest {
  updates: Array<{
    type: 'team' | 'project';
    id: string;
    canvas_position_x: number;
    canvas_position_y: number;
  }>; // max 200
}
interface BatchPositionResponse {
  applied: number;
  updated_at: string;
}

// POST seed — only writes rows currently NULL
interface SeedPositionsRequest {
  teams: Record<string, { x: number; y: number }>;
  projects: Record<string, { x: number; y: number }>;
}
interface SeedPositionsResponse {
  seeded_teams: number;
  seeded_projects: number;
}
```

### Auth and permission enforcement

Every route: `authenticateUser` middleware + inline org-permission check:

```typescript
const { data: orgMembership } = await supabase
  .from('organization_members').select('role')
  .eq('organization_id', orgId).eq('user_id', userId).single();
if (!orgMembership) return res.status(403).json({ error: 'Not a member of this org' });
const { data: orgRole } = await supabase
  .from('organization_roles').select('permissions')
  .eq('organization_id', orgId).eq('name', orgMembership.role).single();
const canManage = orgMembership.role === 'owner'
  || orgMembership.role === 'admin'
  || orgRole?.permissions?.manage_teams_and_projects === true;
if (!canManage) return res.status(403).json({ error: 'Permission denied' });
```

Additional validation on write paths:
- Body validation: `canvas_position_x`, `canvas_position_y` must be finite numbers. Clamp to reasonable range (e.g., ±1,000,000) to prevent abuse.
- Batch size: reject `updates.length > 200` with 400.
- For team/project ownership: verify the target team/project `organization_id` matches `:orgId` before update. Prevents cross-org writes.

### Seed endpoint (key detail)

`POST /seed` exists to let the frontend persist Fibonacci-computed fallback positions without overwriting user-placed ones. Under the hood:
```sql
UPDATE teams
SET canvas_position_x = $1, canvas_position_y = $2,
    canvas_position_updated_at = NOW()
WHERE id = $3 AND organization_id = $4
  AND canvas_position_x IS NULL AND canvas_position_y IS NULL;
```
The `IS NULL` guard is the idempotency trick — concurrent seeds and user drags can't collide.

### Realtime channel

- **Channel name:** `org-canvas:{orgId}`
- **Transport:** Supabase Realtime **Broadcast** (`channel.on('broadcast', { event: … }, handler)`).
- **Access control:** All org members can subscribe; payloads are filtered client-side by RBAC (cursor visibility) and by node visibility (which the server already enforces via the rest of the app — if you can't see a team, you don't receive its updates for the same reason).
- **Client throttle:** ~80ms for `cursor_move`, ~50ms during active drag for `node_drag_move` (drag events are inherently rate-limited by user input + React Flow).

### Broadcast event payloads

```typescript
// frontend/src/components/organization-graph/canvasTypes.ts
export type CanvasBroadcastEvent =
  | { event: 'cursor_move'; userId: string; name: string; avatarUrl: string | null;
      colorSeed: string; x: number; y: number }
  | { event: 'cursor_leave'; userId: string }
  | { event: 'node_drag_start'; userId: string; nodeType: 'team' | 'project'; nodeId: string }
  | { event: 'node_drag_move'; userId: string; nodeType: 'team' | 'project'; nodeId: string;
      x: number; y: number; childUpdates?: Array<{ id: string; x: number; y: number }> }
  | { event: 'node_drag_end'; userId: string; nodeType: 'team' | 'project'; nodeId: string;
      x: number; y: number }
  | { event: 'position_saved'; nodeType: 'team' | 'project'; nodeId: string;
      x: number; y: number };
```

`cursor_move` payload intentionally carries `name`/`avatarUrl` so receivers don't need a separate user lookup. `colorSeed` is the userId (deterministic hash client-side).

### Visibility filtering (client-side)

Two independent axes:

**Cursor visibility:** viewer sees cursor of broadcaster U iff
- Viewer has `manage_teams_and_projects`, OR
- U shares at least one team with viewer.

Implemented in `cursorVisibility.ts`:
```typescript
function canSeeCursor(
  viewer: { hasManagePermission: boolean; teamMemberUserIds: Set<string> },
  broadcasterUserId: string,
): boolean {
  if (viewer.hasManagePermission) return true;
  return viewer.teamMemberUserIds.has(broadcasterUserId);
}
```
`teamMemberUserIds` is computed once at page-load from the existing team-with-members data already fetched by the overview page.

**Node visibility:** existing app RBAC — if the viewer's team/project list doesn't include a node, they don't render it, so `node_drag_*` events for invisible nodes are simply ignored client-side.

**Ghost glow trigger:** node drag event received for a visible node, AND the dragger's cursor is NOT visible to the viewer → set `isBeingRemotelyDragged: true` with `remoteCursorVisible: false` on that node. Node component renders the glow.

---

## Frontend Design

### Pages & Routes

No new routes. Feature lives entirely inside the existing General tab of the Organization Overview page (`OrganizationOverviewPage.tsx` under the `/organizations/:id` route).

### Component tree (additions only)

```
OrganizationOverviewPage
├── (existing layout/sidebars/etc.)
└── <ReactFlow>
    ├── <ReactiveDotBackground />          ← NEW (replaces Background)
    ├── (existing nodes + edges)
    └── <MultiplayerCursors />             ← NEW (absolute overlay)
        └── <RemoteCursor /> × N
```

Hook wiring inside `OrganizationOverviewPage`:
```
useCanvasLayout(orgId)          // loads saved positions, exposes setPosition()
useCanvasChannel(orgId)         // subscribes to org-canvas:{orgId}, exposes remote state
useCursorBroadcast(orgId, user) // broadcasts local cursor, throttled
```

### New components — specs

#### `ReactiveDotBackground.tsx`

- Mounted **inside** `<ReactFlow>` in place of `<Background>`, so React Flow renders it behind nodes.
- Uses `useViewport()` from `@xyflow/react` to read `{ x, y, zoom }`.
- Renders a full-size `<canvas>` absolutely positioned within the flow container.
- On every `pointermove` inside the flow pane (ref to `.react-flow__pane`), captures `clientX/clientY` relative to canvas.
- Redraws on `requestAnimationFrame` when cursor moves OR viewport changes.
- Drawing:
  - Base grid: gap = 16px (world units), scaled by zoom
  - For each dot: compute screen position via viewport transform; compute distance to cursor (screen space); `radius = 1.2 + 1.2 * exp(-dist² / (2 * 90²))`, `alpha = 0.3 + 0.5 * exp(-dist² / (2 * 120²))` (gaussian falloff).
  - Draw with `ctx.arc` + `ctx.fill`. Batched by globalAlpha segments for perf.
- Props: `gap?: number` (default 16), `baseSize?: number` (default 1.2), `color?: string` (default `"148, 163, 184"`).

Perf target: <3ms per redraw at 1920×1080 (~8000 dots). Canvas 2D on Chrome/Firefox/Safari modern versions.

#### `MultiplayerCursors.tsx`

- Absolute overlay at z-index above React Flow nodes.
- Receives list of visible remote cursors from `useCanvasChannel`.
- For each cursor: renders `<RemoteCursor>` which uses `usePerfectCursor` hook for interpolation.
- Cursor DOM: Figma-style arrow SVG + name label `[avatar] Name`. Constant screen-pixel size (does NOT scale with zoom — wraps outside the zoom transform).
- Position: cursor world coords → screen coords via `useViewport()` transform (so when canvas pans, cursors track with their world point).
- Idle behavior (per open question): persist indefinitely for v1; make the fade duration a constant we tune in browser.

Subcomponent:
```typescript
function RemoteCursor({ cursor }: { cursor: RemoteCursorState }) {
  const ref = useRef<HTMLDivElement>(null);
  const setPoint = usePerfectCursor(([x, y]) => {
    if (ref.current) ref.current.style.transform = `translate(${x}px, ${y}px)`;
  });
  useLayoutEffect(() => { setPoint([cursor.screenX, cursor.screenY]); }, [cursor.screenX, cursor.screenY]);
  return <div ref={ref} className="pointer-events-none absolute top-0 left-0">…</div>;
}
```

#### `useCursorBroadcast.ts`

- Throttles the user's own pointer position (in **world** coordinates — convert from screen using `useViewport()`).
- Sends `cursor_move` broadcast every ~80ms if the pointer has actually moved.
- Sends `cursor_leave` on pointer leaving the flow pane.
- Does NOT send if the user has no org membership (degenerate case).

#### `useCanvasChannel.ts`

- Subscribes to `org-canvas:{orgId}` channel.
- Maintains:
  - `remoteCursors: Map<userId, RemoteCursorState>` (filtered by `cursorVisibility`).
  - `remoteDragging: Map<nodeId, { userId; position; cursorVisible: boolean }>` (for ghost glow + optimistic remote position).
  - `lastSavedPositions: Map<nodeId, {x, y}>` (reconciliation target on `position_saved`).
- Cleans up on unmount (`supabase.removeChannel`).
- Applies drag move events to `graphNodes` optimistically — viewers see remote moves in real-time before DB persistence.

#### `useCanvasLayout.ts`

- Reads saved positions from `teams` and `projects` data already loaded by the overview page (no new fetch — they come in the existing GETs once we extend the types).
- Returns `setPosition(nodeType, nodeId, x, y)` which:
  1. Updates local graph state immediately (optimistic).
  2. Broadcasts `node_drag_end` (or batch for team+children).
  3. PATCHes the API. On success → broadcasts `position_saved`. On failure → reverts local state + toast.
- Provides `seedMissingPositions(nodesWithNullPositions)` which POSTs `/canvas/seed` once after the Fibonacci fallback runs.

#### `cursorVisibility.ts`

Pure function helpers + TypeScript types. Exports `canSeeCursor()` and helpers to compute `teamMemberUserIds` from the existing `teamsWithProjects` data structure. Tested as a pure function via Vitest (no component / realtime mocks needed).

#### `canvasTypes.ts`

Shared types (`CanvasBroadcastEvent`, `RemoteCursorState`, `CanvasPosition`, etc.).

### Modifications to existing components

#### `OrganizationOverviewPage.tsx`

1. Extract user permission for `manage_teams_and_projects` from `useOutletContext<OrganizationContextType>` / existing permission source. (Find the existing pattern — this page already consumes org permissions elsewhere; reuse that.)
2. Replace:
   ```tsx
   <Background variant={BackgroundVariant.Dots} gap={16} size={1.2} color="rgba(148,163,184,0.3)" />
   ```
   with:
   ```tsx
   <ReactiveDotBackground />
   ```
3. Flip:
   ```tsx
   nodesDraggable={false}   // → nodesDraggable={hasManagePermission}
   ```
   AND enable pan/zoom (currently effectively locked via `fitView` + `nodesDraggable={false}`):
   ```tsx
   panOnDrag={true}
   zoomOnScroll={true}
   zoomOnPinch={true}
   panOnScroll={false}
   ```
4. Add drag handlers:
   ```tsx
   onNodeDragStart={handleNodeDragStart}
   onNodeDrag={handleNodeDrag}       // broadcasts throttled node_drag_move
   onNodeDragStop={handleNodeDragStop} // persists via setPosition
   ```
5. Per-node `draggable` override: the org center node must have `draggable: false` always. The layout hook sets this.
6. Mount `<MultiplayerCursors />` as sibling of `<ReactFlow>` (absolute overlay).
7. Wire `useCanvasChannel` + `useCursorBroadcast` + `useCanvasLayout`.

#### `useOrganizationVulnerabilitiesGraphLayout.ts`

- Accept two new inputs: a `positionOverrides: Record<nodeId, {x, y}>` map and a `nodeIdsMissingPositions: Set<string>` output callback.
- For each team / project: if override present, use it; else compute Fibonacci as today.
- Return `missingPositions: { teams: Record<id, {x,y}>; projects: Record<id, {x,y}> }` so the page can seed them via `/canvas/seed`.
- Keep the `goldenAngle` computation exactly as-is — we only change how the result is consumed.

**Stability guarantee for the "always save the Fibonacci seed" rule:** because seeds are persisted immediately after first render, subsequent loads use `positionOverrides` for everyone — the index-based Fibonacci is effectively deprecated for existing nodes. New teams/projects added later get Fibonacci based on the *current* total count, and that result is persisted immediately.

#### `VulnProjectNode.tsx`

Add two new data props:
```typescript
interface VulnProjectNodeData {
  // …existing…
  isBeingRemotelyDragged?: boolean;
  remoteCursorVisible?: boolean;  // true = normal multiplayer, false = ghost glow
}
```

In the `isOverviewTeamCard` / `isOverviewProjectCard` render paths, add a conditional class:
```tsx
<div className={cn(
  "existing-classes-here",
  "transition-[transform,box-shadow] duration-150",
  isBeingRemotelyDragged && !remoteCursorVisible && "ring-2 ring-primary/40 shadow-lg animate-pulse",
)}>
```

React Flow already adds a `selected` / `dragging` class on the wrapper — we can hook CSS into that via a stylesheet:
```css
/* in OrganizationOverviewPage or a css file — keeping it scoped */
.react-flow__node.dragging > div {
  transform: scale(1.03);
  box-shadow: 0 12px 24px -8px rgba(0,0,0,0.35);
  transition: transform 80ms ease-out, box-shadow 80ms ease-out;
}
.react-flow__node:not(.dragging) > div {
  transition: transform 150ms cubic-bezier(0.34, 1.56, 0.64, 1), box-shadow 150ms ease-out;
}
```

#### `GroupCenterNode.tsx`

No functional change. Just ensure it's always rendered with `draggable: false` in the layout hook (already is in spirit, but the new `nodesDraggable={true}` default would enable it — must opt out explicitly at the node level).

### Design specifications (per frontend-design skill)

- **Cursor arrow:** 16×16 SVG arrow, fill = per-user color. Name label below: `bg-background-card border border-border rounded-md px-2 py-0.5 text-xs font-medium`. Avatar: 14×14 rounded full, left of name.
- **Per-user color palette:** 12 distinct swatches from our theme — mix of `primary`, `info`, `warning`, `destructive` tones with off-primary variants. Hash userId → palette index.
- **Dragging state:** 3% scale, 12px shadow drop. Spring settle on release (150ms `cubic-bezier(0.34, 1.56, 0.64, 1)` — gentle overshoot).
- **Ghost glow:** `ring-2 ring-primary/40 shadow-lg animate-pulse` on the node card for 2s, then fade.
- **Overlap glow:** if drop position overlaps another node by more than 30% bbox: brief `ring-2 ring-warning/50` 2s fade on both nodes. Advisory only, never prevents drop.
- **Reactive dot color:** base `rgba(148, 163, 184, 0.3)` (matches today). Max reactive alpha ~0.8. Radius 1.2 → 2.4 at cursor center.

All of the above follows the frontend-design skill's preference for **solid backgrounds, subtle borders, sparing use of brand color** — no glow decorations on non-interactive surfaces.

---

## Implementation Tasks

Tasks are ordered so each produces something browser-verifiable. This matches the user's established cadence: ship one visible piece, sign off, iterate.

### Milestone 1 — Saved positions foundation (S)

**1.1** Create migration `backend/database/org_canvas_positions.sql` with the SQL above. Apply to dev DB.
- Acceptance: `\d teams` and `\d projects` show new columns.

**1.2** Extend backend types returned by `GET /api/organizations/:orgId/teams` and `/projects` to include `canvas_position_x/y`. Grep for the response shape in `backend/src/routes/teams.ts` and `projects.ts` — likely just `.select('*')`, so this is free. Confirm in the payload.
- Acceptance: curl returns the new fields.

**1.3** Extend frontend `Team` and `Project` types in `frontend/src/lib/api.ts` to include `canvas_position_x: number | null` and `canvas_position_y: number | null`.
- Acceptance: TypeScript compiles.

**1.4** Modify `useOrganizationVulnerabilitiesGraphLayout.ts` to consume saved positions when present. Return `missingPositions` for the page to seed.
- Acceptance: no visible change yet.

Files touched: `backend/database/org_canvas_positions.sql` (new), `frontend/src/lib/api.ts`, `frontend/src/components/vulnerabilities-graph/useOrganizationVulnerabilitiesGraphLayout.ts`.

### Milestone 2 — Position write API + seed (M)

**2.1** Create `backend/src/routes/organization-canvas.ts`:
- Implement `PATCH /:orgId/canvas/teams/:teamId/position`
- Implement `PATCH /:orgId/canvas/projects/:projectId/position`
- Implement `POST /:orgId/canvas/positions/batch`
- Implement `POST /:orgId/canvas/seed` (NULL-guarded update)
- Inline permission check following the teams.ts pattern.
- Validation: x/y are finite numbers, clamped to ±1,000,000; batch ≤ 200.

**2.2** Mount router in `backend/src/index.ts` under `/api/organizations`.

**2.3** Add frontend API methods to `frontend/src/lib/api.ts`:
- `api.updateTeamCanvasPosition(orgId, teamId, {x, y})`
- `api.updateProjectCanvasPosition(orgId, projectId, {x, y})`
- `api.batchUpdateCanvasPositions(orgId, updates)`
- `api.seedCanvasPositions(orgId, { teams, projects })`

**2.4** Wire seed call: after first render on the overview page, if `missingPositions` is non-empty and user has `manage_teams_and_projects`, call `api.seedCanvasPositions`. Only admins seed — otherwise first admin's visit writes them.

Files touched: `backend/src/routes/organization-canvas.ts` (new), `backend/src/index.ts`, `frontend/src/lib/api.ts`, `frontend/src/app/pages/OrganizationOverviewPage.tsx`.

Acceptance: first admin load on a fresh org writes Fibonacci seeds to DB. Reload shows same positions (read from DB, not recomputed).

### Milestone 3 — Drag to move (single user) (M)

**3.1** Add permission check in `OrganizationOverviewPage`. Extract the user's org-level permissions (follow the existing pattern in `OrganizationLayout.tsx`).

**3.2** Set `nodesDraggable={hasManagePermission}` on `<ReactFlow>`. Set `draggable: false` explicitly on the org center node in the layout hook (prevents accidental drag even for admins).

**3.3** Enable pan/zoom: `panOnDrag, zoomOnScroll, zoomOnPinch`.

**3.4** Implement `useCanvasLayout` hook. On node drag stop, call the relevant PATCH. Optimistic local update + rollback on error (toast).

**3.5** Wire `onNodeDragStop` in `OrganizationOverviewPage` to `useCanvasLayout.setPosition`.

Acceptance: admin drags a team, releases, reloads — team is still there. Member account sees nodes but can't drag.

Files touched: `OrganizationOverviewPage.tsx`, new `useCanvasLayout.ts`.

### Milestone 4 — Team drag carries children (S)

**4.1** In `onNodeDragStart`, if the dragged node is a team, record the start positions of its child projects in a ref.

**4.2** In `onNodeDrag`, if the dragged node is a team, compute delta and apply to child projects via `setGraphNodes`. React Flow re-renders immediately.

**4.3** In `onNodeDragStop`, if the dragged node is a team, send the batch endpoint with the team + all child new positions.

Acceptance: drag a team → its projects translate rigidly together; positions all persist.

Files touched: `OrganizationOverviewPage.tsx`, `useCanvasLayout.ts`.

### Milestone 5 — Drag juice (S)

**5.1** Add the CSS from the Design Specs section to a new stylesheet (or inline via CSS module). Scope to `.react-flow__node.dragging > div` and `.react-flow__node:not(.dragging) > div` so only overview-page nodes get it (can scope via a wrapper class on the flow).

**5.2** Verify in-browser that scale + shadow feels right. Tune values to ~2–5% with Henry in session.

Acceptance: grabbing a node "lifts", releasing it settles.

Files touched: overview page CSS.

### Milestone 6 — Reactive dot background (M)

**6.1** Create `ReactiveDotBackground.tsx` per the spec above. Canvas 2D, `useViewport()` sync, gaussian falloff around cursor.

**6.2** Remove the existing `<Background>` and mount `<ReactiveDotBackground />` in its place.

**6.3** Browser-verify that dots follow pan/zoom (world-locked) and react to your cursor (screen-space proximity). Check perf in DevTools Performance panel — must stay under 8ms per frame at 60fps.

Acceptance: page looks the same at rest; dots light up smoothly near the cursor; pan drags dots with the canvas; zoom scales them.

Files touched: new component, `OrganizationOverviewPage.tsx`.

### Milestone 7 — Multiplayer cursors (M)

**7.1** `npm install perfect-cursors` in `frontend/`.

**7.2** Create `canvasTypes.ts`, `cursorVisibility.ts` with unit tests.

**7.3** Create `useCursorBroadcast.ts`: throttle own pointer broadcasts at ~80ms, send `cursor_move` with world coords + user identity payload.

**7.4** Create `useCanvasChannel.ts`: subscribe to `org-canvas:{orgId}`, maintain `remoteCursors` map with visibility filter applied.

**7.5** Create `MultiplayerCursors.tsx` overlay with `<RemoteCursor>` children using `usePerfectCursor`.

**7.6** Wire hooks into `OrganizationOverviewPage`. Mount `<MultiplayerCursors />` as absolute sibling of `<ReactFlow>`.

**7.7** Browser test with two sessions (two profiles or two browsers): confirm cursors interpolate smoothly, labels show correctly, visibility filter works (log viewer without `manage_teams_and_projects` can only see teammate cursors).

Acceptance: two browsers side-by-side show each other's cursors gliding smoothly.

Files touched: new components + hooks; `OrganizationOverviewPage.tsx`.

### Milestone 8 — Remote drag + ghost glow (S–M)

**8.1** Extend `useCanvasChannel` to receive `node_drag_start`, `node_drag_move`, `node_drag_end`, `position_saved`. Apply `node_drag_move` positions to local graph state optimistically for all viewers who can see the node.

**8.2** When a remote drag is in progress but the dragger's cursor is NOT visible to the viewer, set `isBeingRemotelyDragged: true` + `remoteCursorVisible: false` on the node data.

**8.3** Extend `VulnProjectNode.tsx` to render the ghost glow when those flags are set. 2s fade on `node_drag_end` if glow was shown.

**8.4** Extend `useCanvasLayout.setPosition` to also broadcast `node_drag_start/move/end` during local drags.

Acceptance: one browser drags as admin, the other watches the node move live (with cursor if visible, ghost glow if not).

Files touched: `useCanvasChannel.ts`, `VulnProjectNode.tsx`, `OrganizationOverviewPage.tsx`.

### Milestone 9 — Testing & polish (M)

**9.1** Backend tests in `backend/src/routes/__tests__/organization-canvas.test.ts` (Jest + Supertest, following the `teams.test.ts` pattern):
- 403 for non-admin user on PATCH
- 403 for admin of a different org on PATCH (cross-org protection)
- 400 for batch > 200
- 400 for non-finite x/y
- 200 for admin with valid payload → row updated
- Seed endpoint: only writes NULL rows; non-NULL rows untouched.

**9.2** Frontend unit tests in `cursorVisibility.test.ts` (Vitest):
- `canSeeCursor` with `hasManagePermission: true` returns true regardless.
- Without permission: returns true only if broadcaster in teammate set.
- Edge cases: empty team membership, broadcaster is self.

**9.3** Browser E2E check (manual, per user preference):
- Fresh org: Fibonacci seeds on first admin load.
- Drag a team: children follow, reload shows persistence.
- Overlap drop: allowed, advisory glow only.
- Two sessions: cursors + remote drag visible per RBAC rules.
- Member account: can view, can't drag, dots still react.
- 30+ node org: no jank on drag or cursor motion.

**9.4** Perf verification:
- Background redraw < 5ms with cursor moving.
- Cursor broadcast ≤ 20 msg/s per user.
- Initial page load unchanged (seed happens after first paint).

**9.5** Register migration run in deploy notes.

Files touched: tests; docs.

---

## Testing & Validation Strategy

### Backend (Jest + Supertest)

Test file: `backend/src/routes/__tests__/organization-canvas.test.ts`

Coverage:
- **Auth:** 401 without Bearer; 403 without `manage_teams_and_projects`; 403 across orgs.
- **Validation:** non-finite x/y → 400; batch > 200 → 400; missing fields → 400.
- **Happy paths:** PATCH team, PATCH project, batch (mixed team + project), seed.
- **Seed idempotency:** calling seed twice with same payload → second call seeds 0 rows (NULL guard).
- **Seed non-overwrite:** pre-populate position, seed attempts to write → row untouched.
- Mock Supabase via the existing `test/mocks/supabaseSingleton` pattern used in `teams.test.ts`.

Perf target: all endpoints p95 < 80ms (simple single-row update).

### Frontend (Vitest + manual browser)

Unit tests:
- `cursorVisibility.test.ts` — pure function, full branch coverage.
- Optional: `useCanvasLayout.test.ts` if feasible with hooks testing library — cover optimistic update + revert on error.

Manual browser test plan:
1. Admin fresh-org flow: seeds persist, reload stable.
2. Admin drag team: children follow, persists, visible in DB.
3. Member observer: can't drag, cursor + dot reactivity works.
4. Two-session multiplayer: cursor visibility filter verified (admin sees all, member sees teammate-only).
5. Ghost glow: admin on team outside member's access drags a team member CAN see — member sees glow, no cursor.
6. Pan/zoom: own view, doesn't affect others.
7. Realtime disconnect + reconnect: cursors vanish/reappear cleanly.
8. Large org (stress): create 50+ teams/projects — verify no jank.

### Integration

- End-to-end: admin drags node → row updated in Supabase → second browser session receives realtime event → node moves in second session within 200ms.
- Confirm the Supabase channel cleans up on navigation away (no leaked subscriptions via DevTools → Network → WS).

### Regression surface

The most likely regression is the replacement of `<Background>`. Verify:
- Skeleton state still renders correctly (uses `skeletonNodeTypes`, doesn't touch Background).
- Other pages that use `<Background>` (check via grep for `BackgroundVariant`) are unaffected — our replacement is scoped to overview page only.

---

## Risks & Open Questions

### Risks

- **Canvas 2D perf on low-end devices:** At 4K/zoomed-in, dot count could spike. Mitigation: cap the dot count with a max-density clamp, or fall back to the static SVG Background on `navigator.hardwareConcurrency <= 2`. Decide during browser testing.
- **Realtime channel scale:** Each org member subscribing adds a channel subscriber. Supabase Realtime supports thousands per project — unlikely to be a bottleneck, but monitor.
- **Concurrent drag races:** two admins dragging the same team simultaneously → last-writer-wins. Visual jitter possible. Acceptable for v1; would need CRDT-like merge for true conflict resolution (overkill).
- **Fibonacci seed race on first load:** two admins hit the overview at once — both compute identical Fibonacci, both call seed, but the NULL-guard in the SQL ensures only the first write lands. No issue.
- **`perfect-cursors` is ~5 years old, unmaintained:** actively used by tldraw, stable API. Small surface area (one class), we could vendor it if the dep disappears.
- **RLS enforcement for direct Supabase subscribe:** Broadcast doesn't pass through RLS — anyone authenticated can technically subscribe to any `org-canvas:*` channel. Mitigation: our cursor visibility filter is client-side; positions only persist via the auth-gated backend PATCH. Worst case: a hostile client sees cursor coordinates they shouldn't — these are low-sensitivity mouse positions, not org data. Acceptable.

### Open questions (decide during implementation)

1. **Cursor idle behavior** — persist vs fade. Default to persist (Figma-style). Revisit after browser test.
2. **Drag juice intensity** — exact scale %, shadow, easing. Tune live.
3. **Role badge in cursor label** — `Name` vs `Name · Role`. A/B live.
4. **Cursor shape** — Figma arrow vs custom. Start with Figma arrow.
5. **Overlap glow timing** — 2s vs shorter. Tune live.
6. **Where to get `manage_teams_and_projects` on the overview page** — follow the existing `OrganizationLayout.tsx` pattern; it already populates this. Trace the data path during Milestone 3 and reuse.
7. **Z-order on overlap** — last-moved on top; confirm it reads well.
8. **Spawn placement algorithm** — pure Fibonacci-next-slot (chosen default) vs non-overlap scan (maybe later). Ship Fibonacci; revisit if crowded orgs look bad.

---

## Dependencies

### NPM

New dependency in `frontend/`:
- `perfect-cursors` (~3KB, MIT, by Steve Ruiz / tldraw)

### Internal systems

- **Supabase Realtime (Broadcast)** — already in infra, first use of Broadcast (postgres_changes is the only type used today).
- **RBAC (`manage_teams_and_projects`)** — existing.
- **`fetchWithAuth()` API client** — existing.
- **React Flow `useViewport()`** — already a dep, not yet used here.
- **Existing layout hook** — extended, not replaced.
- **`OrganizationLayout` permission loading pattern** — reused.

---

## Success Criteria

Gut-feel only, per the brief. Done when all of the following hold in a 2-browser side-by-side session:

1. Admin loading a fresh org triggers Fibonacci seed that persists — reload shows the same arrangement.
2. Dragging a team node moves its child projects rigidly; release saves; reload preserves.
3. Dragging a project alone moves only that project.
4. Background dots animate smoothly around your own cursor; do not react to other cursors (v1 scope).
5. Dots pan/zoom with the canvas (world-locked).
6. Members see the page, cannot drag, cursor + dot reactivity work normally for them.
7. Two sessions visible to each other: cursors interpolate smoothly with avatar+name.
8. Cursor visibility RBAC: non-admin member does NOT see cursor of an admin outside their teams.
9. When the above admin drags a team the member CAN see, the member sees node motion with a ghost glow (no cursor).
10. Drag feels juicy — scale + shadow on grab, spring settle on drop.
11. No jank at 50+ nodes.
12. No feature flag; shipped to prod once Henry signs off in browser.
