# Unified Flow Builder — Implementation Plan

**Source brief:** `.cursor/plans/feature-brief-unified-flow-builder.md`
**Author:** Henry + Claude
**Date:** 2026-04-19
**Target surface:** Replaces 4 code-based features (notification rules, PR check code, dependency policy code, project status code) with a unified visual flow builder.

---

## Overview

Replace four JavaScript-based customization surfaces (`organization_notification_rules.custom_code`, `organization_pr_checks.pr_check_code`, `package_policy_code`, `project_status_code`) with a single unified visual graph editor. Users build flows by connecting nodes — triggers, filters, transforms, destinations, outcomes, and a code escape hatch. All four flow types share one canvas, one node library, and one execution engine. Notification flows replace today's rule-based dispatch (preserving the existing `notification_events` event bus). PR check flows execute asynchronously via QStash and update the GitHub Check Run when complete. Policy and status flows replace the per-dep and per-project code editors. The editor is fullscreen at `/organizations/:orgId/flows/:flowId`, with multiplayer cursors and live drag (reusing the org graph multiplayer infrastructure). Settings pages become flow lists. Run history is captured per flow with full per-node execution traces, surfaced in a new Notification History page.

This is a **large feature** broken into 15 milestones. Each milestone produces something browser-verifiable. The whole feature is shipped as one cutover — all 4 flow types must work before the old code editors are deleted.

---

## Competitive Research & Design Rationale

(Full details in the feature brief. Summary here for execution.)

| Area | Inspiration | What we're building |
|---|---|---|
| Canvas UX | n8n + tldraw | @xyflow/react canvas with node palette (left), config (right). Drag-drop. |
| Node library shape | Tines (Stories of Actions) | Triggers, Filters, Transforms, Destinations, Outcomes, Actions, Code. Security-flavored. |
| Execution model | Tines per-action runs + n8n execution traces | One row per flow run + one row per node execution, fully retrievable for debugging. |
| Async PR checks | GitHub's Check Runs API | Webhook responds immediately with check `in_progress`, QStash worker evaluates, updates check to `completed`. |
| Multiplayer | Org graph multiplayer (Supabase Broadcast + perfect-cursors) | Reuse the same primitives. Channel: `flow:{flowId}`. |
| Differentiation | No SCA competitor (Snyk/Socket/Endor/Mend) has a visual flow builder. | This is the wedge. |

**Key technical decisions:**

1. **Single `flows` table with `flow_type` discriminator**, not separate tables per type. The execution engine, CRUD API, and editor are all type-aware via configuration, not branching logic. New flow types added later need only a node library + trigger registration.
2. **Node implementations as a registry** in `backend/src/lib/flows/nodes/`, one file per node type. Each exports `{ schema, validate, execute }`. New nodes are zero-touch additions to the engine.
3. **Hard cutover** (per user direction — solo pre-launch). Drop `organization_notification_rules`, `team_notification_rules`, `project_notification_rules`, `organization_pr_checks`, `package_policy_code`, `project_status_code`. Preserve `notification_events`, `notification_deliveries`, `user_notifications`, `user_notification_preferences` (still needed).
4. **Reuse @xyflow/react** (already in stack for org graph + supply chain graph). No new graph library.
5. **Reuse Supabase Broadcast + perfect-cursors** (already being added for org graph multiplayer). The flow editor channel mirrors the org canvas channel pattern.
6. **Reuse existing destination dispatchers** (`backend/src/lib/destination-dispatchers.ts`) — node implementations call into them. We are not rewriting Slack/Discord/Jira/etc. delivery code.
7. **Reuse the existing `executePolicyFunction()` sandbox** for the code escape-hatch node — same SSRF protections, same fetch limits.

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
Supabase is a module-level singleton (`backend/src/lib/supabase.ts`). No `req.supabase`.

**Inline RBAC pattern** (`backend/src/routes/teams.ts:308-310`):
```typescript
const { data: orgMembership } = await supabase
  .from('organization_members').select('role')
  .eq('organization_id', orgId).eq('user_id', userId).single();
const { data: orgRole } = await supabase
  .from('organization_roles').select('permissions')
  .eq('organization_id', orgId).eq('name', orgMembership.role).single();
const hasPermission = orgRole?.permissions?.manage_notifications === true;
if (!hasPermission) return res.status(403).json({ error: '…' });
```
No `requireOrgPermission` middleware exists. Inline the check.

**Worker endpoints with QStash signature verification** (`backend/src/routes/workers.ts:2034`):
```typescript
router.post('/dispatch-notification', verifyQStashOrInternal, async (req, res) => { … });
```
Reuse this pattern for `/execute-flow` and `/execute-pr-check-flow`.

**Migration style** (`backend/database/phase18_epd_scoring.sql`, `backend/database/org_canvas_positions.sql` once written):
- `ADD COLUMN IF NOT EXISTS`, `CREATE TABLE IF NOT EXISTS`
- Descriptive filename (no phase number for non-phase work — compare `findings_status.sql`)
- RLS policies for any new tables (read = org members, write = service role / RPC-gated)

**Notification dispatcher** (`backend/src/lib/notification-dispatcher.ts`):
- Loaded via `require()` inside route handlers (not top-level import) to avoid startup-time cycles
- Uses `notificationLog()` helper for structured JSON logging
- Calls `processDeliveries()` after creating delivery rows
- Calls `createInAppNotifications()` for in-app inbox

**Event bus** (`backend/src/lib/event-bus.ts`):
- `emitEvent({ type, organizationId, projectId?, teamId?, payload, source, priority })`
- Inserts into `notification_events`, queues `dispatch-notification` via QStash
- 17+ call sites across `routes/projects.ts`, `routes/integrations.ts`, `routes/organizations.ts`, `routes/workers.ts`, `lib/incident-engine.ts`, `routes/incidents.ts`, `routes/internal.ts`, `routes/watchtower-event.ts`. **All preserved as-is.**

**Policy engine sandbox** (`backend/src/lib/policy-engine.ts`):
- `executePolicyFunction(code, fnName, context, opts)` — battle-tested sandbox with SSRF, fetch limits, timeouts
- `runPRCheck()`, `runPackagePolicy()`, `runStatusEvaluation()` are wrappers
- The code escape-hatch node will call `executePolicyFunction` directly with a synthetic function name

**ReactFlow integration** (`frontend/src/app/pages/OrganizationOverviewPage.tsx:2168-2202`):
- `useNodesState` / `useEdgesState`
- Custom nodes via `nodeTypes` map
- `<Background>` for background grid

**Frontend API client** (`frontend/src/lib/api.ts`):
- `fetchWithAuth()` wraps every call with the JWT
- Methods grouped by feature, all return typed responses

**Existing Realtime** (`frontend/src/hooks/useRealtimeStatus.ts:88-135`):
- `supabase.channel('...').on('postgres_changes', …).subscribe()`
- Org graph multiplayer plan introduces first `broadcast` usage — flow editor will be the second use case

### Files to be deleted (hard cutover)

| File | Why |
|---|---|
| `backend/database/phase9_notifications.sql` (most of it) | Schema rewrite via migration |
| `backend/database/team_notification_rules_schema.sql` | Replaced by `flows` |
| `backend/database/project_notification_rules_schema.sql` | Replaced by `flows` |
| `backend/database/organization_notification_rules_schema.sql` | Replaced by `flows` |
| `backend/src/lib/notification-validator.ts` (mostly) | Validation moves into per-node validators; sandbox kept for code node only |
| `backend/src/lib/notification-dispatcher.ts:resolveMatchingRules()` | Replaced by flow resolution |
| `frontend/src/app/pages/NotificationRulesSection.tsx` | Replaced by flow list + editor |
| `frontend/src/app/pages/NotificationHistorySection.tsx` | Replaced by new history page (different schema) |
| `frontend/src/components/NotificationAIAssistant.tsx` | Replaced by AI flow assistant (out of scope for v1) |
| `frontend/src/components/PolicyAIAssistant.tsx` | Same |
| Most of `frontend/src/app/pages/PoliciesPage.tsx` | Replaced by per-flow-type list pages |
| `frontend/src/components/PolicyCodeEditor.tsx` | Code editor only used in code node; that uses Monaco directly |
| `frontend/src/components/PolicyDiffViewer.tsx`, `PolicyDiffCodeEditor.tsx`, `policy-monaco-setup.ts` | No longer needed at top level (still useful for code node) |

### Files to be modified

| File | Modification |
|---|---|
| `backend/src/index.ts` | Mount new `/api/flows` router |
| `backend/src/routes/workers.ts` | Add `/execute-flow`, `/execute-pr-check-flow` endpoints; redirect `/dispatch-notification` to use flows |
| `backend/src/lib/event-bus.ts` | No changes — events still emitted the same way |
| `backend/src/routes/integrations.ts` | PR webhook handler (`handlePullRequestEvent`) calls flow engine instead of inline policy code |
| `backend/src/routes/gitlab-webhooks.ts` | Same: PR check via flow |
| `backend/src/routes/bitbucket-webhooks.ts` | Same |
| `backend/src/routes/workers.ts` (extraction completion) | Status code → status flow; package policy code → policy flow |
| `frontend/src/app/routes.tsx` | Add `/organizations/:orgId/flows/:flowId` route |
| `frontend/src/app/pages/OrganizationSettingsPage.tsx` | Replace notifications section with flow list |
| `frontend/src/app/pages/PoliciesPage.tsx` | Replace with PR check flow list |
| `frontend/src/app/pages/ProjectSettingsContent.tsx` | Add Policy + Status flow lists |
| `frontend/src/lib/api.ts` | Add `flows` API methods + types |

### Files to be created (high level — full list in tasks below)

Backend:
- `backend/database/flows_schema.sql` (new tables)
- `backend/database/drop_legacy_rule_tables.sql` (cutover migration; runs after backfill if any)
- `backend/src/routes/flows.ts` (CRUD + test run + history)
- `backend/src/lib/flows/engine.ts` (executor)
- `backend/src/lib/flows/registry.ts` (node registry)
- `backend/src/lib/flows/types.ts` (shared types)
- `backend/src/lib/flows/context.ts` (context builder per trigger type)
- `backend/src/lib/flows/nodes/*.ts` (one per node type — ~30 files)
- `backend/src/routes/__tests__/flows.test.ts`
- `backend/src/lib/flows/__tests__/engine.test.ts`

Frontend:
- `frontend/src/app/pages/FlowEditorPage.tsx` (fullscreen editor)
- `frontend/src/app/pages/NotificationHistoryPage.tsx` (run history)
- `frontend/src/components/flow-editor/FlowCanvas.tsx`
- `frontend/src/components/flow-editor/NodePalette.tsx`
- `frontend/src/components/flow-editor/NodeConfigPanel.tsx`
- `frontend/src/components/flow-editor/TestRunModal.tsx`
- `frontend/src/components/flow-editor/RunInspectorDrawer.tsx`
- `frontend/src/components/flow-editor/nodes/*.tsx` (one per node type)
- `frontend/src/components/flow-editor/useFlowDraft.ts` (auto-save + version)
- `frontend/src/components/flow-editor/useFlowMultiplayer.ts` (cursors + live edits)
- `frontend/src/components/flow-editor/flowTypes.ts`
- `frontend/src/components/flow-editor/nodeRegistry.ts` (UI side — schema + colors + icons)
- `frontend/src/components/FlowList.tsx` (reusable flow list for settings pages)

---

## Data Model

### Migration 1: `backend/database/flows_schema.sql`

```sql
-- Unified flows table for notification, PR check, policy, and status flows.
-- Each row is a complete graph; execution engine walks it.

CREATE TABLE IF NOT EXISTS flows (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_type TEXT NOT NULL CHECK (flow_type IN ('notification', 'pr_check', 'policy', 'status')),
  scope TEXT NOT NULL CHECK (scope IN ('organization', 'team', 'project')),
  scope_id UUID NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  graph JSONB NOT NULL DEFAULT '{"version":1,"nodes":[],"edges":[]}'::jsonb,
  version INTEGER NOT NULL DEFAULT 1,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  dry_run BOOLEAN NOT NULL DEFAULT FALSE,
  snoozed_until TIMESTAMPTZ,
  created_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flows_org_type_active
  ON flows (organization_id, flow_type, active) WHERE active = TRUE;
CREATE INDEX IF NOT EXISTS idx_flows_scope ON flows (scope, scope_id);

ALTER TABLE flows ENABLE ROW LEVEL SECURITY;

CREATE POLICY flows_select_org_members ON flows
  FOR SELECT USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );
-- Inserts/updates/deletes go through service role from backend (auth-gated by RBAC).

-- Append-only version history. One row per save.
CREATE TABLE IF NOT EXISTS flow_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  version INTEGER NOT NULL,
  graph JSONB NOT NULL,
  name TEXT NOT NULL,
  changed_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  change_summary TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (flow_id, version)
);

CREATE INDEX IF NOT EXISTS idx_flow_versions_flow ON flow_versions (flow_id, version DESC);

ALTER TABLE flow_versions ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_versions_select_org_members ON flow_versions
  FOR SELECT USING (
    flow_id IN (
      SELECT id FROM flows WHERE organization_id IN (
        SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
      )
    )
  );

-- Per-execution record. Powers the notification history page.
CREATE TABLE IF NOT EXISTS flow_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_id UUID NOT NULL REFERENCES flows(id) ON DELETE CASCADE,
  flow_version INTEGER NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  trigger_event_id UUID REFERENCES notification_events(id) ON DELETE SET NULL,
  trigger_payload JSONB NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'skipped', 'dry_run')),
  outcome JSONB,
  error TEXT,
  duration_ms INTEGER,
  started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  completed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_flow_runs_flow_started ON flow_runs (flow_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flow_runs_org_started ON flow_runs (organization_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_flow_runs_trigger_event ON flow_runs (trigger_event_id) WHERE trigger_event_id IS NOT NULL;

ALTER TABLE flow_runs ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_runs_select_org_members ON flow_runs
  FOR SELECT USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

-- Per-node execution trace. Click a run, see which nodes fired and what flowed through.
CREATE TABLE IF NOT EXISTS flow_node_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  flow_run_id UUID NOT NULL REFERENCES flow_runs(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL,
  node_type TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('success', 'failed', 'skipped')),
  input JSONB,
  output JSONB,
  error TEXT,
  duration_ms INTEGER,
  executed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_flow_node_executions_run ON flow_node_executions (flow_run_id, executed_at);

ALTER TABLE flow_node_executions ENABLE ROW LEVEL SECURITY;
CREATE POLICY flow_node_executions_select_org_members ON flow_node_executions
  FOR SELECT USING (
    flow_run_id IN (
      SELECT id FROM flow_runs WHERE organization_id IN (
        SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
      )
    )
  );
```

### Migration 2: `backend/database/drop_legacy_rule_tables.sql` (run AFTER cutover deploy)

```sql
-- Hard cutover: solo user pre-launch, no migration of existing JS rules.
-- Run after the new flow system is verified in browser.

DROP TABLE IF EXISTS organization_notification_rules CASCADE;
DROP TABLE IF EXISTS team_notification_rules CASCADE;
DROP TABLE IF EXISTS project_notification_rules CASCADE;
DROP TABLE IF EXISTS notification_rule_changes CASCADE;
DROP TABLE IF EXISTS organization_pr_checks CASCADE;
-- package_policy_code, project_status_code: drop these columns from `projects` table
-- (they're not their own tables, but columns)
ALTER TABLE projects DROP COLUMN IF EXISTS effective_pr_check_code;
ALTER TABLE projects DROP COLUMN IF EXISTS effective_package_policy_code;
ALTER TABLE projects DROP COLUMN IF EXISTS effective_status_code;
ALTER TABLE projects DROP COLUMN IF EXISTS package_policy_code;
ALTER TABLE projects DROP COLUMN IF EXISTS status_code;
-- (verify exact column names against current schema before applying)
```

### Tables we KEEP unchanged

| Table | Reason |
|---|---|
| `notification_events` | Still the input to the notification flow trigger |
| `notification_deliveries` | Still tracks per-destination delivery; flow nodes write here |
| `user_notifications` | In-app inbox unchanged |
| `user_notification_preferences` | DND, mute, opt-out preferences still apply |
| `project_pr_guardrails` | Legacy guardrails — keep as fallback, document as deprecated; PR check flows can supersede them |
| `organization_integrations` / `team_integrations` / `project_integrations` | All destination connections live here |

### Graph JSON shape

Stored in `flows.graph` and `flow_versions.graph`:

```jsonc
{
  "version": 1,
  "nodes": [
    {
      "id": "n_trigger",
      "type": "trigger.event",
      "position": { "x": 100, "y": 100 },
      "config": { "event_types": ["vulnerability_discovered"] }
    },
    {
      "id": "n_filter",
      "type": "filter.condition",
      "position": { "x": 350, "y": 100 },
      "config": {
        "match": "all",
        "rules": [
          { "field": "vulnerability.severity", "op": "in", "value": ["critical", "high"] },
          { "field": "vulnerability.reachability", "op": "eq", "value": "confirmed" }
        ]
      }
    },
    {
      "id": "n_slack",
      "type": "destination.slack",
      "position": { "x": 600, "y": 100 },
      "config": {
        "integration_id": "...",
        "channel_id": "...",
        "title": "{{vulnerability.cve_id}} in {{project.name}}",
        "body": "Severity: {{vulnerability.severity}}\\nDepscore: {{vulnerability.depscore}}"
      }
    }
  ],
  "edges": [
    { "id": "e1", "source": "n_trigger", "sourceHandle": "out", "target": "n_filter", "targetHandle": "in" },
    { "id": "e2", "source": "n_filter", "sourceHandle": "true", "target": "n_slack", "targetHandle": "in" }
  ]
}
```

Templates use `{{ field.path }}` Handlebars-style. Backend renderer uses an existing or vendored Handlebars implementation (lightweight; ~10 KB).

---

## API Design

### New endpoints — all in `backend/src/routes/flows.ts`, mounted at `/api/flows`

| Method | Route | Auth | Permission | Purpose |
|---|---|---|---|---|
| `GET` | `/api/flows` | Bearer | Org member | List flows (filter by `?organization_id=&scope=&scope_id=&type=`) |
| `GET` | `/api/flows/:id` | Bearer | Org member | Get one flow with current graph |
| `POST` | `/api/flows` | Bearer | `manage_notifications` (notification) or `manage_policies` (other types) | Create new flow with blank graph |
| `PUT` | `/api/flows/:id` | Bearer | Same as create per type | Update flow (creates a `flow_versions` row, increments `version`) |
| `DELETE` | `/api/flows/:id` | Bearer | Same as create per type | Hard delete |
| `PATCH` | `/api/flows/:id/snooze` | Bearer | Same | Body: `{ snoozed_until: ISO \| null }` |
| `PATCH` | `/api/flows/:id/active` | Bearer | Same | Body: `{ active: boolean }` |
| `PATCH` | `/api/flows/:id/dry_run` | Bearer | Same | Body: `{ dry_run: boolean }` |
| `GET` | `/api/flows/:id/versions` | Bearer | Org member | List previous versions |
| `POST` | `/api/flows/:id/revert/:version` | Bearer | Same as edit | Restore old version (creates new version row, doesn't rewrite history) |
| `POST` | `/api/flows/:id/test_run` | Bearer | Org member | Body: `{ event_id?, mock_payload? }` → returns `{ status, node_executions, outcome }` without dispatching for real |
| `GET` | `/api/flows/:id/recent_events` | Bearer | Org member | List recent `notification_events` matching this flow's trigger type, for the test-run sample picker |
| `GET` | `/api/flow-runs` | Bearer | Org member | Paginated history (`?organization_id=&flow_id=&status=&from=&to=&limit=50`) |
| `GET` | `/api/flow-runs/:id` | Bearer | Org member | Single run with all `flow_node_executions` |

### New worker endpoints in `backend/src/routes/workers.ts`

| Method | Route | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/workers/execute-flow` | QStash signed | Body: `{ flow_id, trigger_event_id?, trigger_payload }`. Loads flow, walks graph, records run + node executions. |
| `POST` | `/api/workers/execute-pr-check-flow` | QStash signed | Body: `{ flow_id, pr_payload, check_run_context }`. Same as `/execute-flow` but ends by updating GitHub/GitLab/Bitbucket check status. |

### Rewired endpoint

- `POST /api/workers/dispatch-notification` (existing) — reimplemented to:
  1. Load the event (existing).
  2. Find all matching notification flows (via `resolveMatchingFlows()` — replaces `resolveMatchingRules()`).
  3. For each flow, queue `POST /api/workers/execute-flow` via QStash with the event payload.
  4. Mark event as `dispatched` once all flows queued.

This way QStash retry semantics and rate limits stay isolated per-flow.

### Request / response types (TypeScript)

```typescript
// Shared
type FlowType = 'notification' | 'pr_check' | 'policy' | 'status';
type FlowScope = 'organization' | 'team' | 'project';

interface Flow {
  id: string;
  flow_type: FlowType;
  scope: FlowScope;
  scope_id: string;
  organization_id: string;
  name: string;
  description: string | null;
  graph: FlowGraph;
  version: number;
  active: boolean;
  dry_run: boolean;
  snoozed_until: string | null;
  created_by_user_id: string | null;
  created_at: string;
  updated_at: string;
}

interface FlowGraph {
  version: 1;
  nodes: FlowNode[];
  edges: FlowEdge[];
}

interface FlowNode {
  id: string;
  type: string;            // e.g. "trigger.event", "filter.condition"
  position: { x: number; y: number };
  config: Record<string, unknown>;
}

interface FlowEdge {
  id: string;
  source: string;
  sourceHandle: string;    // e.g. "out", "true", "false"
  target: string;
  targetHandle: string;    // e.g. "in"
}

// CRUD
interface CreateFlowRequest {
  flow_type: FlowType;
  scope: FlowScope;
  scope_id: string;
  name: string;
  description?: string;
  graph?: FlowGraph;       // optional, defaults to empty
}

interface UpdateFlowRequest {
  name?: string;
  description?: string;
  graph?: FlowGraph;
  change_summary?: string; // optional commit message
}

// Test run
interface TestRunRequest {
  event_id?: string;       // pick from recent events
  mock_payload?: unknown;  // or build a fake one
}

interface TestRunResponse {
  status: 'completed' | 'failed' | 'skipped';
  outcome: unknown;        // shape depends on flow_type
  node_executions: Array<{
    node_id: string;
    node_type: string;
    status: 'success' | 'failed' | 'skipped';
    input: unknown;
    output: unknown;
    error: string | null;
    duration_ms: number;
  }>;
  total_duration_ms: number;
}

// Run history
interface FlowRun {
  id: string;
  flow_id: string;
  flow_name: string;       // joined from flows
  flow_type: FlowType;
  flow_version: number;
  trigger_event_id: string | null;
  trigger_payload: unknown;
  status: 'running' | 'completed' | 'failed' | 'skipped' | 'dry_run';
  outcome: unknown;
  error: string | null;
  duration_ms: number | null;
  started_at: string;
  completed_at: string | null;
}
```

---

## Backend: Flow Engine

### `backend/src/lib/flows/types.ts`

```typescript
export interface NodeContext {
  flowId: string;
  flowRunId: string;
  organizationId: string;
  flowType: FlowType;
  scope: FlowScope;
  scopeId: string;
  // Mutable bag carried between nodes. Each node reads from `data` (the flowing payload)
  // and may write back. Trigger context is initially placed here.
  data: Record<string, unknown>;
}

export interface NodeExecutionResult {
  // The output payload (becomes the next node's input)
  output: Record<string, unknown>;
  // Which output handle to follow. Default = 'out'. For branches: 'true'/'false', or named.
  next?: string;
  // True if this node decides the flow should stop (e.g., filter rejected)
  halt?: boolean;
}

export interface NodeDefinition {
  type: string;             // "trigger.event"
  category: 'trigger' | 'filter' | 'logic' | 'transform' | 'destination' | 'outcome' | 'action' | 'code';
  label: string;            // "Event Trigger"
  // Which flow types can use this node
  validForFlowTypes: FlowType[];
  // Maximum 1 trigger node per flow (validated at save time)
  isTrigger?: boolean;
  // Schema describes the right-panel config form. Used by frontend + validate().
  configSchema: ConfigField[];
  outputHandles: string[];  // ['out'] or ['true','false'] or custom
  // Validate config at save time
  validate?: (config: Record<string, unknown>) => string[];
  // Execute at runtime
  execute: (config: Record<string, unknown>, context: NodeContext) => Promise<NodeExecutionResult>;
}

export interface ConfigField {
  key: string;
  label: string;
  type: 'string' | 'text' | 'number' | 'boolean' | 'select' | 'multi-select'
      | 'integration' | 'channel' | 'event_type_select' | 'condition_builder'
      | 'code' | 'template' | 'json';
  required?: boolean;
  default?: unknown;
  options?: Array<{ value: string; label: string }>;
  // For 'integration': filter by provider
  providerFilter?: string[];
  // For 'channel': depends on integration_id field
  dependsOn?: string;
  description?: string;
  placeholder?: string;
}
```

### `backend/src/lib/flows/registry.ts`

```typescript
import { NodeDefinition } from './types';
import * as triggerEvent from './nodes/trigger.event';
import * as triggerPrOpened from './nodes/trigger.pr_opened';
// ... import all ~30 node modules

export const NODE_REGISTRY: Record<string, NodeDefinition> = {
  'trigger.event': triggerEvent.definition,
  'trigger.pr_opened': triggerPrOpened.definition,
  'trigger.dependency_evaluated': /* ... */,
  // ... all nodes
};

export function getNode(type: string): NodeDefinition | undefined {
  return NODE_REGISTRY[type];
}

// Used by API to send the registry to the frontend (for the node palette + config UI)
export function getRegistryForFlowType(flowType: FlowType): NodeDefinition[] {
  return Object.values(NODE_REGISTRY).filter(n => n.validForFlowTypes.includes(flowType));
}
```

### `backend/src/lib/flows/engine.ts`

```typescript
import { NODE_REGISTRY } from './registry';
import { supabase } from '../supabase';

export interface ExecuteFlowOptions {
  flowId: string;
  triggerPayload: Record<string, unknown>;
  triggerEventId?: string;
  dryRun?: boolean;       // if true, destinations log instead of dispatch
}

export interface ExecuteFlowResult {
  flowRunId: string;
  status: 'completed' | 'failed' | 'skipped' | 'dry_run';
  outcome: Record<string, unknown>;
  durationMs: number;
}

export async function executeFlow(opts: ExecuteFlowOptions): Promise<ExecuteFlowResult> {
  const startedAt = Date.now();

  // 1. Load flow
  const { data: flow } = await supabase.from('flows').select('*').eq('id', opts.flowId).single();
  if (!flow) throw new Error('Flow not found');
  if (!flow.active) {
    return await recordSkippedRun(flow, opts, 'flow inactive');
  }
  if (flow.snoozed_until && new Date(flow.snoozed_until) > new Date()) {
    return await recordSkippedRun(flow, opts, 'flow snoozed');
  }

  // 2. Create flow_runs row
  const { data: runRow } = await supabase.from('flow_runs').insert({
    flow_id: flow.id,
    flow_version: flow.version,
    organization_id: flow.organization_id,
    trigger_event_id: opts.triggerEventId ?? null,
    trigger_payload: opts.triggerPayload,
    status: 'running',
  }).select().single();

  const flowRunId = runRow.id;
  const dryRun = opts.dryRun ?? flow.dry_run;

  try {
    // 3. Find trigger node
    const triggerNode = flow.graph.nodes.find((n: any) => NODE_REGISTRY[n.type]?.isTrigger);
    if (!triggerNode) {
      return await failRun(flowRunId, 'no trigger node');
    }

    // 4. Walk the graph
    const context: NodeContext = {
      flowId: flow.id,
      flowRunId,
      organizationId: flow.organization_id,
      flowType: flow.flow_type,
      scope: flow.scope,
      scopeId: flow.scope_id,
      data: { ...opts.triggerPayload },
    };

    let currentNode = triggerNode;
    let nextHandle: string | null = 'out';
    let outcome: Record<string, unknown> = {};
    const safetyLimit = 200; // max nodes per run
    let stepsExecuted = 0;

    while (currentNode && nextHandle && stepsExecuted < safetyLimit) {
      const def = NODE_REGISTRY[currentNode.type];
      if (!def) {
        await recordNodeExecution(flowRunId, currentNode, 'failed', context.data, null, `Unknown node type: ${currentNode.type}`);
        return await failRun(flowRunId, `unknown node type: ${currentNode.type}`);
      }

      const nodeStart = Date.now();
      try {
        // Inject dryRun flag for destination/outcome nodes
        const nodeConfig = { ...currentNode.config, __dryRun: dryRun };
        const result = await def.execute(nodeConfig, context);

        await recordNodeExecution(
          flowRunId, currentNode, 'success',
          context.data, result.output, null,
          Date.now() - nodeStart,
        );

        if (result.halt) {
          break;
        }

        // Update context for next node
        context.data = result.output;
        nextHandle = result.next ?? 'out';

        // Capture outcome from terminal nodes
        if (def.category === 'destination' || def.category === 'outcome') {
          outcome = { ...outcome, [currentNode.id]: result.output };
        }

        // Find next node via edge
        const edge = flow.graph.edges.find((e: any) => e.source === currentNode.id && e.sourceHandle === nextHandle);
        currentNode = edge ? flow.graph.nodes.find((n: any) => n.id === edge.target) : null;
        stepsExecuted++;
      } catch (err: any) {
        await recordNodeExecution(
          flowRunId, currentNode, 'failed',
          context.data, null, err.message,
          Date.now() - nodeStart,
        );
        return await failRun(flowRunId, err.message);
      }
    }

    if (stepsExecuted >= safetyLimit) {
      return await failRun(flowRunId, 'execution step limit exceeded (loop?)');
    }

    // 5. Record completion
    const durationMs = Date.now() - startedAt;
    await supabase.from('flow_runs').update({
      status: dryRun ? 'dry_run' : 'completed',
      outcome,
      duration_ms: durationMs,
      completed_at: new Date().toISOString(),
    }).eq('id', flowRunId);

    return { flowRunId, status: dryRun ? 'dry_run' : 'completed', outcome, durationMs };
  } catch (err: any) {
    return await failRun(flowRunId, err.message);
  }
}

// Helpers (record skipped, fail, record node execution, etc.)
```

**Key engine behaviors:**

- Linear walk by default. Loop and parallel nodes need extension (deferred to Phase 2 of impl — start with linear chains, then add fan-out for `logic.parallel`).
- Each node receives `context.data` as input and returns new output → next node's input.
- Filter nodes return `halt: true` when they reject; others continue down the chosen handle.
- Destinations and outcomes write to `outcome` — that's the `flow_runs.outcome` summary.
- `__dryRun` flag injected into every node config; destination nodes check this and log instead of dispatching.

### Node implementations — examples

**`backend/src/lib/flows/nodes/trigger.event.ts`**
```typescript
export const definition: NodeDefinition = {
  type: 'trigger.event',
  category: 'trigger',
  label: 'Event Trigger',
  validForFlowTypes: ['notification'],
  isTrigger: true,
  outputHandles: ['out'],
  configSchema: [
    {
      key: 'event_types',
      label: 'Event Types',
      type: 'multi-select',
      required: true,
      options: [
        { value: 'vulnerability_discovered', label: 'Vulnerability Discovered' },
        { value: 'malicious_package_detected', label: 'Malicious Package Detected' },
        { value: 'project_created', label: 'Project Created' },
        // ... all ~17 event types
      ],
    },
  ],
  validate: (config) => {
    const errors: string[] = [];
    if (!Array.isArray(config.event_types) || config.event_types.length === 0) {
      errors.push('At least one event type is required');
    }
    return errors;
  },
  execute: async (config, context) => {
    // Triggers don't transform data; they just pass it through.
    // The matching logic (does this event type match?) happens in resolveMatchingFlows()
    // before the engine ever runs.
    return { output: context.data, next: 'out' };
  },
};
```

**`backend/src/lib/flows/nodes/filter.condition.ts`**
```typescript
export const definition: NodeDefinition = {
  type: 'filter.condition',
  category: 'filter',
  label: 'Filter',
  validForFlowTypes: ['notification', 'pr_check', 'policy', 'status'],
  outputHandles: ['true', 'false'],
  configSchema: [
    {
      key: 'rules',
      label: 'Conditions',
      type: 'condition_builder',
      required: true,
    },
    {
      key: 'match',
      label: 'Match',
      type: 'select',
      required: true,
      default: 'all',
      options: [
        { value: 'all', label: 'All conditions (AND)' },
        { value: 'any', label: 'Any condition (OR)' },
      ],
    },
  ],
  execute: async (config, context) => {
    const rules = config.rules as Array<{ field: string; op: string; value: unknown }>;
    const match = config.match as 'all' | 'any';
    const results = rules.map(r => evaluateCondition(r, context.data));
    const passed = match === 'all' ? results.every(Boolean) : results.some(Boolean);
    return { output: context.data, next: passed ? 'true' : 'false' };
  },
};

function evaluateCondition(rule: { field: string; op: string; value: unknown }, data: Record<string, unknown>): boolean {
  const v = getByPath(data, rule.field);   // dot-path lookup
  switch (rule.op) {
    case 'eq': return v === rule.value;
    case 'neq': return v !== rule.value;
    case 'gt': return typeof v === 'number' && typeof rule.value === 'number' && v > rule.value;
    case 'lt': return typeof v === 'number' && typeof rule.value === 'number' && v < rule.value;
    case 'in': return Array.isArray(rule.value) && rule.value.includes(v as never);
    case 'contains': return typeof v === 'string' && typeof rule.value === 'string' && v.includes(rule.value);
    case 'regex': return typeof v === 'string' && new RegExp(rule.value as string).test(v);
    case 'exists': return v !== undefined && v !== null;
    default: return false;
  }
}
```

**`backend/src/lib/flows/nodes/destination.slack.ts`**
```typescript
import { dispatchToDestination } from '../../destination-dispatchers';
import { renderTemplate } from '../templates';

export const definition: NodeDefinition = {
  type: 'destination.slack',
  category: 'destination',
  label: 'Send to Slack',
  validForFlowTypes: ['notification'],
  outputHandles: ['out'],
  configSchema: [
    { key: 'integration_id', label: 'Slack Workspace', type: 'integration', required: true, providerFilter: ['slack'] },
    { key: 'channel_id', label: 'Channel', type: 'channel', required: true, dependsOn: 'integration_id' },
    { key: 'title', label: 'Title (template)', type: 'template', required: true, default: '{{event_type}}' },
    { key: 'body', label: 'Body (template)', type: 'template', required: true },
  ],
  execute: async (config, context) => {
    const dryRun = (config as any).__dryRun;
    const title = renderTemplate(config.title as string, context.data);
    const body = renderTemplate(config.body as string, context.data);

    if (dryRun) {
      return { output: { dispatched: false, dry_run: true, title, body, channel: config.channel_id }, next: 'out' };
    }

    // Reuse existing dispatcher
    const result = await dispatchToDestination(
      /* connection loaded via integration_id */,
      { title, body, severity: 'medium', deptexUrl: '...' },
      { id: 'flow-run', event_type: context.flowType, organization_id: context.organizationId, payload: context.data },
    );

    // Also insert into notification_deliveries so the existing health/rate limiting works
    await supabase.from('notification_deliveries').insert({
      event_id: context.data.event_id ?? null,
      flow_run_id: context.flowRunId,
      organization_id: context.organizationId,
      destination: { type: 'slack', integration_id: config.integration_id, channel_id: config.channel_id },
      integration_id: config.integration_id,
      status: result.success ? 'delivered' : 'failed',
      message_title: title,
      message_body: body,
      error_message: result.error ?? null,
      sent_at: new Date().toISOString(),
      delivered_at: result.success ? new Date().toISOString() : null,
    });

    return { output: { dispatched: result.success, error: result.error }, next: 'out' };
  },
};
```

**Note on `notification_deliveries`:** add a nullable `flow_run_id` column to that table during the schema migration so flow-driven dispatches are linkable to runs. The existing per-rule `rule_id` column becomes nullable.

**`backend/src/lib/flows/nodes/outcome.block_pr.ts`**
```typescript
export const definition: NodeDefinition = {
  type: 'outcome.block_pr',
  category: 'outcome',
  label: 'Block PR',
  validForFlowTypes: ['pr_check'],
  outputHandles: ['out'],
  configSchema: [
    { key: 'message', label: 'Block reason (template)', type: 'template', required: true, default: 'PR blocked by Deptex' },
  ],
  execute: async (config, context) => {
    const message = renderTemplate(config.message as string, context.data);
    // Outcome nodes don't dispatch directly — they set the outcome.
    // The pr_check executor in workers.ts reads outcome.block and updates the check run.
    return { output: { block: true, message }, next: 'out' };
  },
};
```

**`backend/src/lib/flows/nodes/action.code.ts`** (escape hatch)
```typescript
import { executePolicyFunction } from '../../policy-engine';

export const definition: NodeDefinition = {
  type: 'action.code',
  category: 'code',
  label: 'Code',
  validForFlowTypes: ['notification', 'pr_check', 'policy', 'status'],
  outputHandles: ['out'],
  configSchema: [
    {
      key: 'code',
      label: 'JavaScript',
      type: 'code',
      required: true,
      default: 'function flowNode(input) {\n  return input;\n}',
    },
  ],
  execute: async (config, context) => {
    const result = await executePolicyFunction(
      config.code as string,
      'flowNode',
      context.data,
      { timeoutMs: 10000, maxFetches: 5 },
    );
    return { output: result as Record<string, unknown>, next: 'out' };
  },
};
```

### Trigger resolution

`backend/src/lib/flows/resolve.ts`:

```typescript
// Replaces resolveMatchingRules() in notification-dispatcher.ts.
export async function resolveMatchingFlows(event: any): Promise<Flow[]> {
  // Cascade: org flows + team flows (if event.team_id) + project flows (if event.project_id)
  // Filter to active, non-snoozed flows of type='notification'
  // Filter to flows whose trigger.event node config.event_types includes event.event_type

  const { data: orgFlows } = await supabase
    .from('flows')
    .select('*')
    .eq('organization_id', event.organization_id)
    .eq('flow_type', 'notification')
    .eq('scope', 'organization')
    .eq('active', true);

  // ...team flows, project flows...

  return [...orgFlows, ...teamFlows, ...projectFlows].filter(flow => {
    const trigger = flow.graph.nodes.find((n: any) => n.type === 'trigger.event');
    if (!trigger) return false;
    const eventTypes = trigger.config.event_types as string[];
    return eventTypes.includes(event.event_type);
  });
}
```

### PR check async path

In `backend/src/routes/integrations.ts:handlePullRequestEvent`:

```typescript
// AFTER existing dep diff logic that builds `prContext`:
const { data: prCheckFlows } = await supabase
  .from('flows')
  .select('id')
  .eq('organization_id', organizationId)
  .eq('flow_type', 'pr_check')
  .eq('active', true)
  .or(`scope.eq.organization,and(scope.eq.project,scope_id.eq.${projectId})`);

if (prCheckFlows && prCheckFlows.length > 0) {
  // Create check run as in_progress
  const checkRun = await createCheckRun(token, repoFullName, headSha, checkName, { status: 'in_progress' });

  // Queue execution via QStash
  for (const flow of prCheckFlows) {
    await queueWorkerJob('/api/workers/execute-pr-check-flow', {
      flow_id: flow.id,
      pr_payload: prContext,
      check_run_context: { token, repoFullName, checkRunId: checkRun.id, prNumber, headSha, projectId },
    });
  }
  // Webhook responds; QStash worker updates check run when done.
} else {
  // No flows: existing legacy behavior (or just pass)
}
```

`/api/workers/execute-pr-check-flow` worker:
1. Calls `executeFlow(flowId, prContext)` from the engine.
2. Checks `outcome` for any `outcome.block_pr` → if present, updates check run to `failure`.
3. Else updates check run to `success`.
4. Posts/updates PR comment with violation messages from outcome.

---

## Frontend Design

### Pages & Routes

Add to `frontend/src/app/routes.tsx`:

```tsx
// Inside the /organizations/:id children array:
{
  path: "flows/:flowId",
  element: <FlowEditorPage />,
},
{
  path: "notifications/history",
  element: <NotificationHistoryPage />,
},
```

Pages modified:
- **`OrganizationSettingsPage.tsx`** — Notifications section becomes a flow list (using shared `<FlowList flowType="notification" scope="organization" />`)
- **`PoliciesPage.tsx`** — Replaced with PR Check flow list. (We may keep the page name "Policies" since that's the user-facing concept, but the content is a flow list.)
- **`ProjectSettingsContent.tsx`** — Add Policy + Status flow tabs

### Component tree — Flow Editor (`/organizations/:id/flows/:flowId`)

```
FlowEditorPage
├── EditorTopBar
│   ├── BackButton (to settings origin)
│   ├── FlowNameInput (editable inline)
│   ├── ActiveToggle
│   ├── DryRunToggle
│   ├── VersionDropdown
│   ├── TestRunButton
│   └── SaveStatusIndicator ("Saved 2s ago" / "Saving…")
├── EditorBody (flex)
│   ├── NodePalette (left, w-64)
│   │   ├── PaletteSearch
│   │   └── PaletteCategoryGroup × N
│   │       └── PaletteNodeButton × M (drag source)
│   ├── FlowCanvas (flex-1)
│   │   ├── ReactFlow
│   │   │   ├── Background variant=Dots
│   │   │   ├── FlowNode (custom, per node type) × N
│   │   │   ├── FlowEdge × M
│   │   │   ├── MiniMap
│   │   │   └── Controls
│   │   └── MultiplayerCursors (overlay)
│   └── NodeConfigPanel (right, w-80, only when node selected)
│       ├── NodeTypeBadge
│       ├── ConfigField × N (rendered from node's configSchema)
│       └── DeleteNodeButton
└── TestRunModal (when open)
    ├── TabSwitcher (Sample Picker | Mock Builder)
    ├── SamplePicker | MockBuilder
    ├── RunButton
    └── ExecutionTracePanel (after run)
```

### Component tree — Notification History (`/organizations/:id/notifications/history`)

```
NotificationHistoryPage
├── PageHeader ("Notification History")
├── FilterBar
│   ├── FlowTypeFilter
│   ├── StatusFilter
│   ├── DateRangeFilter
│   └── FlowFilter (multi-select)
├── RunTable
│   └── RunRow × N
│       ├── StatusDot
│       ├── Timestamp
│       ├── FlowName + Type Badge
│       ├── TriggerSummary
│       └── OutcomeSummary
└── RunInspectorDrawer (when row clicked)
    ├── DrawerHeader
    ├── TriggerPayload (JSON viewer)
    ├── NodeExecutionTimeline
    │   └── NodeExecutionRow × N (status, type, duration, click → expand)
    └── OutcomeJSON
```

### Design specifications

Following the frontend-design skill:

**Editor top bar**: `h-14 px-4 border-b border-border bg-background flex items-center justify-between`. Save indicator on the right (`text-xs text-foreground-secondary`).

**Node palette**: `w-64 border-r border-border bg-background-card overflow-y-auto`. Search `Input` at top (`h-9`). Category headers `text-xs font-semibold uppercase tracking-wider text-foreground-secondary px-3 py-2`. Node buttons `flex items-center gap-2 px-3 py-2 text-sm hover:bg-background-subtle cursor-grab` with icon (Lucide) + label.

**Canvas background**: `bg-background-content` (slightly lighter than page bg). React Flow `<Background variant={Dots} gap={16} size={1.2} color="rgba(148,163,184,0.3)" />`.

**Flow nodes** (custom React Flow nodes): `min-w-[200px] rounded-lg border border-border bg-background-card shadow-sm`. Header: `px-3 py-2 border-b border-border flex items-center gap-2 text-sm font-semibold` with category-color dot. Body: `px-3 py-2 text-xs text-foreground-secondary` showing summarized config. When selected: `ring-2 ring-primary/50`. Per-category accent color on the dot:
- Trigger: `bg-info`
- Filter: `bg-warning`
- Logic: `bg-purple-500`
- Transform: `bg-cyan-500`
- Destination: `bg-success`
- Outcome: `bg-destructive` (for block) / `bg-success` (for allow)
- Action: `bg-foreground-secondary`
- Code: `bg-orange-500`

**Edges**: Default ReactFlow edges, but with conditional handles:
- `out` handle: bottom-center (single output)
- `true`/`false` handles: bottom-left / bottom-right (filter branches)
- `in` handle: top-center

**Right panel (node config)**: `w-80 border-l border-border bg-background-card overflow-y-auto`. Section headers `text-xs font-semibold uppercase tracking-wider text-foreground-secondary px-4 py-2`. Form fields stacked, `px-4 py-2 space-y-3`. Each field: label (`text-sm font-medium text-foreground`) + control + optional helper text (`text-xs text-foreground-secondary`).

**Field types — UI implementations:**
- `string`: shadcn `<Input>`
- `text`: shadcn `<Textarea>` (3 rows default)
- `select`: shadcn `<Select>`
- `multi-select`: chip-style multi-select (see existing `NotificationRulesSection` for a pattern, or build a simple checkbox list)
- `integration`: dropdown listing connections from `organization_integrations` filtered by `providerFilter`. Reuse the connection picker logic from `NotificationRulesSection.tsx:getConnectionLabel`.
- `channel`: depends on selected integration. For Slack/Discord: dropdown of channels (fetched via API endpoint like `/api/integrations/:id/channels`). For Jira: project key text input. For Linear: team selector. We'll build per-provider channel pickers as needed; v1 can have a text input fallback.
- `condition_builder`: nested rule editor — list of `{field, op, value}` rows + match-all/any toggle. Most complex field type. ~150 LOC component.
- `code`: Monaco editor, JS syntax. Reuse `frontend/src/components/policy-monaco-setup.ts` setup.
- `template`: textarea with `{{ field.path }}` syntax highlighting (basic; nice-to-have). Helper text shows available variables for the current trigger type.
- `event_type_select`: hardcoded list of event types (sourced from a TS const).
- `json`: Monaco editor, JSON syntax.

**Test Run modal**: shadcn `<Dialog>`, `max-w-3xl`. Two tabs at top. Body height ~`h-[600px]`. After running: split top half (input) + bottom half (timeline). Each timeline row: status dot + node label + duration, expandable to show `input` / `output` JSON.

**Notification History page** layout:
- Page container same as other org pages: `min-h-screen bg-background px-6 py-6`
- Filter bar across top: `flex items-center gap-2 mb-4`
- Table card: `rounded-lg border border-border bg-background-card overflow-hidden`
- Table follows the project settings activity table pattern (per memory `project_settings_activity_table.md`): colSpan + flex column pattern, no per-row title, fixed font sizes, status dot column.

**Drawer for run inspector**: same pattern as `frontend-design.skill` for Slide-In Sidebars (`fixed right-0 top-0 bottom-0 w-full max-w-[900px] bg-background-card border-l border-border translate-x-0`).

---

## Implementation Tasks

Tasks ordered to ship in milestones. Each milestone should be independently demoable in browser.

### Milestone 1 — Schema + Flow CRUD backend (M)

**1.1** Create migration `backend/database/flows_schema.sql` with all 4 tables, indexes, and RLS policies. Apply to dev DB.
- Acceptance: `\d flows`, `\d flow_versions`, `\d flow_runs`, `\d flow_node_executions` all exist.

**1.2** Add nullable `flow_run_id` to `notification_deliveries`. Make `rule_id` nullable.
- Acceptance: Existing notification dispatch unchanged; new column queryable.

**1.3** Create `backend/src/lib/flows/types.ts` with all shared TS types (Flow, FlowGraph, NodeDefinition, ConfigField, NodeContext, NodeExecutionResult).

**1.4** Create `backend/src/routes/flows.ts` with CRUD endpoints (GET list, GET one, POST, PUT, DELETE, PATCH snooze/active/dry_run, GET versions, POST revert).
- Inline RBAC check matching the teams.ts pattern.
- PUT creates a new `flow_versions` row + increments `version` on `flows`.
- DELETE is a hard delete.
- Validation: name 1-100 chars, description ≤500 chars, graph parsed as valid FlowGraph (every node has id/type/position/config; every edge has id/source/target).

**1.5** Mount router in `backend/src/index.ts`: `app.use('/api/flows', flowsRouter)`.

**1.6** Add API client methods to `frontend/src/lib/api.ts`: `listFlows`, `getFlow`, `createFlow`, `updateFlow`, `deleteFlow`, `snoozeFlow`, `setFlowActive`, `setFlowDryRun`, `listFlowVersions`, `revertFlowVersion`.

**1.7** Backend tests in `backend/src/routes/__tests__/flows.test.ts`: 401 without auth, 403 without permission, 200 happy paths for create/read/update/delete, version increments on update.

Files created: migration, `flows.ts`, `types.ts`, `flows.test.ts`. Files modified: `index.ts`, `api.ts`, possibly `notification_deliveries` schema.

### Milestone 2 — Flow execution engine + first 5 nodes (L)

**2.1** Create `backend/src/lib/flows/registry.ts` with empty registry.

**2.2** Create `backend/src/lib/flows/engine.ts`:
- `executeFlow(opts)` — load flow, find trigger, walk graph, record run + node executions
- Linear walk only (no parallel/loop yet)
- Safety limit of 200 steps per run

**2.3** Create `backend/src/lib/flows/templates.ts`: simple Handlebars-style `{{ field.path }}` renderer. Use a small library (`mustache` or vendor a simple regex-based one — ~30 LOC).

**2.4** Implement first 5 nodes:
- `nodes/trigger.event.ts` (notification trigger)
- `nodes/filter.condition.ts` (with condition evaluator helper)
- `nodes/transform.set_field.ts` (write a value to a field path)
- `nodes/destination.in_app.ts` (write to user_notifications respecting prefs)
- `nodes/action.code.ts` (escape hatch using executePolicyFunction)

**2.5** Register all 5 nodes in `registry.ts`.

**2.6** Add worker endpoint `POST /api/workers/execute-flow` in `backend/src/routes/workers.ts`. Calls `executeFlow()`.

**2.7** Backend tests in `backend/src/lib/flows/__tests__/engine.test.ts`:
- Walk a 3-node linear flow → all execute, run completes
- Filter rejects → flow halts at filter, run completed with 0 deliveries
- Code node throws → run failed, error captured
- Step limit exceeded → run failed
- Dry-run mode → in_app destination logs but doesn't insert

Files created: `engine.ts`, `registry.ts`, `templates.ts`, `nodes/*.ts` (5 files), `engine.test.ts`. Modified: `workers.ts`.

### Milestone 3 — Wire notification dispatch through flows (M)

**3.1** Create `backend/src/lib/flows/resolve.ts` with `resolveMatchingFlows(event)`. Uses cascade (org + team + project) and filters by trigger config event_types.

**3.2** Modify `backend/src/routes/workers.ts:dispatch-notification`:
- Replace call to `dispatchNotification(eventId)` with logic that:
  1. Loads event
  2. Resolves matching flows
  3. For each flow, queues `POST /api/workers/execute-flow` via QStash
  4. Marks event as `dispatched`

**3.3** Add `flow_run_id` to `notification_deliveries` insertion in `destination.in_app.ts` and (later) all destination nodes.

**3.4** Manual test:
- Create a notification flow via API: trigger.event(['project_created']) → destination.in_app
- Activate it
- POST to create a project (which fires `project_created` event)
- Verify `flow_runs` row created, `flow_node_executions` rows for trigger + in_app, `user_notifications` rows for org members
- Verify NotificationBell shows the notification

Files modified: `workers.ts`, `destination.in_app.ts`. Files created: `resolve.ts`.

### Milestone 4 — Read-only canvas (M)

**4.1** Create `frontend/src/components/flow-editor/flowTypes.ts` with TS types matching backend.

**4.2** Create `frontend/src/components/flow-editor/nodeRegistry.ts`. Mirrors the backend registry but with frontend-only fields: icon (Lucide), color, etc. Initially seeded with the 5 nodes from M2.

**4.3** Create `frontend/src/components/flow-editor/FlowCanvas.tsx`:
- Wraps `<ReactFlow>` with `nodesDraggable={false}` initially (read-only first)
- Maps backend nodes/edges to React Flow nodes/edges
- Custom `nodeTypes` map with one component per node type (initially: a single generic node component, refined per-type later)
- Renders Background, MiniMap, Controls

**4.4** Create `frontend/src/components/flow-editor/nodes/GenericFlowNode.tsx`:
- Reads node `data.type`, looks up registry for label/icon/color
- Renders the node card per design spec

**4.5** Create `frontend/src/app/pages/FlowEditorPage.tsx`:
- Loads flow by id from URL param
- Renders top bar (just back button + name display for now) + FlowCanvas
- Loading state: skeleton

**4.6** Add route to `routes.tsx`: `/organizations/:id/flows/:flowId`.

**4.7** Manual test: create a flow via API with 3 nodes, navigate to `/organizations/:id/flows/:flowId`, see it rendered.

Files created: 4 frontend files + route. No backend changes.

### Milestone 5 — Editable canvas + auto-save + version (L)

**5.1** Make canvas editable: `nodesDraggable={true}`, `useNodesState` / `useEdgesState`. Drag nodes around → state updates locally.

**5.2** Implement edge connection: ReactFlow `onConnect` handler creates new edge in state with proper `sourceHandle`/`targetHandle`.

**5.3** Create `frontend/src/components/flow-editor/useFlowDraft.ts`:
- Holds local draft (graph) state
- Debounces save (1s after last change)
- Calls `updateFlow` API
- Tracks save status: `idle | saving | saved | error`
- Returns `{ draft, setDraft, saveStatus, lastSavedAt }`

**5.4** Wire draft hook into FlowEditorPage. Top bar shows save status.

**5.5** Implement node creation via drag-from-palette:
- Create `frontend/src/components/flow-editor/NodePalette.tsx` (left sidebar)
- Reads node registry, groups by category, makes each draggable with `react-flow` drag-drop API
- On drop on canvas, creates new node at drop position with default config from registry

**5.6** Implement node deletion (selected node + Delete key, or via right-panel button).

**5.7** Implement edge deletion (selected edge + Delete key).

**5.8** Manual test: create a blank flow, drag 3 nodes from palette, connect them, see auto-save fire, reload page, see saved state.

Files created: `useFlowDraft.ts`, `NodePalette.tsx`. Modified: `FlowCanvas.tsx`, `FlowEditorPage.tsx`, `GenericFlowNode.tsx`.

### Milestone 6 — Right panel node config (M)

**6.1** Create `frontend/src/components/flow-editor/NodeConfigPanel.tsx`:
- Receives selected node + onConfigChange callback
- Reads node registry for its `configSchema`
- Renders one form field per ConfigField

**6.2** Create form field components in `frontend/src/components/flow-editor/fields/`:
- `StringField`, `TextField`, `NumberField`, `BooleanField`, `SelectField`, `MultiSelectField`
- `IntegrationField` (loads connections from API filtered by providerFilter)
- `ChannelField` (Slack/Discord — text input fallback for v1)
- `ConditionBuilderField` (nested rules + match-all/any) — most complex
- `TemplateField` (textarea, with helper text listing available variables)
- `CodeField` (Monaco)
- `EventTypeSelectField` (multi-select with hardcoded options)

**6.3** Wire selected node state in FlowEditorPage. ReactFlow's `onNodeClick` sets selected node.

**6.4** When config changes, update node in draft → triggers auto-save.

**6.5** Add backend endpoint `GET /api/flows/registry?flow_type=notification` that returns the node registry for the current flow type. Frontend caches this on FlowEditorPage load.

**6.6** Manual test: open flow, click a node, edit config in right panel, see auto-save, reload, see persisted config.

Files created: `NodeConfigPanel.tsx`, all field components, registry endpoint. Modified: `FlowEditorPage.tsx`.

### Milestone 7 — All notification destination nodes (M)

**7.1** Implement remaining 8 destination nodes in `backend/src/lib/flows/nodes/`:
- `destination.slack.ts`
- `destination.discord.ts`
- `destination.jira.ts`
- `destination.linear.ts`
- `destination.asana.ts`
- `destination.email.ts`
- `destination.pagerduty.ts`
- `destination.custom_webhook.ts`

Each calls into the existing `dispatchToDestination()` from `destination-dispatchers.ts`. Each writes to `notification_deliveries` with `flow_run_id`. Honors `__dryRun`.

**7.2** Register all in `registry.ts`.

**7.3** Update frontend `nodeRegistry.ts` with icons + colors for each.

**7.4** Manual test for each: create a flow with that destination, fire a matching event, verify message arrives.

Files created: 8 node files. Modified: registries.

### Milestone 8 — Test Run modal (M)

**8.1** Add backend endpoints:
- `POST /api/flows/:id/test_run` (executes flow with `dryRun: true`, captures full trace, returns response without persisting `flow_runs` — or persists with `status='dry_run'`)
- `GET /api/flows/:id/recent_events` (lists recent `notification_events` matching this flow's trigger type for the picker)

**8.2** Create `frontend/src/components/flow-editor/TestRunModal.tsx`:
- Two tabs: Sample Picker / Mock Builder
- Sample Picker: dropdown of recent events, JSON preview of selected
- Mock Builder: Monaco JSON editor with a starter template per trigger type
- "Run Test" button → POST to test_run endpoint → renders execution trace

**8.3** Create `frontend/src/components/flow-editor/ExecutionTracePanel.tsx`:
- Vertical timeline of node executions
- Each row: status dot + node label + duration + click to expand input/output JSON

**8.4** Wire test button in editor top bar to open the modal.

**8.5** Manual test: open a flow, click Test Run, pick an event, run, see all nodes light up with their input/output values.

Files created: 2 components, 2 endpoints. Modified: `flows.ts`, `FlowEditorPage.tsx`.

### Milestone 9 — Notification History page (M)

**9.1** Add backend endpoints:
- `GET /api/flow-runs?organization_id=&flow_id=&status=&from=&to=&limit=` (paginated list with flow name joined)
- `GET /api/flow-runs/:id` (single run with all node executions)

**9.2** Create `frontend/src/app/pages/NotificationHistoryPage.tsx`:
- Filter bar (flow type, status, date range, flow multi-select)
- Table of runs, paginated
- Click row → opens RunInspectorDrawer

**9.3** Create `frontend/src/components/flow-editor/RunInspectorDrawer.tsx`:
- Slide-in from right
- Shows trigger payload, full node execution timeline, outcome JSON

**9.4** Add route to `routes.tsx`: `/organizations/:id/notifications/history`.

**9.5** Add "View History" button on the notifications settings list page → links here.

**9.6** Manual test: navigate to history page, see runs from earlier milestones, click one, see full trace.

Files created: 2 components, 2 endpoints. Modified: `routes.tsx`, settings page.

### Milestone 10 — Settings pages as flow lists (M)

**10.1** Create `frontend/src/components/FlowList.tsx`:
- Props: `{ flowType, scope, scopeId, organizationId }`
- Lists flows filtered by props
- Each row: name, description, status (active/snoozed/dry-run badge), last edited, last run timestamp, 3-dot menu (rename, duplicate, snooze, deactivate, delete)
- "+ New Flow" button → POSTs blank flow → navigates to editor

**10.2** Replace notifications section in `OrganizationSettingsPage.tsx` with `<FlowList flowType="notification" scope="organization" scopeId={orgId} />`.

**10.3** Replace `PoliciesPage.tsx` content with `<FlowList flowType="pr_check" scope="organization" />`. Keep page name "Policies" but content is the flow list.

**10.4** Update `ProjectSettingsContent.tsx` to add tabs for Policy and Status flow lists.

**10.5** Add team-scoped flow list to team settings (existing path).

**10.6** Delete `NotificationRulesSection.tsx`, `NotificationHistorySection.tsx` (replaced).

**10.7** Manual test: each settings page now shows flow list, "+ New Flow" works end-to-end.

Files created: `FlowList.tsx`. Modified: 3 settings pages. Deleted: 2 components.

### Milestone 11 — PR check flow type + async execution (L)

**11.1** Implement PR check trigger node `nodes/trigger.pr_opened.ts`:
- Config: `event_actions` (array of: opened, synchronize, reopened)
- No actual matching logic in execute (matching done before queueing)

**11.2** Implement outcome nodes:
- `outcome.block_pr.ts`
- `outcome.allow_pr.ts`
- `outcome.set_check_status.ts`
- `outcome.add_pr_comment.ts`

**11.3** Add helper `actions.fetch_dependency_metadata.ts`:
- Used inside PR check flows to enrich each added/updated dep with vuln/license/policy data
- Reuses `getVulnCountsForPackageVersion`, `getLicenseForPackage`

**11.4** Add worker endpoint `POST /api/workers/execute-pr-check-flow`:
- Body: `{ flow_id, pr_payload, check_run_context }`
- Calls `executeFlow`, then updates check run + posts comment based on outcome

**11.5** Modify `backend/src/routes/integrations.ts:handlePullRequestEvent`:
- Replace inline `runPRCheck()` call with: find matching pr_check flows, queue each via `/execute-pr-check-flow`
- Webhook responds immediately with check run `in_progress`

**11.6** Same modification in `gitlab-webhooks.ts` and `bitbucket-webhooks.ts`.

**11.7** Manual test: create a PR check flow that blocks PRs with critical vulns, push a real PR with a vulnerable dep, verify check run shows failure within 30s.

Files created: 4 outcome nodes, 1 trigger node, 1 action node, 1 worker endpoint. Modified: 3 webhook handlers.

### Milestone 12 — Policy + Status flow types (M)

**12.1** Implement `nodes/trigger.dependency_evaluated.ts` (policy trigger).

**12.2** Implement `nodes/trigger.extraction_complete.ts` (status trigger).

**12.3** Implement outcomes:
- `outcome.allow_dependency.ts`
- `outcome.deny_dependency.ts`
- `outcome.set_status.ts`

**12.4** Modify `backend/src/routes/workers.ts` (extraction completion path):
- Replace `runPackagePolicy()` per-dep with calls to matching policy flows
- Replace `runStatusEvaluation()` with calls to matching status flows
- Cache flows per extraction to avoid loading per dep

**12.5** Manual test: create policy flow that denies GPL packages → run extraction on a project with GPL deps → verify dep marked non-compliant. Create status flow with thresholds → run extraction → verify status set.

Files created: 2 trigger nodes, 3 outcome nodes. Modified: `workers.ts`.

### Milestone 13 — Advanced nodes (L)

**13.1** Implement remaining nodes:
- `logic.branch.ts` (multi-way switch)
- `logic.parallel.ts` (fan out — engine extension needed)
- `logic.merge.ts`
- `logic.delay.ts`
- `logic.loop.ts` (with iteration safety limit)
- `transform.template.ts`
- `transform.json_extract.ts`
- `transform.regex.ts`
- `transform.date_format.ts`
- `action.http_request.ts` (uses SSRF protection from notification-validator.ts)
- `action.ai_prompt.ts` (calls Tier 1 or Tier 2 AI via existing provider helpers)
- `action.fetch_project_metadata.ts`
- `trigger.schedule.ts` (registers a QStash cron when flow saved/deleted)
- `trigger.webhook.ts` (creates a signed inbound URL for external triggers)

**13.2** Engine extensions:
- Parallel/merge: track multiple "active" walks via a Map; merge node waits for all branches
- Schedule: cron node creates QStash schedule on flow save; deletes on flow delete/active=false
- Webhook trigger: registers an HTTP endpoint `/api/flows/webhook/:flow_id` with HMAC verification

**13.3** Manual test for each advanced node.

Files created: ~13 node files + engine extensions. This is the heaviest backend milestone.

### Milestone 14 — Multiplayer editor (L, parallel-able with M13)

**14.1** Wait for org graph multiplayer to land in main (it's IN FLIGHT — milestones M3-M9 of `org-graph-multiplayer.plan.md`). The patterns we'll reuse:
- Supabase Broadcast pattern from `useCanvasChannel.ts`
- `perfect-cursors` interpolation from `MultiplayerCursors.tsx`
- Color hashing from `cursorVisibility.ts`

**14.2** Create `frontend/src/components/flow-editor/useFlowMultiplayer.ts`:
- Subscribes to channel `flow:{flowId}`
- Broadcasts cursor + node drag events (similar to canvas plan)
- Maintains remote cursor map + remote drag state

**14.3** Create `frontend/src/components/flow-editor/FlowMultiplayerCursors.tsx`:
- Wraps the org graph `MultiplayerCursors` pattern, adapted for the flow editor canvas
- Uses `useViewport()` to convert world coords to screen for cursor rendering

**14.4** Apply remote node drags optimistically to the local draft (don't auto-save remote changes — only the actor's session saves).

**14.5** Add presence indicator in editor top bar: avatar stack of active editors.

**14.6** Conflict handling: if two users edit the same flow, last-saver-wins on the auto-save. The save response includes the new `version` — if the local copy is behind, force-pull and notify "another user updated; refreshed".

**14.7** Manual test: open same flow in two browsers, see cursors, see remote nodes move, save state stays consistent.

Files created: 2 frontend files. Modified: `FlowCanvas.tsx`, `FlowEditorPage.tsx`.

### Milestone 15 — Cleanup + drop legacy tables (S)

**15.1** Delete frontend files:
- `NotificationRulesSection.tsx`, `NotificationHistorySection.tsx` (already done in M10)
- Most of `PoliciesPage.tsx` (already done in M10) — keep skeleton if it still renders the flow list
- `NotificationAIAssistant.tsx`, `PolicyAIAssistant.tsx` (replaced; v1 has no AI assistant for flows)
- `PolicyCodeEditor.tsx`, `PolicyDiffViewer.tsx`, `PolicyDiffCodeEditor.tsx` (no longer used at top level — code node uses Monaco inline)

**15.2** Delete backend files:
- Most of `notification-validator.ts` (kept `executePolicyFunction` is in `policy-engine.ts`, so this file can be removed entirely once nothing imports it)
- `notification-dispatcher.ts` reduced to just helper functions used by destination nodes (or fully removed if all logic moved into engine + nodes)

**15.3** Delete legacy routes from `backend/src/routes/`:
- Endpoints in `organizations.ts` for `/notification-rules` (CRUD) — replaced by `/api/flows`
- Endpoints in `organizations.ts` for `/policy-code` — replaced
- Endpoints in `organizations.ts` for `/pr_check` — replaced
- Endpoints in `projects.ts` for `validate-policy` — code node has its own validation

**15.4** Run migration `backend/database/drop_legacy_rule_tables.sql`.

**15.5** Final smoke test: every flow type creates and runs end-to-end in a fresh dev DB.

Files deleted: ~10. Migration applied.

---

## Testing & Validation Strategy

### Backend tests (Jest + Supertest)

**`backend/src/routes/__tests__/flows.test.ts`**:
- Auth: 401 without bearer
- RBAC: 403 without `manage_notifications` for notification flows; 403 without `manage_policies` for other types
- CRUD happy paths
- Version increments on PUT
- Revert creates new version, preserves old
- Validation: invalid graph rejected
- Cross-org write rejected (orgId in route mismatched with flow)

**`backend/src/lib/flows/__tests__/engine.test.ts`**:
- Linear walk: 3-node flow completes
- Filter halt: rejects → next node not executed
- Step limit: cycle in graph caught
- Code node throws → run failed
- Dry run: destinations log, don't dispatch
- Trigger event_types match correctly
- Cascade: org + team + project flows resolved

**Per-node tests** in `backend/src/lib/flows/nodes/__tests__/`:
- One test file per node type
- Test config validation
- Test execute() with sample contexts

### Frontend tests (Vitest)

- `flowTypes.test.ts` — type guards
- `nodeRegistry.test.ts` — all backend node types have UI registrations
- `useFlowDraft.test.ts` — debounced save behavior
- `ConditionBuilderField.test.tsx` — add/remove rules, match toggle

### Manual browser test plan

1. **Notification flow**: create with trigger.event(['project_created']) → destination.in_app. Activate. Create a project. Verify NotificationBell shows the notification.
2. **Multi-destination**: add destination.slack to the same flow. Create a project. Verify Slack message arrives.
3. **Filter**: add filter.condition between trigger and slack. Set condition `project.name contains 'test'`. Create projects with/without 'test' in name → only matching ones notify.
4. **Test Run**: pick a recent event, run the flow, verify trace shows correct path.
5. **PR check flow**: create flow with trigger.pr_opened → action.fetch_dependency_metadata → filter (critical vulns) → outcome.block_pr. Push a real PR with vuln → check run shows failure.
6. **Policy flow**: create flow with trigger.dependency_evaluated → filter (license = GPL) → outcome.deny_dependency. Run extraction with GPL package → marked non-compliant.
7. **Status flow**: create flow with trigger.extraction_complete → branch on counts → outcome.set_status. Verify project status updates after extraction.
8. **Code escape hatch**: build a flow using action.code with a JS function. Verify execution captures the code's return.
9. **Multiplayer**: open same flow in 2 browsers. See cursors. Drag nodes in one, watch the other. Edit config in one, see auto-save propagate.
10. **History**: navigate to notifications/history, see all runs from above tests, click one, see full node trace.
11. **Snooze**: snooze a flow → trigger event → verify flow_run is `skipped`.
12. **Dry run**: enable on a flow → trigger event → verify destinations logged but not dispatched.
13. **Active toggle**: deactivate → trigger event → no flow_run created.

### Integration

- Trigger an event → verify QStash queues `dispatch-notification` → which queues `execute-flow` per matching flow → which executes → which calls destination dispatcher → which writes to `notification_deliveries`. Full chain.
- PR webhook → check run created `in_progress` → flow executes → check run updated to `success`/`failure`. Full chain.

### Performance targets

| Metric | Target |
|---|---|
| Flow CRUD endpoints | p95 < 100ms |
| Test run for typical flow (5 nodes) | < 2s |
| Notification flow execution (no HTTP/AI nodes) | p95 < 1s |
| PR check flow execution | p95 < 5s (allowing for dep enrichment) |
| Editor load (50-node flow) | < 500ms |
| Notification History list (50 rows) | < 300ms |
| Per-node execution recording overhead | < 5ms |

### Regression surface

- Existing notification dispatch via `emitEvent()` calls — must keep working through the new engine. All ~17 call sites tested by triggering each event type at least once.
- GitHub PR webhook (currently the only working path) — must not regress; test with the same PR scenarios that work today.
- In-app notifications — `user_notifications` schema unchanged; NotificationBell should keep working.
- User preferences (mute, DND, opt-out) — destination.in_app node still respects these.

---

## Risks & Open Questions

### Risks

- **Scope creep**: this is a large feature spanning 15 milestones. The risk is shipping a half-built v1 that's worse than what we have. Mitigation: every milestone is independently demoable. We can pause/resume between milestones without an inconsistent state. The hard cutover (M15) is the only "no turning back" step — gate it on Henry's full sign-off.
- **Engine bugs around parallel/loop nodes**: these are non-trivial extensions to the linear walker. Defer to M13 so the rest of the system is stable first. Worst case, ship without parallel/loop in v1 and add in v1.1.
- **PR check async UX**: developers may complain about a "pending" check that takes 30s when previously sync was 5s. Mitigation: always show check `in_progress` immediately so it's visible; QStash queue depth monitoring.
- **Multiplayer flow editing complexity**: this is genuinely hard if the org graph multiplayer infrastructure isn't done first. Mitigation: M14 is gated on org graph multiplayer (M3-M9 of that plan). If org graph slips, we ship flow builder without multiplayer (single-user with lock indicator instead).
- **Code escape hatch security**: users could write malicious code. Mitigation: same sandbox we already use (`executePolicyFunction`) — SSRF, fetch limits, timeouts. No new attack surface vs. today's policy code.
- **Schedule and webhook triggers** require new QStash schedule management and inbound URL endpoints — these are real surface-area additions. Defer to M13 so we can ship without them if time-constrained.
- **Tooltip tests for new node types**: easy to forget edge cases. Mitigation: write a test suite that loads the registry and validates every node has: a label, a configSchema with at least one field (or zero for trivial nodes), declares which flow types it's valid for, and has an execute() function that returns a NodeExecutionResult.

### Open questions (decide during implementation)

1. **Channel picker UX for Slack/Discord/etc.** — fetch channels per integration on demand vs. cached list? Default: fetch on dropdown open with skeleton, cache for the session.
2. **Template variable autocomplete** — nice to have. v1 = placeholder text + helper text listing variables. v2 = actual autocomplete with the available paths.
3. **Where to put the "View History" link** — in the flow list page header? In the editor top bar? Both? Default: list page header for the org-wide history; editor top bar for per-flow history.
4. **Edge labels** — should branch handles ("true"/"false") render labels on the edges? Default: yes, for readability. Use ReactFlow's edge label feature.
5. **Node search in palette** — fuzzy match name + category? Default: simple `includes` filter for v1.
6. **Auto-layout button** — "rearrange nodes" via dagre or elkjs? Default: skip for v1, users place manually.
7. **Flow duplication** — POST to `/api/flows/:id/duplicate`? Default: yes, lightweight endpoint, useful for templates.
8. **Per-flow per-edit audit log** — `flow_versions` covers most of this. Do we need a separate "who toggled active when" audit? Default: defer to v2; toggles are low-risk vs. graph edits.
9. **Default snooze durations** — like notification rules today (1h, 1d, 1w, custom)? Default: yes, same dropdown UX.
10. **Right panel width** — 320px feels right per design spec; verify in browser, may need 380px for code field.
11. **Mobile**: this editor is desktop-only. Mobile shows a "this feature requires desktop" message. Document this explicitly.

---

## Dependencies

### NPM packages

Backend — possibly add:
- `mustache` (~5 KB) for template rendering — or vendor a simple regex renderer. Decide in M2.

Frontend — already has everything needed:
- `@xyflow/react` (canvas)
- `monaco-editor` (code field)
- shadcn UI components (Dialog, Select, Button, Input, etc.)
- `perfect-cursors` (will be added by org graph multiplayer; we reuse)

### Internal systems this builds on

- **Existing destination dispatchers** (`backend/src/lib/destination-dispatchers.ts`) — all 9 destinations reused as-is.
- **Existing event bus** (`backend/src/lib/event-bus.ts`) — no changes; emits unchanged.
- **Existing `executePolicyFunction`** (`backend/src/lib/policy-engine.ts`) — sandbox for code node.
- **Existing OAuth token refresh** (`backend/src/lib/notification-dispatcher.ts:refreshTokenWithMutex`) — destination nodes call into this.
- **Org graph multiplayer infrastructure** — flow editor multiplayer reuses `useCanvasChannel` pattern. Gating dependency.
- **Existing RBAC** — `manage_notifications`, `manage_policies` — no new permissions.
- **QStash** — `/execute-flow`, `/execute-pr-check-flow`, schedule node use this. No new QStash infrastructure.
- **Supabase Realtime Broadcast** — channel `flow:{flowId}` — same pattern as org canvas.

### Not used / not built in v1

- No new graph library; no Liveblocks/Yjs/CRDT lib.
- No new AI infrastructure; AI prompt node uses existing `getPlatformProvider` / `getProviderForOrg`.
- No mobile support.
- No template gallery (v2).
- No flow composition / call_flow (v2).
- No external API trigger surface beyond webhook node (v2).

---

## Success Criteria

This is "done" when **all** of:

1. All four flow types (notification, pr_check, policy, status) work end-to-end in a fresh dev environment.
2. Old code editors are removed from the codebase. Old tables are dropped. No code references `organization_notification_rules`, `organization_pr_checks`, `package_policy_code`, `project_status_code`.
3. Henry can rebuild every existing JS rule he had as a flow without using the code escape hatch (proves node library is sufficient).
4. The notification dispatch chain still works for every event type currently emitted (regression-free).
5. PR check flows run async and update GitHub Check Run within 30s for typical flows.
6. Multiplayer flow editing works in two browsers side-by-side (assuming org graph multiplayer is in main).
7. Notification History page shows runs with full per-node traces.
8. Test Run modal works for all four flow types — pick event or build mock, see trace.
9. Edit conflict handling is graceful — last-saver-wins, refresh prompt for stale clients.
10. Looking at a flow canvas, Henry can immediately understand what it does without reading code.
11. No jank in editor at 50+ nodes.
12. No feature flag — ships when Henry signs off in browser per the established cadence.

---

## Phased shipping recommendation

Given size: ship in 3 visible phases internally, even though it's one feature externally.

**Phase A (M1-M9)**: Notification flows working end-to-end. Editor + canvas + 5 destination types + history page. Old notification system in parallel; no cutover yet.

**Phase B (M10-M12)**: All four flow types working. PR check + policy + status flows. Settings pages refactored. Still in parallel with old system.

**Phase C (M13-M15)**: Advanced nodes + multiplayer + cleanup. Drop old tables. Done.

This lets Henry get value from notification flows ~halfway through implementation rather than waiting for the whole feature. And if scope pressure hits, Phase A alone is shippable as "v1: notification flows".
