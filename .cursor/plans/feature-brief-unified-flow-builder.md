# Feature Brief: Unified Flow Builder

## 1. One-liner

A visual graph/flow builder (Tines + n8n hybrid) that replaces the current JavaScript-based notification rules, PR check code, dependency policy code, and project status code with a unified node-based editor.

---

## 2. Problem Statement

The current system uses JavaScript code editors for four critical customization features:
- **Notification rules** (`organization_notification_rules.custom_code`)
- **PR check code** (`organization_pr_checks.pr_check_code`)
- **Dependency policy code** (`package_policy_code` - per-package allow/deny)
- **Project status code** (`project_status_code` - aggregate status assignment)

While code provides ultimate customizability, it has three core problems:

1. **Discoverability**: Users (security engineers) can't envision what's possible. Staring at a function signature doesn't surface the use cases. The result: heavy reliance on the AI to write code, and many users don't customize at all.
2. **Mental overhead**: Each feature has a different signature, sandbox, and mental model. PR check returns `{passed, violations}`. Policy returns `{allowed, reasons}`. Status returns `string`. Notification returns `boolean | {notify, message}`. Four different shapes for similar work.
3. **Brittleness**: Code rules are isolated — no reuse of filters, transforms, or sub-flows. Editing live code in production is risky.

A visual flow builder solves all three: discoverability via the node palette, one consistent mental model across all features, and reusable composable nodes with version history.

---

## 3. Competitive Landscape

### Direct competitors (SCA / dependency security)

| Vendor | Approach | Visual flow builder? |
|--------|----------|----------------------|
| **Snyk** | Simple email/Slack actions, `.snyk` YAML for ignores | ❌ |
| **Endor Labs** | "Action Policies" — form-based rule editor | ❌ |
| **Socket** | Rule-based config | ❌ |
| **Dependabot/Mend** | Static config files | ❌ |

**Key finding: NO direct SCA competitor has a visual flow builder for notifications/policy.** This is a clear differentiation opportunity.

### Adjacent inspiration

| Tool | Borrow | Why |
|------|--------|-----|
| **Tines** | Node library design (HTTP request, event trigger, logical filter, notification action). Run inspector for execution traces. | Built specifically for security teams who don't want code. SOAR is the closest analog. |
| **n8n** | Canvas UX (drag-drop, node palette sidebar, right-panel node config). Code node escape hatch pattern. | Open-source, familiar to anyone who's used Zapier/Make. |
| **Datadog** | Monitor templates as starting points (defer to v2). | Reduces blank-canvas paralysis. |
| **Linear** | Settings as list, fullscreen editor for complex objects. | Right placement pattern. |
| **Stripe** | Same — list in settings, focused editor for the entity. | Same. |

### Differentiation strategy

1. **Bring Tines-style flows into SCA.** No competitor does this — it's a wedge.
2. **Unify four customization features into ONE builder.** Even Tines doesn't do this; it's a separate platform you'd integrate. We bake it in.
3. **Async PR check evaluation with check run updates.** Most competitors do PR checks synchronously and limit complexity. Our async architecture means flows can be arbitrarily rich.
4. **Multiplayer editing.** Reuses the org graph multiplayer infrastructure. Differentiating for security teams collaborating on workflows.

---

## 4. User Stories

### Notification flows
- As a **security engineer**, I want to drag a "Slack" destination onto my canvas and connect it to a "Vulnerability Discovered" trigger so I can route critical CVEs to my team channel without writing code.
- As a **security engineer**, I want to add a "Filter" node between the trigger and destination that only fires for `severity >= high AND reachability = confirmed` so I avoid alert fatigue.
- As an **org admin**, I want to see a notification history page listing every flow run, so I can audit which alerts fired and why.

### PR check flows
- As a **security engineer**, I want to build a PR check flow that says "if any added dep has critical vulns, block the PR; if license is GPL, post a warning comment but don't block" — without writing JS conditionals.
- As a **developer**, when my PR is blocked I want the check run summary to clearly say "blocked by Flow: 'No critical CVEs', node 'License Filter'" so I know which rule fired.

### Policy flows
- As a **security engineer**, I want to express "auto-deny any package by author X" or "auto-deny any package with quarantine status" as a few connected nodes instead of code.

### Status flows
- As a **security engineer**, I want a status flow that says "if >0 critical vulns: status=Non-Compliant, else if >0 high vulns: status=Needs Review, else status=Compliant" as a visible decision tree.

### Power-user
- As a **security engineer**, I want a "Code" escape-hatch node so I can drop in JavaScript when the visual nodes can't express what I need.
- As a **security engineer**, I want to test a flow against a real recent event before publishing, so I can verify it does what I expect.
- As **two engineers**, we want to edit the same flow simultaneously (multiplayer) so we can pair on complex workflows.

---

## 5. Data Model

### New tables

#### `flows`
The unified table for all flow types.

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `flow_type` | TEXT | `'notification' \| 'pr_check' \| 'policy' \| 'status'` |
| `scope` | TEXT | `'organization' \| 'team' \| 'project'` |
| `scope_id` | UUID | FK to org/team/project depending on scope |
| `organization_id` | UUID FK | Always populated for RLS even when scope=team/project |
| `name` | TEXT | User-visible name |
| `description` | TEXT | Optional |
| `graph` | JSONB | The serialized flow: `{ nodes: [...], edges: [...] }` |
| `version` | INTEGER | Incremented on each save |
| `active` | BOOLEAN | Default true |
| `dry_run` | BOOLEAN | When true, evaluate but skip side effects |
| `snoozed_until` | TIMESTAMPTZ | For temporary disable |
| `created_by_user_id` | UUID FK | |
| `created_at`, `updated_at` | TIMESTAMPTZ | |

**Indexes**: `(flow_type, scope, scope_id)`, `(organization_id, active)`, `(scope_id) WHERE active = true`.

**RLS**: Read = org members. Write = users with corresponding permission (`manage_notifications` for notification flows, `manage_policies` for the others).

#### `flow_versions`
Full version history (snapshot per save, not diff-based, for simplicity and easy revert).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `flow_id` | UUID FK | |
| `version` | INTEGER | |
| `graph` | JSONB | Snapshot of the graph at this version |
| `name` | TEXT | Snapshot of the flow name |
| `changed_by_user_id` | UUID FK | |
| `change_summary` | TEXT | Optional commit-message-style note |
| `created_at` | TIMESTAMPTZ | |

**Index**: `(flow_id, version DESC)`.

#### `flow_runs`
One row per flow execution (notification history page reads from this).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `flow_id` | UUID FK | |
| `flow_version` | INTEGER | Which version of the flow ran |
| `trigger_event_id` | UUID FK | nullable — points to `notification_events` for notification flows |
| `trigger_payload` | JSONB | Snapshot of input that triggered the run |
| `status` | TEXT | `'running' \| 'completed' \| 'failed' \| 'skipped' \| 'dry_run'` |
| `outcome` | JSONB | What happened (e.g., `{ destinations: [...], blocked: true }`) |
| `error` | TEXT | If failed |
| `duration_ms` | INTEGER | |
| `started_at`, `completed_at` | TIMESTAMPTZ | |

**Indexes**: `(flow_id, started_at DESC)`, `(organization_id, started_at DESC)` for the global notification history page.

#### `flow_node_executions`
Per-node execution trace (powers the "click a run, see canvas highlighted" UX in v2; v1 just stores them for debugging).

| Column | Type | Notes |
|--------|------|-------|
| `id` | UUID PK | |
| `flow_run_id` | UUID FK | |
| `node_id` | TEXT | The node ID inside the graph JSON |
| `node_type` | TEXT | `'trigger' \| 'filter' \| 'transform' \| 'destination_slack' \| ...` |
| `status` | TEXT | `'success' \| 'failed' \| 'skipped'` |
| `input` | JSONB | What flowed into the node |
| `output` | JSONB | What the node produced |
| `error` | TEXT | If failed |
| `duration_ms` | INTEGER | |
| `executed_at` | TIMESTAMPTZ | |

**Index**: `(flow_run_id, executed_at)`.

### Tables to delete or gut (Henry is the only user — clean cutover)

- `organization_notification_rules` (custom_code, destinations columns) — replaced by `flows` where `flow_type='notification'`
- `team_notification_rules` — same
- `project_notification_rules` — same
- `organization_pr_checks` — replaced by `flows` where `flow_type='pr_check'`
- `package_policy_code` — replaced by `flows` where `flow_type='policy'`
- `project_status_code` — replaced by `flows` where `flow_type='status'`
- `notification_rule_changes` — replaced by `flow_versions`
- `notification_events` — KEEP (still needed as the trigger for notification flows)
- `notification_deliveries` — KEEP (still needed for delivery tracking, referenced by `flow_runs.outcome`)
- `user_notifications`, `user_notification_preferences` — KEEP (in-app inbox is unchanged)

### Graph JSON schema

```json
{
  "version": 1,
  "nodes": [
    {
      "id": "node-1",
      "type": "trigger.event",
      "position": { "x": 100, "y": 100 },
      "config": { "event_type": "vulnerability_discovered" }
    },
    {
      "id": "node-2",
      "type": "filter.condition",
      "position": { "x": 350, "y": 100 },
      "config": {
        "expression": [
          { "field": "context.vulnerability.severity", "op": "in", "value": ["critical", "high"] },
          { "field": "context.vulnerability.reachability", "op": "eq", "value": "confirmed" }
        ],
        "match": "all"
      }
    },
    {
      "id": "node-3",
      "type": "destination.slack",
      "position": { "x": 600, "y": 100 },
      "config": { "integration_id": "...", "channel_id": "...", "title_template": "{{vulnerability.cve_id}}", "body_template": "..." }
    }
  ],
  "edges": [
    { "from": "node-1", "to": "node-2", "fromHandle": "out", "toHandle": "in" },
    { "from": "node-2", "to": "node-3", "fromHandle": "true", "toHandle": "in" }
  ]
}
```

---

## 6. Node Library (Tines-rich, ~30 nodes)

### Triggers (entry points; one per flow)
- `trigger.event` — fires on a `notification_events` row (notification flow type)
- `trigger.pr_opened` — fires when a PR webhook hits (pr_check flow type)
- `trigger.dependency_evaluated` — fires when a dep is evaluated (policy flow type)
- `trigger.extraction_complete` — fires when extraction finishes (status flow type)
- `trigger.schedule` — fires on a cron schedule
- `trigger.webhook` — external HTTP trigger with signed URL

### Filters / logic
- `filter.condition` — if/else with field comparisons (eq, neq, gt, lt, in, contains, regex, exists)
- `filter.match_any` — OR of conditions
- `filter.match_all` — AND of conditions
- `logic.branch` — multi-way switch on a field value
- `logic.parallel` — fan out to multiple paths simultaneously
- `logic.merge` — wait for multiple parallel paths to complete
- `logic.delay` — wait N seconds/minutes
- `logic.loop` — iterate over an array (with max iterations safety limit)

### Transforms
- `transform.set_field` — assign a value to a context field
- `transform.template` — render a Handlebars template
- `transform.json_extract` — pull a value from JSON via JSONPath
- `transform.regex` — extract or replace via regex
- `transform.date_format` — format a date

### Destinations (notification flow)
- `destination.slack` (channel selector)
- `destination.discord` (channel selector)
- `destination.jira` (project + issue type)
- `destination.linear` (team + labels)
- `destination.asana` (workspace + project)
- `destination.email` (recipients)
- `destination.pagerduty` (routing key)
- `destination.custom_webhook` (URL + HMAC)
- `destination.in_app` (per-user preferences applied)

### Outcomes (PR check / policy / status)
- `outcome.block_pr` (with message)
- `outcome.allow_pr`
- `outcome.set_check_status` (success/failure with summary)
- `outcome.add_pr_comment` (with template)
- `outcome.allow_dependency`
- `outcome.deny_dependency` (with reason)
- `outcome.set_status` (status name)

### External / power
- `action.http_request` — arbitrary HTTPS call (SSRF-protected; reuses existing protections)
- `action.ai_prompt` — calls Tier 1 (platform) or Tier 2 (BYOK) AI model with templated prompt
- `action.code` — escape hatch: run JS with current context, return modified context. Same sandbox as today's policy code.
- `action.fetch_dependency_metadata` — enrich the context with vuln/license/registry data for a package
- `action.fetch_project_metadata` — enrich with project asset tier, team, etc.

### v2 / future (capture but don't build)
- `action.call_flow` — invoke another flow (composition)
- `node.api_input` — make a flow callable as an HTTP API
- Template gallery
- Visual run inspector with canvas highlighting (data is captured in v1 via `flow_node_executions`)

---

## 7. API Endpoints

### Flow CRUD
- `GET /api/flows?scope=org&scope_id=...&type=notification` — list flows for a scope/type
- `GET /api/flows/:id` — fetch a single flow with current graph
- `POST /api/flows` — create a new flow
- `PUT /api/flows/:id` — update flow (creates new `flow_versions` row)
- `DELETE /api/flows/:id` — delete (hard delete; versions preserved if needed)
- `PATCH /api/flows/:id/snooze` — snooze until timestamp
- `PATCH /api/flows/:id/active` — toggle active
- `PATCH /api/flows/:id/dry_run` — toggle dry-run mode

### Versions
- `GET /api/flows/:id/versions` — list versions
- `POST /api/flows/:id/revert/:version` — revert to a previous version

### Test runs
- `POST /api/flows/:id/test_run` — body: `{ event_id?, mock_payload? }`. Runs flow without side effects; returns full execution trace.
- `GET /api/flows/:id/recent_events?limit=20` — sample picker source: list recent events that would trigger this flow type, so user can pick one for test run.

### Execution history
- `GET /api/flow-runs?organization_id=...&flow_id=...&limit=50` — paginated run history (powers notification history page)
- `GET /api/flow-runs/:id` — single run detail with all node executions

### Worker endpoints (called by QStash)
- `POST /api/workers/execute-flow` — body: `{ flow_id, trigger_payload, trigger_event_id? }`. Replaces the old `dispatch-notification` endpoint.
- `POST /api/workers/execute-pr-check-flow` — async PR check evaluation; updates check run when done.

### Internal (event emission stays the same)
- `emitEvent()` from `event-bus.ts` — unchanged contract. Now resolves to flows of type `'notification'` instead of rules.

---

## 8. Frontend Views

### Settings list pages (existing locations, redesigned content)

Each existing settings page becomes a flow list:

- **Org Settings > Notifications** → list of notification flows + "New Flow" button
- **Project Settings > PR Checks** → list of PR check flows
- **Project Settings > Policy** → list of policy flows (for that project's deps)
- **Project Settings > Status** → list of status flows

Each list shows: name, description, last edited, last run timestamp, status (active/snoozed/dry-run), 3-dot menu (rename, duplicate, snooze, delete).

### Flow editor — `/flows/:id` (new fullscreen page)

Layout:
```
┌─────────────────────────────────────────────────────────────┐
│ ← Back to {ParentSettings}    Flow Name (editable)    [⋯]  │  ← header
├──────────┬─────────────────────────────────┬────────────────┤
│ Node     │                                 │ Selected Node  │
│ Palette  │         Canvas                  │ Config         │
│ (search) │     (@xyflow/react)             │ (right panel)  │
│          │                                 │                │
│ Triggers │     [trigger]→[filter]→[Slack]  │ ─ Type: Slack  │
│ Filters  │                                 │ ─ Channel: ... │
│ Logic    │                                 │ ─ Title: ...   │
│ Trans... │                                 │                │
│ Dests    │                                 │                │
│ Actions  │                                 │                │
│ Code     │                                 │                │
└──────────┴─────────────────────────────────┴────────────────┘
                                              ↑
                                       [Test Run] [Save] [Publish?]
```

Features:
- Drag node from palette to canvas
- Click node → right panel config (form fields generated from node type schema)
- Click edge → delete or relabel
- Cmd+Z undo, Cmd+Shift+Z redo (per-user)
- Multiplayer presence cursors (reuse org graph infrastructure)
- "Test Run" button opens a modal: pick recent event OR build mock payload → see execution trace
- Auto-save on idle (always live + version history mode)
- Version dropdown in header to view/revert
- Top-right status: "Saved 2s ago" / "Saving…" / "Conflict — refresh"

### Notification History page (new) — `/organizations/:id/notifications/history`

A timeline of `flow_runs` for the org:
- Filters: flow_type, flow_id, status, date range
- Each row: timestamp, flow name, trigger summary (e.g., "vulnerability_discovered: CVE-2024-1234"), outcome ("Sent to #security in Slack", or "Blocked PR #42")
- Click a row → drawer with full execution trace (node-by-node) + raw input/output

This replaces / supersedes the current notification rule change history UI. It's the primary debugging surface for "did my flow fire?"

### Test run modal

Two tabs:
- **Sample picker**: dropdown of recent events that match this flow's trigger type, with preview of the event payload
- **Mock builder**: JSON editor (Monaco) with autocomplete-ready schema for the trigger type

Below: execution trace panel (live as flow runs) showing each node's input → output → status, with a small canvas thumbnail highlighting which path fired.

---

## 9. User Flows

### Creating a notification flow
1. User goes to Org Settings > Notifications
2. Clicks "New Flow" → POST `/api/flows` with `flow_type='notification'`, blank graph
3. Redirected to `/flows/{newId}` (fullscreen editor, blank canvas)
4. Drags `trigger.event` from palette → canvas
5. Right panel: configures `event_type = 'vulnerability_discovered'`
6. Drags `filter.condition` → canvas, connects from trigger
7. Right panel: adds condition `severity in [critical, high]`
8. Drags `destination.slack` → canvas, connects from filter
9. Right panel: picks integration (Slack workspace), picks channel, edits title/body templates
10. Auto-save on idle. Version 1 created.
11. Clicks "Test Run" → picks a recent vulnerability event → execution trace shows: trigger fired ✓, filter passed ✓, would-have-sent to #security ✓
12. Toggles flow to "Active". Done.

### PR check flow with async evaluation
1. User creates a PR check flow with: trigger → filter (added deps with critical vulns) → outcome.block_pr
2. PR opens on GitHub → webhook arrives at backend
3. Backend immediately creates a GitHub check run with status='in_progress'
4. Backend queues `POST /api/workers/execute-pr-check-flow` via QStash with `{flow_id, pr_payload, check_run_id}`
5. Webhook responds 200 to GitHub (under the 10s limit)
6. QStash delivers the job → worker walks the flow → `outcome.block_pr` reached
7. Worker updates the check run to status='completed', conclusion='failure' with the violation summary
8. PR is now blocked on GitHub

### Auditing what fired
1. User goes to Org Settings > Notifications > "View History"
2. Filters by date range, sees a timeline of every notification flow run
3. Clicks a row from yesterday's CVE-2024-1234 alert
4. Drawer opens showing: trigger node fired with the vuln payload, filter node evaluated to true, Slack destination dispatched successfully (with the actual message body)
5. If something looked wrong, clicks "Open in editor" to jump to that flow at the version that ran

### Multiplayer editing
1. Henry opens flow A in editor at `/flows/abc`
2. Teammate opens the same flow → sees Henry's cursor + "Henry is editing"
3. Both add nodes and connect edges live (CRDT-style merge from org graph multiplayer)
4. Conflict-free because it's a node graph (insert/delete operations commute)

---

## 10. Edge Cases & Error Handling

### Flow execution
- **Trigger fires but flow is inactive** → no run recorded, event proceeds (other matching flows still run)
- **Trigger fires and flow is snoozed** → `flow_runs` row created with status='skipped', reason='snoozed'
- **Trigger fires and flow is dry_run** → run executes fully but destinations log instead of dispatch; `flow_runs.status='dry_run'`
- **Node throws an error mid-flow** → that node's execution recorded as 'failed', flow halts, `flow_runs.status='failed'`, `error` populated. Remaining nodes not executed.
- **Loop exceeds max iterations safety limit** → flow halts with error 'loop limit exceeded'
- **HTTP request times out** (>10s) → node fails, flow halts
- **AI prompt rate limit hit** → node fails with retry hint
- **Code node syntax error** → caught at save time (validator) and at execution time

### Editor
- **Two users save simultaneously (no multiplayer)** → optimistic concurrency via `version` column; later save returns 409 with merge UI (shows other user's changes)
- **User deletes a destination integration that a flow uses** → flow stays valid but on next run, destination node fails with 'integration not found' (clearly logged)
- **User changes the integration token / it expires** → flow run fails on dispatch; auto-disables integration after 3 failures (existing logic carries over)
- **Graph cycle detected on save** → reject save with error
- **Disconnected nodes** (orphan nodes not reachable from a trigger) → allow save, mark them visually grayed-out, never executed

### Migration
- Hard cutover: drop old tables, no migration of existing JS rules (per user direction — solo user pre-launch)

---

## 11. Non-Functional Requirements

### Performance
- **Notification flow evaluation**: <2s typical (synchronous in dispatch worker), <10s p99
- **PR check flow evaluation**: async, no time limit beyond QStash's 15min ceiling. Webhook responds in <1s.
- **Editor load**: <500ms for flows with <50 nodes
- **Test run**: <5s for typical flows
- **Graph renders smoothly with 50+ nodes** (xyflow handles this fine)

### Data volume expectations
- Solo user pre-launch: 5-50 flows total per org
- Run history: assume 100-1000 runs per day in active orgs → cleanup cron deletes runs >90 days
- Each `flow_runs` row + node executions: ~1-10KB depending on payload size

### Reliability
- Flows must NOT be lost on save (append-only `flow_versions` ensures recoverability)
- A failed flow run must not corrupt other runs (each is isolated)
- A bad node type definition must not break the editor (graceful "unknown node" placeholder)

### Scalability
- Cleanup crons match existing notification cleanup (90d for runs, 1y for flow_versions)
- Per-org rate limit on flow executions: 200/hr (matches existing notification rate limit)
- Per-flow execution cap: 1000 concurrent runs (prevent runaway loops)

---

## 12. RBAC

| Action | Required permission |
|--------|---------------------|
| Create/edit notification flow | `manage_notifications` (existing) |
| Create/edit PR check / policy / status flow | `manage_policies` (existing) |
| View any flow | Org member (read-only canvas if no edit perm) |
| View flow run history | Org member (so devs can see why their PR got blocked) |
| Delete a flow | Same as create (manage_notifications or manage_policies) |
| Snooze / toggle active | Same as create |

No new permissions needed — reuse existing.

---

## 13. Dependencies

### Existing code/features this builds on
- **`@xyflow/react`** — already in stack for org graph
- **Org graph multiplayer infrastructure** — reuse for editor multiplayer
- **`event-bus.ts`** — `emitEvent()` keeps its contract; just routes to flows now
- **`destination-dispatchers.ts`** — destination node implementations call into existing dispatcher functions (Slack, Discord, etc.)
- **`policy-engine.ts`** — sandbox execution lives on for the `action.code` escape-hatch node
- **`notification-validator.ts`** — fetch SSRF protections reused for `action.http_request` node
- **QStash** — async worker dispatch unchanged
- **Supabase Realtime** — for multiplayer editor presence
- **Existing OAuth integrations** — destination nodes resolve `integration_id` via `loadIntegrationConnection()` (already works for org/team/project)

### New libs / no new external deps required

---

## 14. Success Criteria

### Quantitative
- **All 4 features migrated** (notifications, PR check, policy, status) — old code editors deleted from the codebase
- **Test run feature works** for at least one flow of each type
- **Async PR check completes within 30s** of webhook receipt for typical flows
- **Multiplayer editing tested** with 2 simultaneous users without conflicts

### Qualitative
- **Henry can rebuild every existing JS rule as a flow** without using the code escape hatch (proves the node library is sufficient)
- **Looking at the canvas, Henry can immediately understand what a flow does** without reading any code
- **A new user (or AI agent) can create a useful notification flow in <5 minutes** without docs

### Concrete acceptance criteria for "done"
1. Create a notification flow with trigger + filter + Slack destination → fires on real event → message arrives in Slack
2. Create a PR check flow that blocks PRs with critical vulns → real PR with vulnerable dep → check run shows failure within 30s
3. Create a policy flow that denies any GPL-licensed package → extraction picks up GPL package → marked non-compliant
4. Create a status flow that aggregates dep counts → triggers on extraction complete → project status updates
5. Test Run modal works for all four flow types
6. Notification history page shows last 50 flow runs with full traces
7. Multiplayer editing tested with two browser windows on the same flow
8. Old tables (`organization_notification_rules`, `organization_pr_checks`, `package_policy_code`, `project_status_code`) dropped from schema
9. Old code editor files removed from frontend (`PoliciesPage.tsx` PR check tab, etc.)

---

## 15. Open Questions

1. **Code node sandbox** — reuse the existing `executePolicyFunction()` sandbox, or build a fresh one with better isolation? (Lean: reuse — already battle-tested.)
2. **Template field syntax** — Handlebars (`{{ field.name }}`) vs JSONPath vs custom? (Lean: Handlebars — most users have seen it.)
3. **Filter expression UI** — single rule chain (Datadog style) vs nested groups (Notion filter style) vs JSONLogic editor? (Lean: nested groups for power, with simple chain as the default UX.)
4. **Notification history retention** — 90 days matches existing cleanup. Worth extending to a year for audit needs? (Lean: 90 days, configurable later.)
5. **Per-flow audit log of edits** — `flow_versions` covers this with snapshots. Do we also want a separate "who toggled active when" audit trail? (Probably yes, but lightweight.)
6. **In-app notification destination** — currently in-app notifications are auto-created for all org members. With flows, should "in-app" be an explicit destination node, or stay implicit? (Lean: explicit — gives users control over when in-app notifications fire.)
7. **PR check flow that fails to evaluate** — what does the check run show? Pass-by-default (fail open) or block (fail closed)? (Lean: fail closed for security; surface the error in the check summary.)

---

## 16. Scope: MVP vs Full

### Phase 1 (MVP) — must ship together
- `flows`, `flow_versions`, `flow_runs`, `flow_node_executions` tables
- Drop old tables (clean cutover)
- Backend flow evaluator engine (walks graph, executes nodes)
- Async PR check execution path
- Canvas editor with all 30 nodes from the library
- Right-panel node config UI (form generated per node type)
- Save / version history / revert
- Test Run modal (both sample picker + mock builder)
- Notification History page with execution traces
- All 4 flow types working (notification, PR check, policy, status)
- Multiplayer editing (reuse org graph)
- Settings pages refactored as flow lists

### Phase 2 (post-MVP, soon)
- Visual run inspector (click a flow run → see canvas with highlighted path + values on hover)
- Template gallery for common flows
- Flow composition (`action.call_flow`)
- API trigger nodes (make a flow externally callable)
- AI-assisted flow building ("Build a flow that…" → generates initial graph)

### Phase 3 (future / out of scope)
- Flow marketplace (share flows publicly)
- Per-tenant custom node types (let users define reusable sub-flows as nodes)
- Visual flow diff (compare two versions side-by-side)
- Real-time analytics dashboard per flow (run rate, failure rate, latency)

### Phased rollout strategy
Since Henry is the only user pre-launch, no need for feature flags or gradual rollout. Build the whole MVP, cut over in a single deploy, delete the old code.
