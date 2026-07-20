# Aegis Backend Cleanup — Removal Mapping

Branch: `chore/backend-cleanup`. Open-source-release cleanup of the Aegis
surface: delete verified-dead v2 code, cut five retired platform features
end-to-end, and (Stage 2) unify `lib/aegis-v3` into `lib/aegis`.
(The previous contents of this file — the DB naming-realignment mapping —
shipped with PR #149 and remain in git history.)

Ground truth verified before any deletion:

- The LIVE chat is **v3**: frontend posts to `/api/aegis/v3/stream` +
  `/regenerate`; backend `routes/aegis-v3.ts` + `lib/aegis-v3/*`.
- The LIVE Task agent is `lib/aegis/tasks.ts` + the consolidated
  `lib/aegis/tools/` category modules (via `buildToolSet`) + the `/tasks/*`
  routes in `routes/aegis.ts` + `/api/internal/aegis/execute-task-step`.
- Four `lib/aegis/` files are SHARED with the live v3 chat:
  `llm-provider.ts`, `provider.ts`, `participants.ts`, `types.ts`
  (verified: these are the only `lib/aegis/*` imports in `lib/aegis-v3/*`,
  `routes/aegis-v3.ts`, and `routes/aegis-fix.ts`).

---

## 1. Verified-dead v2 code deleted (0 importers each, checked repo-wide)

### Backend `lib/aegis/`

| File | Note |
|---|---|
| `queue.ts` | v1 message queue; imported executor (also dead) |
| `chat.ts` | v1 chat entry; imported system-prompt |
| `system-prompt.ts` | hyphenated file, only importer was `chat.ts` (NOT the camelCase `systemPrompt.ts`, which fell to the cascade below) |
| `pr-review.ts` | superseded PR-review path; no importer |

### The 12 dead per-tool factory files in `lib/aegis/tools/`

`analyze-upgrade-path.ts`, `check-cisa-kev.ts`, `get-epss-score.ts`,
`get-package-reputation.ts`, `get-project-summary.ts`,
`get-project-vulnerabilities.ts`, `get-reachability-flows.ts`,
`get-security-posture.ts`, `get-vulnerability-detail.ts`, `list-policies.ts`,
`list-project-dependencies.ts`, `list-projects.ts` — superseded by the
consolidated category modules (`security-ops.ts`, `intelligence.ts`,
`project-ops.ts`, …), which register same-named tools in the registry. None
of the 12 was imported anywhere (they never appeared in `tools/index.ts`).

### Dead frontend

- `frontend/src/lib/aegis-stream.ts` (0 importers) and the
  `streamAegisMessage` method in `frontend/src/lib/api.ts` (only caller was
  aegis-stream.ts; it targeted `/api/aegis/stream`, a route that no longer
  exists).

---

## 2. The five cut features (full surface per feature)

### 2a. Automations (cron)

- **Lib:** `lib/aegis/automations-engine.ts`; `lib/aegis/tools/automation.ts`
  (tools `createScheduledJob` / `updateScheduledJob` / `deleteScheduledJob`;
  names removed from `TOOL_PROFILES.admin`, `'automation'` removed from the
  `ToolCategory` union, import removed from `tools/index.ts`).
- **Routes:** `routes/aegis.ts` — `GET /automations/:organizationId`,
  `POST /automations`, `PUT /automations/:id`, `DELETE /automations/:id`,
  `POST /automations/:id/run`. `routes/aegis-task-step.ts` —
  `POST /check-due-automations`, `POST /run-automation/:id`.
  `routes/cron-dispatcher.ts` — removed `/api/internal/aegis/check-due-automations`
  from the every-5-min fan-out.
- **Frontend:** Automations tab in
  `components/settings/AegisManagementConsole.tsx` (TABS entry, state,
  loaders, tab body, TOOL_CATEGORIES row); `api.ts` methods
  `getAegisAutomations` / `createAegisAutomation` / `updateAegisAutomation` /
  `deleteAegisAutomation` / `runAegisAutomation` + `AegisAutomation` type.
- **DB:** `aegis_event_triggers` dropped (phase75; its only reader was
  automations-engine). `aegis_automations` / `aegis_automation_jobs` needed no
  drop — already dropped in prod by `drop_aegis_tables.sql` /
  `phase20_aegis_v2_cleanup.sql` (they were absent from `schema.sql`; the
  route code deleted here had been writing to non-existent tables).
- **Tests:** backend `aegis-platform.test.ts` Automations describe; frontend
  `aegis-platform.test.tsx` test 99 + `getAegisAutomations` mocks (also in
  `incident-response-ui.test.tsx`).

### 2b. Slack bot

- **Lib:** `lib/aegis/slack-bot.ts`.
- **Routes:** `routes/aegis.ts` — `POST /slack/events`,
  `POST /slack/interactions`. (These were the only `express.raw`/`urlencoded`
  users in the file; the `express` default import was dropped accordingly.)
- **Frontend:** none existed (the Slack card on IntegrationsPage is the
  *notifications* Slack integration — a different, kept feature).
- **DB:** `aegis_slack_config` dropped (phase75; only reader was slack-bot).

### 2c. Sprint orchestration

- **Lib:** `lib/aegis/sprint-orchestrator.ts`.
- **Routes:** `routes/aegis.ts` — `POST /sprints/:organizationId`,
  `POST /sprints/:organizationId/confirm`,
  `GET /sprints/:organizationId/:taskId/summary`; plus the local
  `hasPermission()` helper whose only callers were the sprint routes.
- **DB:** none (sprints were rows in the kept `aegis_tasks`/`aegis_task_steps`).
- **Tests:** backend `aegis-platform.test.ts` Sprint Orchestration describe.
- **KEPT deliberately:** the `createSecuritySprint` / `getSprintStatus` tools
  inside `lib/aegis/tools/security-ops.ts`. They are "sprint" in name only —
  they operate purely on the kept `aegis_tasks`/`aegis_task_steps` tables,
  import nothing from the orchestrator, are referenced in
  `TOOL_PROFILES.security`, and are part of the consolidated `tools/` modules
  the Task agent uses. Cutting them would change the live Task agent's
  toolset beyond the approved anchors. Flagged for a separate owner decision.

### 2d. Security-debt snapshots

- **Lib:** `lib/aegis/security-debt.ts`.
- **Routes:** `routes/aegis.ts` — `GET /debt/:organizationId`;
  `routes/aegis-task-step.ts` — `POST /snapshot-debt`;
  `routes/cron-dispatcher.ts` — removed `/api/internal/aegis/snapshot-debt`
  from the daily fan-out.
- **Frontend:** none existed.
- **DB:** `security_debt_snapshots` dropped (phase75; only reader/writer was
  security-debt.ts).
- **Tests:** backend `aegis-platform.test.ts` Security Debt describe.

### 2e. Incident playbooks — **Aegis chat-tool surface only**

- **Cut:** `lib/aegis/tools/incidents.ts` (chat/agent tools `declareIncident`,
  `getIncidentStatus`, `listActiveIncidents`; names removed from
  `TOOL_PROFILES.security`, import removed from `tools/index.ts`).
- **KEPT — the broader incident-response feature** (flagged per instructions):
  - `lib/incident-engine.ts` — although its header says "playbook execution",
    it is **load-bearing for the kept feature**: `routes/incidents.ts` calls
    `declareIncident` / `resolveIncident` / `addTimelineEvent`, and
    `lib/incident-triggers.ts` (notification-event triggers) calls
    `declareIncident`. It could not be removed without cutting the broader
    feature, which is out of scope.
  - `lib/incident-triggers.ts`, `lib/incident-templates.ts`,
    `lib/incident-postmortem.ts`, `routes/incidents.ts`,
    `routes/incident-cron.ts`, the `manage_incidents` permission, and the
    Incidents tab (`IncidentResponseSection`) in the Aegis Management Console
    (it reads the org-scoped `/api/organizations/:orgId/incidents*` routes,
    not any Aegis route).
  - The `__incident_id` step-completion hook inside
    `routes/aegis-task-step.ts` `/execute-task-step` — the kept
    incident-engine creates aegis tasks whose steps carry `__incident_id`,
    so the hook is part of the kept feature's execution path.
  - **Known pre-existing inconsistency (not introduced here):** the broader
    incident feature's tables (`security_incidents`, `incident_playbooks`,
    `incident_timeline`) were dropped from prod by
    `phase20_aegis_v2_cleanup.sql` and are absent from `schema.sql`, yet the
    kept code still queries them. Left exactly as found; a decision on the
    broader incidents feature is the owner's call.

---

## 3. Dependency cascade (verified before deletion)

`lib/aegis/executor.ts` was imported only by `slack-bot.ts`,
`automations-engine.ts`, and `queue.ts` — all removed above. That freed:

- `executor.ts` (deleted),
- `lib/aegis/systemPrompt.ts` (only importer: executor),
- `lib/aegis/actions/` — `index.ts`, `init.ts`, `members.ts`, `policies.ts`,
  `security.ts`, `teams.ts` (only importer: executor).

`tasks.ts` and the consolidated `tools/` modules were NOT touched (live Task
agent), other than the registry index/profile edits listed above.

---

## 4. DB migration

`backend/database/phase75_drop_aegis_platform_features.sql` — drops exactly
`aegis_event_triggers`, `aegis_slack_config`, `security_debt_snapshots`
(the only cut-feature tables that still exist; each had a single code
owner, deleted above). `backend/database/schema.sql` hand-edited to match
(3 CREATE TABLE blocks, 9 constraints, 4 indexes — 42 lines; `schema:dump`
deliberately NOT run, it pulls prod drift). Historic migrations that created
these tables are immutable history and untouched; on a fresh
filename-ordered install phase75 runs last and drops them.

Kept tables (per scope): `aegis_tasks`, `aegis_task_steps`, `aegis_chat_*`,
`aegis_memory`, `aegis_tool_executions`, `aegis_org_settings`,
`aegis_approval_requests`, `aegis_activity_logs`, `aegis_inbox`,
`aegis_config`. (Several of these are themselves absent from prod/schema.sql
— dropped historically by phase20 and never re-created — but "keep" here
means "no drop statement"; their code paths are untouched.)

---

## 5. Other KEPT-and-flagged items

- **`AegisManagementConsole.tsx` is orphaned UI**: its only importers are two
  test files — no live page renders it. Kept (minus the Automations tab)
  because deleting an entire console is an ownership call beyond this
  cleanup's approved scope.
- **`api.ts` `sendAegisMessage`** posts to `/api/aegis/handle`, a route that
  does not exist; it has no callers. Outside the approved dead-code list, so
  kept and flagged.
- **`match_aegis_memories` function in `schema.sql`** references the
  `aegis_memory` table which is absent from schema.sql (pre-existing prod
  drift, predates this change). Untouched.
- **v2 route surface under `/api/aegis`** (threads CRUD, invite codes,
  status/enable, activity, inbox, tasks, approvals, memory, settings,
  tool-executions, spending, usage-stats, threads-by-project) — all kept;
  the thread routes back the live chat sidebar and the task routes back the
  Task agent.

---

## 6. Verification — Stage 1 (all from inside the worktree)

- `backend`: `npx tsc --noEmit` — 0 errors other than 2 pre-existing TS2742
  junction-environment artifacts (`llm-provider.ts`, `provider.ts`; the
  baseline's other TS2742 artifacts lived in files deleted here).
- `frontend`: `npx tsc --noEmit -p tsconfig.json` — clean (exit 0).
- `backend`: `npx jest --no-coverage` — **220 suites passed / 2 skipped,
  3503 tests passed / 12 skipped, 0 failures**.
- `frontend`: `npx vitest run` — **57 files passed / 1 skipped, 563 tests
  passed / 23 skipped, 0 failures**.
