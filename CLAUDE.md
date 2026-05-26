# Deptex System Reference

Deptex is an AI-powered open-core dependency security platform. It combines dependency intelligence, continuous supply-chain monitoring, policy-as-code, and an autonomous AI security agent (Aegis) to automate software security for organizations.

---

## Conventions

- Use git bash, not PowerShell
- Backend: `cd backend && npm run dev` (port 3001). Frontend: `cd frontend && npm run dev` (port 3000)
- API routes: add to `backend/src/routes/`, register in `backend/src/index.ts`
- DB migrations: `backend/database/` (~140 SQL files). **If you add or modify a migration, also run `cd depscanner && npm run schema:dump` in the same PR to refresh `backend/database/schema.sql`.** That file is the source of truth for PGLite local-mode (depscanner CLI + CI smoke tests). CI (`.github/workflows/schema-check.yml`) fails PRs that touch a migration without refreshing it.
- UI components: Radix primitives + Tailwind (shadcn pattern). Add via `npx shadcn@latest`
- See `DEVELOPERS.md` for full setup, `CONTRIBUTING.md` for PR flow, `fly.md` for Fly.io deployment
- See `.cursor/skills/add-new-features/SKILL.md` for where to add routes and libs
- See `.cursor/skills/frontend-design/SKILL.md` and `.cursor/skills/ui-principles/SKILL.md` for UI standards
- See `docs/flow-code-sandbox.md` before changing the flow / policy code execution sandbox (isolated-vm setup, exposed helpers, return cap)
- Dogfood corpus: `depscanner/test-repos/` holds 12 hand-authored framework fixtures (one per ecosystem we ship), each seeded with intentional vulnerabilities across every scanner category. `npm run dogfood:check` (in `depscanner/`) is the executable cross-batch regression gate; the runbook for the end-to-end manual walkthrough is `docs/runbooks/depscanner-dogfood.md`. Don't modify the upstream taint-engine fixtures in `depscanner/fixtures/test-*` — those are byte-stable inputs for the snapshot suite. The dogfood copies are intentionally separate.
- Roadmap: `.cursor/plans/deptex_projects_roadmap_index.plan.md`

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend API | Express + TypeScript (ES2020, CommonJS) |
| Database | PostgreSQL via Supabase (`@supabase/supabase-js`, service role key) |
| Auth | Supabase Auth (JWT Bearer tokens, Google/GitHub OAuth) |
| Realtime | Supabase Realtime (subscription to DB changes) |
| Frontend | React 18 + Vite 5 + Tailwind CSS 3 + Radix UI primitives (shadcn pattern) |
| Routing | React Router v6 (`createBrowserRouter`) |
| Graphs | @xyflow/react (dependency + vulnerability graphs) |
| Code editor | Monaco Editor (policy code) |
| Workers | 2 workers on Fly.io: depscanner (formerly extraction-worker; v1 runs extraction, v2 adds DAST), fix-worker (Aegis Fix Agent) |
| SBOM | cdxgen (CycloneDX). dep-scan (VDR, reachability). Semgrep, TruffleHog |
| AST parsing | web-tree-sitter (WASM) — 8 languages (JS/TS, Python, Java, Go, Ruby, PHP, Rust, C#), 34 framework detectors |
| Queues | Upstash QStash (async jobs, cron schedules) |
| Cache | Upstash Redis |
| AI | Platform-key only (we pay). Gemini Flash via `getPlatformProvider()`; OpenAI/Anthropic/Google for Aegis + Aider via `getPlatformKeyForProvider()` reading `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from the worker env. BYOK was retired in `phase29_drop_byok.sql`. |
| AI - Agent | Vercel AI SDK (`ai`, `@ai-sdk/openai`, `@ai-sdk/anthropic`, `@ai-sdk/google`). Frontend: `@ai-sdk/react` useChat |
| Deployment | Fly.io (workers, scale-to-zero), Supabase (DB + auth), Vercel-style frontend |

---

## Architecture Overview

```
backend/
  src/
    index.ts              Express entry, all routes mounted here
    routes/               API route handlers (orgs, teams, projects, aegis, workers, webhooks, etc.)
    lib/                  Shared libraries (ai/, aegis/, learning/, github, policy-engine, etc.)
    middleware/            auth.ts (JWT), ip-allowlist.ts
  database/               ~140 SQL migration files
depscanner/             Unified scanner worker. Extraction (clone + cdxgen + dep-scan + tree-sitter + framework detection + Semgrep + TruffleHog) today; DAST (ZAP) added in Phase 23+. Single Fly app `deptex-depscanner` with type-aware dispatch on scan_jobs.type. Fly.io scale-to-zero.
fix-worker/             Aegis Fix Agent — plan-then-execute coding agent (Fly.io scale-to-zero)

frontend/src/
  main.tsx                RouterProvider entry
  contexts/AuthContext.tsx Supabase session, OAuth
  app/routes.tsx          All route definitions
  app/pages/              Page components
  components/             Shared components (supply-chain/, vulnerabilities-graph/, etc.)
```

---

## Auth Flow

1. Frontend: Google/GitHub OAuth via Supabase Auth -> JWT
2. API calls: `Authorization: Bearer <jwt>`
3. Backend: `authenticateUser` middleware -> `req.user = { id, email }`. `optionalAuth` variant doesn't fail on missing token.
4. Frontend: `ProtectedRoute` redirects unauthenticated to `/`, `PublicRoute` redirects authenticated to `/organizations`

---

## RBAC & Permissions

**Roles are permission bundles, not a fixed ladder.** Each role is a row in `organization_roles` (org-scoped) carrying a `permissions` JSONB; `organization_members.role` stores the role *name*. `owner` is the only structural role — all permissions, cannot be removed. Org creation seeds exactly two default roles, `owner` and `member`; **there is no built-in `admin` role**, and orgs add/rename/delete their own roles freely. Authorize by checking the relevant permission key in the role's `permissions` JSONB (`owner` always passes) — never by matching a role *name* (`role === 'admin'` is a legacy bug: a non-existent role name).

**Organization permission keys** (`organization_roles.permissions` JSONB):
- `manage_organization_settings`, `manage_integrations`, `manage_members`, `manage_policies`, `manage_notifications`, `manage_statuses`, `manage_teams_and_projects`, `view_all_teams_and_projects`, `view_settings`, `view_activity`, `view_members`, `add_members`, `kick_members`, `edit_roles`, `edit_permissions`
- AI & Aegis: `interact_with_aegis`, `manage_aegis`, `trigger_fix`, `view_ai_spending`, `manage_incidents`

**Team roles** (`team_roles.permissions` JSONB):
- `manage_projects`, `manage_members`, `manage_settings`, `manage_integrations`, `manage_notifications`

Note: `owner` is the only role guaranteed by name. The org-identity edits in General settings (name / avatar / transfer / delete) are owner-only.

---

## AI Architecture (Platform-Key Only)

- All AI calls run on Deptex-owned platform keys.
- Gemini Flash via `getPlatformProvider()` for docs assistant, policy AI, notification AI, usage analysis (when `GOOGLE_AI_API_KEY` is set).
- Aegis + EPD + rule generation pick provider via `getPlatformKeyForProvider()` (`backend/src/lib/aegis/llm-provider.ts`), which reads `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from the worker env.
- Rate limits: per-feature daily (5–50/day), Aegis 200 msg/day, 5 concurrent, monthly cost cap on Redis (`ai:cost:{orgId}:*`).
- BYOK (per-organization customer keys + `organization_ai_providers` + `AI_ENCRYPTION_KEY` envelope) was retired in `phase29_drop_byok.sql`. `AI_ENCRYPTION_KEY` env var is still required because the IaC-v2 registry credentials table reuses the same encryption helper.

---

## Key Data Flows

### Extraction Pipeline
```
Connect repo -> queueExtractionJob() inserts scan_jobs (type='extraction'), starts Fly.io depscanner machine
  -> Worker claims via claim_scan_job(machine_id, ['extraction']) RPC (atomic, FOR UPDATE SKIP LOCKED)
  -> Clone -> cdxgen SBOM -> parse deps -> upsert -> tree-sitter usage extraction + framework entry points -> dep-scan
  -> atom reachable flows + reachability_rules (Semgrep taint packs, per-CVE, upgrades matching PDVs to `confirmed`)
  -> updateReachabilityLevels classifier -> Semgrep SAST -> TruffleHog
  -> Logs stream to extraction_logs (Supabase Realtime)
  -> QStash: populate-dependencies (registry + GHSA + OpenSSF + policy eval + health score)
  -> QStash: backfill-dependency-trees (transitive edges via pacote)
  -> Fault tolerance: 60s heartbeat, 5min stuck detection, recovery cron, max 3 attempts
```

Reachability rule packs live in `depscanner/reachability-rules/` — one folder per CVE (`CVE-YYYY-NNNNN-<slug>/rule.yml` + fixtures). See that directory's README for authoring conventions. `scripts/validate-reachability-rules.ts` runs in CI and fails on malformed/missing rules.

### Aegis AI Agent
```
POST /api/aegis/v2/stream (AI SDK SSE, useChat on frontend)
  -> platform-key model via llm-provider.ts, pgvector memory context
  -> Vercel AI SDK streamText(maxSteps) with 50+ tools across 10 categories
  -> Tool permission checks (RBAC + danger level), approval flow for dangerous tools
  -> Task system: plan-then-execute with QStash step execution, circuit breaker
  -> Sprint orchestration: batch fix discovery and AI fix scheduling
```

### Policy Engine
```
Org-level: package_policy_code (per-dep), project_status_code (assigns status), pr_check_code (PR blocking)
  -> Sandboxed execution (isolated-vm or Function fallback)
  -> Policy evaluation runs after populate-dependencies
  -> Change history in organization_policy_changes
```

### Webhooks (GitHub/GitLab/Bitbucket)
```
Push -> detectAffectedWorkspaces() -> queueExtractionJob() if sync_frequency=on_commit
PR -> check runs + smart comments + policy engine + PR tracking
```

---

## Key Environment Variables

| Variable | Purpose |
|----------|---------|
| `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY` | Database, auth, realtime, storage |
| `SUPABASE_JWT_SECRET` | Project JWT secret (HS256). When set, the auth middleware verifies access tokens locally instead of calling the Supabase auth server — one fewer round trip per request. Falls back to `getUser` when unset. |
| `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY` | Async job dispatch |
| `UPSTASH_REDIS_URL`, `UPSTASH_REDIS_TOKEN` | Caching, job queues |
| `FLY_API_TOKEN`, `FLY_DEPSCANNER_APP` (fallback: `FLY_EXTRACTION_APP`), `FLY_FIX_APP` | Worker machine management |
| `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` | GitHub App (webhook secret required in prod) |
| `GOOGLE_AI_API_KEY` | Platform Gemini Flash key |
| `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` | Platform OpenAI / Anthropic keys (used by Aegis, EPD Anthropic fallback, rule generation) |
| `AI_ENCRYPTION_KEY` | AES-256-GCM key for `organization_registry_credentials` (32-byte hex). Reused encryption helper after BYOK retirement. |
| `INTERNAL_API_KEY` | Protects internal/worker API endpoints |

---

## Depscore

Composite vulnerability priority score. Uses `projects.importance` (a numeric scalar in `[0.5, 2.0]`, default `1.0`) multiplied directly into the score as `tierWeight` — no enum, no lookup table. Tiered `reachabilityLevel` weights: confirmed=1.0, data_flow=0.9, function=0.7, module=0.5. EPD contextual scoring adds `epd_factor` for execution path dominance. (The legacy `asset_tier` enum + `organization_asset_tiers` table were dropped in `phase41_drop_asset_tiers.sql`.)

---

## Migrations

All SQL migrations live in `backend/database/`. Files are prefixed by their original feature phase (e.g. `phase7b_aegis_platform.sql`, `phase18_epd_scoring.sql`); the prefix is historical and stable but carries no load-bearing ordering beyond what the filenames themselves imply. For a fresh install, run them in filename-sorted order. A dedicated migration runner is tracked for self-hosting readiness.

Historical plan documents for each feature phase are archived in `.cursor/plans/archive/`.
