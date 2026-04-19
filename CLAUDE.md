# Deptex System Reference

Deptex is an AI-powered open-core dependency security platform. It combines dependency intelligence, continuous supply-chain monitoring, policy-as-code, and an autonomous AI security agent (Aegis) to automate software security for organizations.

---

## Conventions

- Use git bash, not PowerShell
- Backend: `cd backend && npm run dev` (port 3001). Frontend: `cd frontend && npm run dev` (port 3000)
- API routes: add to `backend/src/routes/`, register in `backend/src/index.ts`
- DB migrations: `backend/database/` (~140 SQL files)
- UI components: Radix primitives + Tailwind (shadcn pattern). Add via `npx shadcn@latest`
- See `DEVELOPERS.md` for full setup, `CONTRIBUTING.md` for PR flow, `fly.md` for Fly.io deployment
- See `.cursor/skills/add-new-features/SKILL.md` for where to add routes and libs
- See `.cursor/skills/frontend-design/SKILL.md` and `.cursor/skills/ui-principles/SKILL.md` for UI standards
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
| Tables | @tanstack/react-table |
| Code editor | Monaco Editor (policy code) |
| Forms | react-hook-form + zod validation |
| Workers | 4 Node.js workers: extraction, parser, watchtower-worker, watchtower-poller |
| SBOM | cdxgen (CycloneDX). dep-scan (VDR, reachability). Semgrep, TruffleHog |
| AST parsing | oxc-parser (JS/TS import extraction) |
| Queues | Upstash QStash (async jobs, cron schedules) |
| Cache | Upstash Redis |
| AI - Tier 1 | Google Gemini Flash (platform features, we pay). `getPlatformProvider()` in `backend/src/lib/ai/provider.ts` |
| AI - Tier 2 | BYOK OpenAI/Anthropic/Google (Aegis, Aider). `organization_ai_providers`, AES-256-GCM encrypted keys |
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
  extraction-worker/      Clone + cdxgen + dep-scan + AST + Semgrep + TruffleHog (Fly.io scale-to-zero)
  parser-worker/          Standalone AST import analysis (oxc-parser)
  watchtower-worker/      Supply-chain forensic analysis
  watchtower-poller/      Deprecated for prod; QStash cron replaces it
  aider-worker/           AI-powered fix worker (Aider/Python on Fly.io)
  database/               ~140 SQL migration files

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

**Organization roles** (`organization_roles.permissions` JSONB):
- `manage_teams_and_projects`, `view_all_teams_and_projects`, `manage_organization_settings`, `manage_integrations`, `manage_members`, `manage_policies`, `manage_notifications`, `manage_statuses`, `view_activities`
- AI & Aegis: `interact_with_aegis`, `manage_aegis`, `trigger_fix`, `view_ai_spending`, `manage_incidents`

**Team roles** (`team_roles.permissions` JSONB):
- `manage_projects`, `manage_members`, `manage_settings`, `manage_integrations`, `manage_notifications`

**Defaults:** Owner (all), Admin (all except transfer), Member (view only)

---

## AI Architecture (Two-Tier)

- **Tier 1 (Platform):** Gemini Flash for docs assistant, policy AI, notification AI, usage analysis. We pay (~$0.0001/call). `getPlatformProvider()` when `GOOGLE_AI_API_KEY` set.
- **Tier 2 (BYOK):** Org-configured OpenAI/Anthropic/Google for Aegis + Aider fixes. Keys encrypted with `AI_ENCRYPTION_KEY` (AES-256-GCM). `getProviderForOrg()`.
- Rate limits: Tier 1 per-feature (5-50/day). Tier 2 Aegis 200 msg/day, 5 concurrent, monthly cost cap (Redis).

---

## Key Data Flows

### Extraction Pipeline
```
Connect repo -> queueExtractionJob() inserts extraction_jobs, starts Fly.io machine
  -> Worker claims via claim_extraction_job RPC (atomic, FOR UPDATE SKIP LOCKED)
  -> Clone -> cdxgen SBOM -> parse deps -> upsert -> AST analysis -> dep-scan -> Semgrep -> TruffleHog
  -> Logs stream to extraction_logs (Supabase Realtime)
  -> QStash: populate-dependencies (registry + GHSA + OpenSSF + policy eval + health score)
  -> QStash: backfill-dependency-trees (transitive edges via pacote)
  -> Fault tolerance: 60s heartbeat, 5min stuck detection, recovery cron, max 3 attempts
```

### Aegis AI Agent
```
POST /api/aegis/v2/stream (AI SDK SSE, useChat on frontend)
  -> BYOK model via llm-provider.ts, pgvector memory context
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
| `QSTASH_TOKEN`, `QSTASH_CURRENT_SIGNING_KEY`, `QSTASH_NEXT_SIGNING_KEY` | Async job dispatch |
| `UPSTASH_REDIS_URL`, `UPSTASH_REDIS_TOKEN` | Caching, job queues |
| `FLY_API_TOKEN`, `FLY_EXTRACTION_APP`, `FLY_AIDER_APP` | Worker machine management |
| `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY`, `GITHUB_WEBHOOK_SECRET` | GitHub App (webhook secret required in prod) |
| `GOOGLE_AI_API_KEY` | Tier 1 AI (Gemini Flash) |
| `AI_ENCRYPTION_KEY` | BYOK key encryption (32-byte hex, required for Tier 2) |
| `INTERNAL_API_KEY` | Protects internal/worker API endpoints |

---

## Depscore

Composite vulnerability priority score. Uses `tierMultiplier` from `organization_asset_tiers` (project's `asset_tier_id`). Tiered `reachabilityLevel` weights: confirmed=1.0, data_flow=0.9, function=0.7, module=0.5. EPD contextual scoring (Phase 18) adds `epd_factor` for execution path dominance.

---

## Phase Status

Completed: 6B, 6C, 7, 9, 10, 14, 16, 17. Refined (impl done): 7B (tests pending). Outline: 13, 15, 18.
Full roadmap: `.cursor/plans/deptex_projects_roadmap_index.plan.md`

---

## Migration Reference

Migrations live in `backend/database/`. Key migrations by phase:
- **6B:** `phase6b_reachability_tables.sql`
- **6C:** `aegis_chat_threads_schema.sql` (prereq), `phase6c_ai_infrastructure.sql`
- **7:** `phase7_ai_fix.sql`
- **7B:** Run in order: `aegis_chat_threads_schema.sql`, `aegis_chat_messages_schema.sql`, `aegis_automations_schema.sql`, `phase6c_ai_infrastructure.sql`, `phase7b_aegis_platform.sql`
- **8:** `phase8_migrations.sql`, `phase8_project_commits.sql`, `phase8_webhook_deliveries.sql`, `phase8_project_pull_requests.sql`
- **9:** `phase9_notifications.sql`
- **10:** `phase10_gin_index.sql`
- **14:** `phase14_enterprise_security.sql`
- **16:** `phase16_aegis_learning.sql`
- **17:** `phase17_incident_response.sql`
- **18:** `phase18_epd_scoring.sql`
