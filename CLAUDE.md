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
- `manage_organization_settings`, `manage_integrations`, `manage_members`, `manage_policies`, `manage_notifications`, `manage_statuses`, `manage_teams_and_projects`, `view_settings`, `view_activity`, `view_members`, `add_members`, `kick_members`, `edit_roles`, `edit_permissions`
- AI & Aegis: `interact_with_aegis`, `manage_aegis`, `trigger_fix`, `view_ai_spending`, `manage_incidents`
- Billing: `manage_billing` — gates top-up, payment-method CRUD, auto-recharge config, receipt download. Required to be included in billing-alert email recipients.

**Team roles** (`team_roles.permissions` JSONB):
- `manage_projects`, `manage_members`, `manage_settings`, `manage_integrations`, `manage_notifications`

Note: `owner` is the only role guaranteed by name. The org-identity edits in General settings (name / avatar / transfer / delete) are owner-only.

---

## AI Architecture (Platform-Key Only)

- All AI calls run on Deptex-owned platform keys.
- Gemini Flash via `getPlatformProvider()` for docs assistant, policy AI, notification AI, usage analysis (when `GOOGLE_AI_API_KEY` is set).
- Aegis + EPD + rule generation pick provider via `getPlatformKeyForProvider()` (`backend/src/lib/aegis/llm-provider.ts`), which reads `OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from the worker env.
- Rate limits: per-feature daily (5–50/day), Aegis 200 msg/day, 5 concurrent. **Cost enforcement is via the prepaid billing ledger** (see Prepaid Billing below) — the legacy Redis `ai:cost:{orgId}:*` cap was retired with the prepaid rewrite.
- BYOK (per-organization customer keys + `organization_ai_providers` + `AI_ENCRYPTION_KEY` envelope) was retired in `phase29_drop_byok.sql`. `AI_ENCRYPTION_KEY` env var is still required because the IaC-v2 registry credentials table reuses the same encryption helper.

---

## Key Data Flows

### Extraction Pipeline
```
Connect repo -> queueExtractionJob() inserts scan_jobs (type='extraction'), starts Fly.io depscanner machine
  -> Worker claims via claim_scan_job(machine_id, ['extraction']) RPC (atomic, FOR UPDATE SKIP LOCKED)
  -> Clone -> cdxgen SBOM -> parse deps -> upsert -> tree-sitter usage extraction + framework entry points -> dep-scan
  -> AI rule generation -> cross-file taint engine (framework-models/*.yaml specs: sources/sinks/sanitizers per vuln_class, upgrades matching PDVs to `confirmed`)
  -> updateReachabilityLevels classifier + EPD -> IaC/container + malicious-package + Semgrep SAST + TruffleHog
  -> Logs stream to extraction_logs (Supabase Realtime)
  -> QStash: populate-dependencies (registry + GHSA + OpenSSF + policy eval + health score)
  -> QStash: backfill-dependency-trees (transitive edges via pacote)
  -> Fault tolerance: 60s heartbeat, 5min stuck detection, recovery cron, max 3 attempts
```

Reachability comes from the cross-file taint engine (`depscanner/src/taint-engine/`): per-framework specs in `framework-models/*.yaml` declare sources, sinks (tagged with `vuln_class`), and sanitizers, and the framework spec loads alongside the stdlib spec (e.g. `node-stdlib.yaml`) so taint can flow across files. `npm run taint-engine:validate` runs the spec/fixture validation harness; the per-language `test:taint-engine-*` suites cover propagation.

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

### Prepaid Billing
```
Top up:    UI → POST /billing/topup-intent → Stripe createTopUpInvoice (invoice + auto-charge)
                 → payment_intent.succeeded webhook → credit_balance RPC → balance_cents up
Meter:     worker/Aegis → POST /api/internal/billing/meter-event (INTERNAL_API_KEY)
                 → recordMeterEvent → deduct_balance RPC (FOR UPDATE, idempotent on
                   (org, idempotency_key)) → balance_cents down → setImmediate fires
                   maybeAutoRecharge + checkAndDispatchBalanceAlerts
Auto-recharge: balance < auto_recharge_threshold_cents AND rolling-30-day sum +
                 auto_recharge_amount_cents <= auto_recharge_monthly_cap_cents
                 → createTopUpInvoice (off-session) → succeeds = pi_created (webhook credits)
                 → fails inline = disable + void open invoice + sendAutoRechargeFailed
Alerts:    low_balance / zero_balance / credit_added / auto_recharge_failed /
           auto_recharge_cap_reached — Resend (or
           Gmail SMTP fallback) to all org members with manage_billing. Dedup via slot
           columns on organization_billing. Subjects carry UTC timestamp suffix so each
           alert is its own Gmail thread.
Webhooks:  /api/stripe/webhooks — signature verified (rawBodyBuffer), atomic dedup via
           billing_stripe_webhook_events. Handles payment_intent.succeeded,
           payment_intent.payment_failed, invoice.payment_failed,
           invoice.payment_action_required, payment_method.detached, customer.deleted.
           Cross-tenant guard on every credit. Enforcement kill switch checked on
           credit path.
Kill switch: DEPTEX_BILLING_ENFORCEMENT=on enables charges; anything else returns
           enforcement_off and stops all deductions and credits.
Drift cron: POST /api/internal/billing/check-ledger-drift — daily QStash; emails
           BILLING_OPS_ALERT_EMAIL if assert_balance_matches_ledger() returns any rows.
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
| `INTERNAL_API_KEY` | Protects internal/worker API endpoints. Compared in constant time via `middleware/internal-key.ts`; never log fragments. |
| `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET` | Stripe SDK + webhook signature verification. SDK pinned to API version 2026-04-22.dahlia (the account's current version — must be one the account accepts or every call 400s). |
| `RESEND_API_KEY`, `EMAIL_FROM` | Resend transactional email (sender defaults to `Deptex <noreply@deptex.dev>`). When unset, falls back to Gmail SMTP via `EMAIL_USER`/`EMAIL_PASSWORD`. |
| `DEPTEX_BILLING_ENFORCEMENT` | Must equal `on` for charges to actually deduct + Stripe webhooks to credit. Any other value → silent no-op + log line (`enforcement_off`). |
| `BILLING_OPS_ALERT_EMAIL` | Recipient for the daily ledger-drift cron's alert (when set). |
| `SENTRY_DSN` | Sentry error-tracking DSN for backend + both workers. When set, errors are captured + alerted; when unset, the SDK no-ops (local dev / CI / pre-launch). `SENTRY_ENVIRONMENT` + `SENTRY_RELEASE` (git SHA) tag events. |
| `VITE_SENTRY_DSN` | Public Sentry DSN for the frontend (build-time). `VITE_SENTRY_RELEASE` optional. |
| `SENTRY_AUTH_TOKEN`, `SENTRY_ORG`, `SENTRY_PROJECT` | Frontend build/CI only — uploads source maps via `@sentry/vite-plugin`. Absent locally → maps aren't uploaded (gitignored). |

---

## Observability (Sentry)

Errors-only Sentry across all four surfaces (backend API + depscanner + fix-worker + frontend). No performance tracing, no session replay — minimal quota + PII surface. SDK pinned `>= 10.27.0` (avoids CVE-2025-65944).

- **Init:** `instrument.ts` is the first import in each entry point (backend `src/index.ts`, both workers, frontend `main.tsx`). All init no-op without a DSN, so code merges before the Sentry project exists.
- **Secret scrubbing (non-negotiable):** a shared `beforeSend` redactor (`backend/src/lib/observability/scrub.ts`, byte-identical copies in each worker + frontend `src/observability/scrub.ts`) strips secret-shaped strings (JWTs, Stripe/GitHub/AI keys, PEM, Bearer) + values under sensitive keys, drops request bodies/cookies + `user.email`, keeps `user.id` (= org id, for correlation). `sendDefaultPii: false`.
- **What's captured:** the global Express handler + the out-of-Express paths (QStash/BullMQ adapters, self-host-cron, Stripe webhooks); per-job context + process-level `unhandledRejection`/`uncaughtException` + `Sentry.close()` on SIGINT/SIGTERM in both workers; the 16 silent billing money-path failures (auto-recharge, webhook credits/alerts, meter events) via `captureBillingError`; frontend `ErrorBoundary` + route `errorElement` + 5xx API failures.
- **e2e:** `cd backend && npm run e2e:sentry` drives the real `@sentry/node` pipeline and asserts secrets are scrubbed before any event leaves the process + all four scrubber copies agree.
- Datadog/APM deferred until there's traffic. The `billing_events` admin event-log is the fast-follow arc.

---

## Depscore

Composite vulnerability priority score. Uses `projects.importance` (a numeric scalar in `[0.5, 2.0]`, default `1.0`) multiplied directly into the score as `tierWeight` — no enum, no lookup table. Tiered `reachabilityLevel` weights: confirmed=1.0, data_flow=0.9, function=0.7, module=0.5. EPD contextual scoring adds `epd_factor` for execution path dominance. (The legacy `asset_tier` enum + `organization_asset_tiers` table were dropped in `phase41_drop_asset_tiers.sql`.)

---

## Migrations

All SQL migrations live in `backend/database/`. Files are prefixed by their original feature phase (e.g. `phase7b_aegis_platform.sql`, `phase18_epd_scoring.sql`); the prefix is historical and stable but carries no load-bearing ordering beyond what the filenames themselves imply. For a fresh install, run them in filename-sorted order. A dedicated migration runner is tracked for self-hosting readiness.

Historical plan documents for each feature phase are archived in `.cursor/plans/archive/`.
