# Deptex Backend

The core API for **Deptex** — an AI-powered, open-core dependency-security platform: dependency intelligence, continuous supply-chain monitoring, policy-as-code, and the **Aegis** AI security agent.

Open source under **AGPL-3.0** — see [`LICENSE`](../LICENSE). Contributions are accepted under the CLA described in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express + TypeScript (ES2020, CommonJS)
- **Database & Auth**: PostgreSQL via Supabase (service-role key; Supabase Auth JWTs)
- **Async jobs / cache**: Upstash QStash + Redis
- **AI**: Vercel AI SDK (OpenAI / Anthropic / Google) — platform-key only
- **Package manager**: npm

The root [`CLAUDE.md`](../CLAUDE.md) is the deep-architecture reference — key data flows, RBAC, prepaid billing, and observability. This README covers running and navigating the backend and links out to `CLAUDE.md` rather than duplicating it.

## How it fits the system

The backend is the **API layer** of a four-package monorepo. It serves the frontend, owns the database connection, and queues the work the Fly.io workers execute:

```
  React frontend  ──HTTP /api/* (JWT)──▶  Backend API  (this package · Vercel)
        ▲                                       │
        │  Supabase Realtime                    ├──▶  Supabase  (Postgres · Auth · Storage)
        └───────────────────────────────────────┤
                                                 ├──▶  QStash / Redis  (async jobs · cron · cache)
                                                 └──▶  scan_jobs + Fly.io machine boot
                                                          │  claim (FOR UPDATE SKIP LOCKED)
                                                          ▼
                                       depscanner   &   fix-worker   (Fly.io workers)
```

- **`frontend/`** (React + Vite) calls `/api/*` with a Supabase JWT; live UI updates arrive over Supabase Realtime, not from the backend directly.
- **`depscanner/`** (extraction + DAST) and **`fix-worker/`** (the Aegis Fix Agent) are separate Fly.io worker packages. The backend is the *producer*: it inserts `scan_jobs` and boots Fly machines; the workers *claim* jobs and report back over `/api/internal/*` and `/api/workers` (guarded by `INTERNAL_API_KEY` / QStash signatures, not user auth).
- **Supabase** is the database, auth, storage, and realtime layer. The backend connects with the service-role key.

Full data flows (extraction pipeline, Aegis agent, policy engine, billing ledger) live in [`CLAUDE.md`](../CLAUDE.md).

## Setup

### Prerequisites

- Node.js 18+ and npm
- A Supabase project (Postgres + Auth)
- `psql` on your `PATH` (used by the migration runner)

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create your env file. The template lives at the repo root; the backend loads its own `backend/.env`:
   ```bash
   cp ../.env.example .env
   ```
   Fill in at least the Supabase keys (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`), `PORT`, and `FRONTEND_URL` / `BACKEND_URL` — see [Environment variables](#environment-variables).

3. Initialize the database — see [Database & migrations](#database--migrations).

4. In the Supabase dashboard, enable the **Google** and **GitHub** OAuth providers and set the redirect URLs.

### Running the server

```bash
npm run dev         # hot-reload dev server (port 3001)
npm run build       # tsc compile
npm start           # run the compiled server
npm run type-check  # tsc --noEmit
```

## Database & migrations

Migrations live in [`database/`](database/) as ~340 phase-prefixed `.sql` files, applied in filename order. A small runner (`scripts/migrate.ts`, which shells out to `psql`) tracks applied files in a `schema_migrations` table:

```bash
# point at your database (defaults to the local Supabase stack)
export DATABASE_URL=postgres://user:pass@host:5432/dbname

npm run migrate          # apply all pending migrations (includes RLS policies)
npm run migrate:status   # list applied vs pending
```

Run `npm run migrate` against an empty database to build the full schema, **including the row-level-security policies** that isolate multi-tenant data (they matter because the frontend reads some tables directly over Supabase Realtime). Use this path for any hosted deployment.

[`database/schema.sql`](database/schema.sql) is a generated baseline dump that serves as the source of truth for **local mode** (the depscanner PGLite backend) and CI smoke tests. It intentionally omits RLS, so it's a quick single-tenant local-dev shortcut (`psql -f database/schema.sql` then `npm run migrate:baseline`) — **not** a substitute for `npm run migrate` on a real deployment. If you add or change a migration, refresh it with `cd ../depscanner && npm run schema:dump` in the same PR (CI enforces this).

## Testing

```bash
npm test            # Jest — full suite (backend + depscanner + fix-worker share one config)
npm run type-check  # tsc --noEmit
npx jest <path>     # run a single suite
```

Tests live in `__tests__/` directories throughout `src/` (routes, middleware, lib) — ~110 suites covering RBAC / tenant isolation, billing, Aegis, DAST, malicious-package intelligence, and webhook security. `npm run e2e:sentry` drives the real Sentry pipeline and asserts that secrets are scrubbed before any event leaves the process.

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Hot-reload dev server (port 3001) |
| `npm run build` / `npm start` | Compile / run the server |
| `npm run type-check` | `tsc --noEmit` |
| `npm test` | Jest suite |
| `npm run migrate` · `migrate:status` · `migrate:baseline` | Database migrations |
| `npm run e2e:sentry` | End-to-end Sentry secret-scrub check |

Additional ops / e2e scripts (billing reconciliation, fleet probes) live in [`scripts/`](scripts/).

## Code structure

The API is a single Express app. **Every route is mounted in `src/index.ts`** — there's no per-route bootstrapping elsewhere, so if a router isn't in `index.ts`, it isn't served.

```
src/
  index.ts        Express entry — middleware wiring + all route mounts
  instrument.ts   Sentry init (first import; no-ops without a DSN)
  routes/         ~57 routers, one area per file — orgs/teams/projects, auth/SSO/SCIM,
                  findings/SCA, DAST, aegis, billing, integrations + webhooks,
                  workers/cron/internal, notifications, incidents. Add a route here,
                  then register it in index.ts.
  lib/            Shared subsystems — aegis/ (agent + tools), ai/, billing/, malicious/,
                  taint-engine/, learning/, observability/ (Sentry scrub), policy-engine,
                  github/gitlab/bitbucket clients, notification-dispatcher, supabase client
  middleware/     auth.ts (Supabase JWT → req.user), internal-key.ts, ip-allowlist.ts
database/         ~340 SQL migrations + schema.sql (see above)
scripts/          migrate.ts + ops/e2e scripts
```

**Request lifecycle:** `Authorization: Bearer <jwt>` → `authenticateUser` resolves `req.user` → route handler → Supabase (service-role) for data, with RBAC checked by **permission key, never role name** → long-running work handed off to QStash and the Fly.io workers. Internal worker/cron endpoints (`/api/internal/*`, `/api/workers`) skip user auth and are guarded by `INTERNAL_API_KEY` or QStash signatures instead.

Main mount prefixes: `/api/organizations` (the bulk of tenant features), `/api/projects` (DAST), `/api/aegis`, `/api/integrations`, `/api/workers`, `/api/internal/*`, `/api/stripe/webhooks`, plus the auth / user / admin surfaces. The deep architecture is in [`CLAUDE.md`](../CLAUDE.md).

## Authentication

Most `/api/*` endpoints require a Supabase JWT as `Authorization: Bearer <token>`; the `authenticateUser` middleware verifies it (locally via `SUPABASE_JWT_SECRET` when set, otherwise against the Supabase auth server) and populates `req.user`. Personal API tokens (`dptx_`-prefixed) are also accepted. Internal worker / cron endpoints are guarded by `INTERNAL_API_KEY` or QStash signatures instead of user auth.

## Environment variables

The essentials are below; the root [`.env.example`](../.env.example) is the complete list, and `CLAUDE.md` explains what each one gates.

- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY` — database, auth, realtime
- `PORT` — server port (default `3001`)
- `NODE_ENV` — `development` / `production`
- `FRONTEND_URL` — frontend origin for CORS + OAuth redirects (no trailing slash)
- `BACKEND_URL` — backend API base for OAuth callbacks (no trailing slash)

Async jobs, AI, billing, and each integration have their own keys (QStash, Upstash Redis, OpenAI/Anthropic/Google, Stripe, the GitHub App, `INTERNAL_API_KEY`, …) — see the `CLAUDE.md` "Key Environment Variables" table.

## Deployment

The backend and frontend deploy to **Vercel** (the backend runs as serverless functions); the `depscanner` and `fix-worker` packages run on **Fly.io** (scale-to-zero). See [`DEVELOPERS.md`](../DEVELOPERS.md) for full local and multi-package setup.

### CI/CD integrations (GitHub, GitLab, Bitbucket)

When hosting online, set (no trailing slash on either):

- **`BACKEND_URL`** — your deployed backend API root (e.g. `https://api.yourdomain.com`)
- **`FRONTEND_URL`** — your deployed frontend app root

Then register these **exact** callback URLs with each provider:

| Provider | Where to set it | Callback URL |
|---|---|---|
| **GitHub** | GitHub App → General → Callback / Setup URL | `{BACKEND_URL}/api/integrations/github/callback` |
| **GitLab** | GitLab → Settings → Applications → Redirect URI | `{BACKEND_URL}/api/integrations/gitlab/org-callback` |
| **Bitbucket** | Bitbucket → Settings → OAuth consumers → Callback URL | `{BACKEND_URL}/api/integrations/bitbucket/org-callback` |

In your **frontend** env, set `VITE_API_BASE_URL` = `BACKEND_URL` so login and API calls hit the deployed backend.

## Contributing

See [`CONTRIBUTING.md`](../CONTRIBUTING.md) for the PR flow and the [`CLA`](../CLA.md); [`DEVELOPERS.md`](../DEVELOPERS.md) has the full setup across all packages.

## Security

Please report security vulnerabilities **privately** — use GitHub's **"Report a vulnerability"** (the repository's *Security → Advisories* tab) rather than opening a public issue.

## License

**AGPL-3.0-or-later** — see [`LICENSE`](../LICENSE). Copyright © 2026 Henry Ruckman-Utting.
