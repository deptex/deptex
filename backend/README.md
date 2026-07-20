# Deptex Backend

The core API for **Deptex** — an AI-powered, open-core dependency-security platform: dependency intelligence, continuous supply-chain monitoring, policy-as-code, and the **Aegis** AI security agent.

Open source under **AGPL-3.0** (see [`LICENSE`](LICENSE); contributions require the CLA described in the root [`CONTRIBUTING.md`](../CONTRIBUTING.md)). Some specialized logic may live in separate repositories.

## Tech Stack

- **Runtime**: Node.js 18+
- **Framework**: Express + TypeScript (ES2020, CommonJS)
- **Database & Auth**: PostgreSQL via Supabase (service-role key; Supabase Auth JWTs)
- **Async jobs / cache**: Upstash QStash + Redis
- **Package Manager**: npm

The root [`CLAUDE.md`](../CLAUDE.md) documents the full architecture — key data flows, RBAC, prepaid billing, and observability.

## Setup

### Prerequisites

- Node.js 18+ and npm
- A Supabase project (Postgres + Auth)

### Installation

1. Install dependencies:
   ```bash
   npm install
   ```

2. Create your environment file from the template:
   ```bash
   cp .env.example .env
   ```
   `.env.example` lists every variable the backend reads. At a minimum you need the Supabase keys (`SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_ANON_KEY`), `PORT`, and `FRONTEND_URL` / `BACKEND_URL`. Async jobs, AI, billing, and each integration have their own keys (QStash, Upstash Redis, OpenAI/Anthropic/Google, Stripe, the GitHub App, `INTERNAL_API_KEY`, …) — the root `CLAUDE.md` "Key Environment Variables" table explains what each one gates.

3. Load the database schema into your Supabase project from [`database/schema.sql`](database/schema.sql). Migrations live in `database/` as phase-prefixed `.sql` files; for a fresh install, run them in filename order.

4. In the Supabase dashboard, enable the **Google** and **GitHub** OAuth providers and configure the redirect URLs.

### Running the Server

```bash
npm run dev         # hot-reload dev server (port 3001)
npm run build       # tsc compile
npm start           # run the server
npm run type-check  # tsc --noEmit
```

## Project Structure

```
backend/
├── src/
│   ├── index.ts        # Express entry — all routes are mounted here
│   ├── instrument.ts   # Sentry init (first import; no-ops without a DSN)
│   ├── routes/         # ~58 API routers (organizations, teams, projects, findings,
│   │                   #   aegis, billing, integrations, webhooks, DAST, workers/cron…)
│   ├── lib/            # shared subsystems: ai/, aegis/, billing/, malicious/,
│   │                   #   taint-engine/, learning/, observability/, policy-engine, github…
│   └── middleware/     # auth (Supabase JWT), internal-key, ip-allowlist
├── database/           # ~140 phase-prefixed SQL migrations + schema.sql (source of truth)
├── package.json
└── tsconfig.json
```

## Authentication

Most `/api/*` endpoints require a Supabase JWT as `Authorization: Bearer <token>`; the `authenticateUser` middleware verifies it and populates `req.user`. Internal worker / cron endpoints (under `/api/internal` and `/api/workers`) are guarded by `INTERNAL_API_KEY` or QStash request signatures instead of user auth.

## Environment Variables

The essentials are below; see [`.env.example`](.env.example) for the complete list and the root `CLAUDE.md` for what each one gates.

- `SUPABASE_URL` — your Supabase project URL
- `SUPABASE_SERVICE_ROLE_KEY` — Supabase service-role key (backend operations)
- `SUPABASE_ANON_KEY` — Supabase anonymous key
- `PORT` — server port (default: 3001)
- `NODE_ENV` — `development` / `production`
- `FRONTEND_URL` — frontend URL for CORS + OAuth redirects (e.g. `http://localhost:3000`)
- `BACKEND_URL` — backend API base URL for OAuth callback URLs (e.g. `http://localhost:3001`). Use **no trailing slash**.

## Production: CI/CD integrations (GitHub, GitLab, Bitbucket)

When hosting the app online, set in your backend environment (**no trailing slash** on either):

- **`BACKEND_URL`** = your deployed backend API root (e.g. `https://api.yourdomain.com`)
- **`FRONTEND_URL`** = your deployed frontend app root (e.g. `https://deptex.vercel.app`)

Then register these **exact** callback URLs with each provider:

| Provider   | Where to set it | Callback URL to register |
|-----------|------------------|---------------------------|
| **GitHub**  | GitHub App → General → "Callback URL" / "Setup URL" | `{BACKEND_URL}/api/integrations/github/callback` |
| **GitLab**  | GitLab → Settings → Applications → Redirect URI | `{BACKEND_URL}/api/integrations/gitlab/org-callback` |
| **Bitbucket** | Bitbucket → Settings → OAuth consumers → Callback URL | `{BACKEND_URL}/api/integrations/bitbucket/org-callback` |

In your **frontend** env (e.g. Vercel env vars), set `VITE_API_BASE_URL` = same as `BACKEND_URL` so login and API calls hit the deployed backend.

## License

**AGPL-3.0-or-later** — see [`LICENSE`](LICENSE).
