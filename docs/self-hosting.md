# Self-hosting Deptex

This guide stands up a working Deptex instance on your own infrastructure. You
end up with: local Postgres (via Supabase), local Redis for async jobs, the
backend API on `:3001`, the frontend on `:3000`, and a GitHub App you control.

License: [AGPL-3.0](../LICENSE). Open source — self-host, modify, and redistribute
freely. If you run a modified version as a network service, AGPL's copyleft requires
you to make your source available under the same license.

---

## Pick a deployment tier before you start

Self-hosting Deptex has three flavors. They share everything except how
GitHub reaches your instance:

| Tier | What you get | What you need |
|------|--------------|---------------|
| **1. Local + tunnel** | Full features. Run everything on your laptop; expose to GitHub via ngrok / cloudflared. | Tunneling tool, ~10 min of setup |
| **2. Deployed** | Full features, public URL, no tunnel. | A server / Fly / Render / etc. and a domain |
| **3. Scan-only (future)** | Point Deptex at a local folder, no GitHub integration. | *Not yet wired up — see [roadmap](#roadmap) below.* |

Tier 1 is the fastest "try it" path. Tier 2 is what you want for a real
team deployment. Tier 3 is the best long-term answer for individual devs
and is on the roadmap.

---

## Prerequisites

- **Node 20+** and **npm 10+**
- **Docker Desktop** (for Supabase + Redis)
- **Supabase CLI** ([install](https://supabase.com/docs/guides/local-development/cli/getting-started))
- **Git** and **psql** (PostgreSQL client — usually installed alongside Postgres)
- For Tier 1 only: **ngrok** ([free plan](https://ngrok.com/)) or cloudflared

---

## 1. Clone and install

```bash
git clone https://github.com/deptex/deptex.git
cd deptex
(cd backend && npm install)
(cd frontend && npm install)
```

## 2. Bring up the databases

**Postgres (Supabase):**

```bash
./scripts/setup-local-db.sh
```

This runs `supabase start` (Docker-based Supabase stack), loads
`backend/database/schema.sql`, installs the schema-dump helper, and
marks all current migrations as "applied" so `npm run migrate` only
picks up new ones going forward.

Note the credentials `supabase status` prints at the end — you need
`API URL`, `anon key`, and `service_role key`.

**Redis (only if you plan to use async jobs/crons):**

```bash
docker compose up -d redis
```

This starts Redis on `localhost:6379` with persistence enabled.

## 3. Configure environment

```bash
cp .env.example .env
cp frontend/.env.example frontend/.env
```

Fill in `.env` — at minimum:

```env
# from `supabase status`
SUPABASE_URL=http://127.0.0.1:54321
SUPABASE_ANON_KEY=...
SUPABASE_SERVICE_ROLE_KEY=...

# openssl rand -hex 32
AI_ENCRYPTION_KEY=...

# any long random string
INTERNAL_API_KEY=...
EXTRACTION_WORKER_SECRET=...

# one AI provider (Gemini Flash is cheap, good default)
GOOGLE_AI_API_KEY=...

# async jobs: point at the Redis you started in step 2
JOB_QUEUE_BACKEND=bullmq
REDIS_URL=redis://localhost:6379
```

And `frontend/.env`:

```env
VITE_SUPABASE_URL=http://127.0.0.1:54321
VITE_SUPABASE_ANON_KEY=...
VITE_API_BASE_URL=http://localhost:3001
```

## 4. Create a GitHub App

1. Go to https://github.com/settings/apps/new (or your org's App page).
2. **Homepage URL:** `http://localhost:3000` (Tier 1) or your public URL (Tier 2).
3. **Webhook URL:**
   - Tier 1: start your tunnel first (see step 5), paste the tunnel URL + `/api/webhooks/github`.
   - Tier 2: `https://yourdomain.com/api/webhooks/github`.
4. **Webhook secret:** generate one (`openssl rand -hex 32`) and paste it in
   `.env` as `GITHUB_WEBHOOK_SECRET`.
5. **Permissions (Repository):**
   - Contents: Read
   - Metadata: Read
   - Pull requests: Read & Write (for PR comments)
   - Checks: Read & Write (for Check Runs)
   - Webhooks: Read
6. **Subscribe to events:** Push, Pull request, Check run, Check suite.
7. After creating, note the **App ID**, download the **private key**
   (`.pem`), and put it on disk. In `.env`:

   ```env
   GITHUB_APP_ID=123456
   GITHUB_APP_NAME=deptex-local
   GITHUB_APP_PRIVATE_KEY_PATH=/absolute/path/to/private-key.pem
   GITHUB_WEBHOOK_SECRET=...
   ```

## 5. (Tier 1 only) Start a tunnel

GitHub needs to reach your webhook URL. If you're running on localhost,
your webhook URL from step 4 is unreachable by GitHub — fix that with
one of:

```bash
ngrok http 3001                    # prints https://abc123.ngrok.io
# or
cloudflared tunnel --url http://localhost:3001
```

Update your GitHub App's **Webhook URL** to the tunnel's HTTPS URL +
`/api/webhooks/github`.

## 6. Start the app

```bash
# terminal 1
cd backend && npm run dev

# terminal 2
cd frontend && npm run dev
```

Visit http://localhost:3000, sign up with email (Supabase Auth — check
http://localhost:54324 for the inbucket to grab the confirmation link),
create an organization, and install your GitHub App on a test repo.

First extraction should fire automatically on push. You can also trigger
one manually from the project page.

---

## Updating to a new Deptex release

```bash
git pull
(cd backend && npm install)
(cd frontend && npm install)
(cd backend && npm run migrate)   # applies any new backend/database/*.sql
```

The migration runner is idempotent and tracks state in the
`schema_migrations` table. Safe to re-run.

---

## What you can skip on self-host

The cloud product has these features that don't make sense self-hosted —
leave the env vars blank:

- **Stripe billing** (`STRIPE_*`) — self-hosters don't pay us.
- **Fly machine management** (`FLY_*`) — unless you're deploying the
  extraction worker on Fly specifically.
- **Transactional email** (`EMAIL_*`) — unless you want outbound
  notifications. Bring your own SMTP.
- **reCAPTCHA** (`RECAPTCHA_*`) — marketing-page gate, irrelevant here.
- **Upstash QStash** (`QSTASH_*`) — replaced by the BullMQ adapter.
- **Upstash Redis** (`UPSTASH_REDIS_*`) — your local Redis handles
  caching too (a small shim may be needed; file an issue if you hit it).

---

## Troubleshooting

**`supabase start` hangs / fails.** Docker Desktop not running, or port
`54321-54324`, `54322` conflict. Stop conflicting containers.

**`psql: command not found`.** Install PostgreSQL client tools. On
macOS: `brew install libpq && brew link --force libpq`. On Ubuntu:
`apt install postgresql-client`.

**Migrations say "no pending migrations" on a fresh box.** You skipped
`scripts/setup-local-db.sh` — run it, or run
`DATABASE_URL=... npm run migrate:status` to see state.

**`[job-queue:noop] no async job backend configured`.** `REDIS_URL`
isn't set or Redis isn't reachable. Check `docker compose ps`.

**GitHub webhooks aren't firing.** For Tier 1, your tunnel URL changed
(ngrok free plan rotates URLs on restart). Update the App's webhook URL.
Also check **Recent Deliveries** under the App settings to see what
GitHub is receiving back.

**`Invalid or missing worker secret` in logs.** `EXTRACTION_WORKER_SECRET`
mismatch between backend and extraction-worker. Set the same value in both.

**`AI_ENCRYPTION_KEY not set` warning on boot.** Required to encrypt
IaC v2 registry credentials (`organization_registry_credentials`). Run
`openssl rand -hex 32` and put it in `.env`.

---

## Roadmap

Planned work to make self-hosting easier:

- **Local folder scanning (Tier 3)** — point Deptex at a directory on
  disk, no Git integration required. CLI scaffolding already exists in
  the `reachability-phase1` branch; will be merged into a future release.
- **PAT-based GitHub integration** — use a personal access token instead
  of installing a GitHub App, at the cost of webhooks + PR Check Runs
  (manual sync only).
- **Full docker-compose stack** — single `docker compose up` that brings
  up Postgres, Redis, backend, workers, and frontend.
- **Self-hosted runner for cloud Deptex** — run scans on your own infra,
  report results back to a hosted Deptex org. Enterprise privacy wedge.

File an issue on GitHub if you hit something this guide doesn't cover.
