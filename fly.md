# Fly.io Deployment

Deptex runs three workers on [Fly.io](https://fly.io), each with its own `fly.toml` and Dockerfile. The backend API and frontend are deployed elsewhere (Supabase for the database, a separate host for the Express API, and a static host for the Vite build).

This file documents how to deploy and operate the Fly.io workers. If you're setting up a fresh Fly.io organization, work through the **Initial setup** section once, then use **Deploying** for day-to-day updates.

---

## Workers

| Worker              | Fly app                        | Region | VM                          | Purpose                                                                 |
| ------------------- | ------------------------------ | ------ | --------------------------- | ----------------------------------------------------------------------- |
| extraction-worker   | `deptex-extraction-worker`     | `ewr`  | performance-8x, 64 GB RAM   | Clone repo, cdxgen SBOM, dep-scan, AST, Semgrep, TruffleHog             |
| watchtower-worker   | `deptex-watchtower-worker`     | `iad`  | shared-cpu-1x, 1 GB RAM     | Supply-chain forensic analysis (job-based, no HTTP)                     |
| aider-worker        | `deptex-aider-worker`          | `iad`  | shared-cpu-4x, 8 GB RAM     | AI-powered fix worker (Python / Aider, BYOK LLM)                        |

All three follow the **scale-to-zero** pattern: the backend starts a Fly machine via the Machines API when a job arrives, the worker processes the job, then the process exits after ~60 s of idle and Fly stops the machine. You pay per second of actual compute, not 24/7.

`extraction-worker` mounts a 50 GB volume (`depscan_vdb`) at `/data` to cache the dep-scan VDB (~30 GB) and atom engine caches between runs.

---

## Prerequisites

1. A Fly.io account and an org you own.
2. `flyctl` installed locally — https://fly.io/docs/hands-on/install-flyctl/.
3. `flyctl auth login` completed.

---

## Initial setup

Do this once per environment (prod, staging).

### 1. Create each app

```bash
cd backend/extraction-worker
fly apps create deptex-extraction-worker --org <your-org>

cd backend/watchtower-worker
fly apps create deptex-watchtower-worker --org <your-org>

cd backend/aider-worker
fly apps create deptex-aider-worker --org <your-org>
```

If the app names are already taken, change them here **and** in the corresponding `fly.toml` + `FLY_EXTRACTION_APP` / `FLY_AIDER_APP` env vars on the backend.

### 2. Create the extraction-worker volume

`extraction-worker` needs a persistent volume for the dep-scan VDB. Create it in the same region as the app (`ewr`):

```bash
cd backend/extraction-worker
fly volumes create depscan_vdb --size 50 --region ewr --app deptex-extraction-worker
```

### 3. Set secrets on each worker

Each worker needs Supabase credentials so it can read/write jobs. `aider-worker` also needs BYOK LLM keys passed per-job via the backend (not as static secrets), so it only needs Supabase.

```bash
# extraction-worker
fly secrets set \
  SUPABASE_URL=... \
  SUPABASE_SERVICE_ROLE_KEY=... \
  --app deptex-extraction-worker

# watchtower-worker
fly secrets set \
  SUPABASE_URL=... \
  SUPABASE_SERVICE_ROLE_KEY=... \
  --app deptex-watchtower-worker

# aider-worker
fly secrets set \
  SUPABASE_URL=... \
  SUPABASE_SERVICE_ROLE_KEY=... \
  --app deptex-aider-worker
```

Add any worker-specific secrets (e.g. `GITHUB_APP_ID`, `GITHUB_PRIVATE_KEY` for private-repo cloning, `INTERNAL_API_KEY` for backend callbacks) as needed — see `backend/src/lib/fly-machines.ts` for the exact env the workers expect.

### 4. Wire the backend

The backend starts Fly machines via the Machines API. Set these on whatever host runs the backend:

```
FLY_API_TOKEN=<personal access token with deploy scope>
FLY_EXTRACTION_APP=deptex-extraction-worker
FLY_AIDER_APP=deptex-aider-worker
```

`watchtower-worker` is started the same way but via a hardcoded app name inside the backend — if you renamed it, update `backend/src/lib/fly-machines.ts`.

### 5. Pre-create a machine pool (optional, extraction-worker)

For faster cold starts on extraction, pre-create a small pool of stopped machines:

```bash
fly machine run . --app deptex-extraction-worker --region ewr --vm-cpu-kind performance --vm-cpus 8 --vm-memory 65536
# Immediately stop it — the backend will start it on demand
fly machine stop <machine-id> --app deptex-extraction-worker
```

---

## Deploying

From the worker directory:

```bash
cd backend/extraction-worker && fly deploy
cd backend/watchtower-worker && fly deploy
cd backend/aider-worker      && fly deploy
```

`fly deploy` reads `fly.toml` in the current directory, builds the Dockerfile, and rolls the new image out to all machines in the app.

For production, deploy from a CI workflow with a Fly deploy token so you don't need a developer's personal token. See https://fly.io/docs/reference/deploy-tokens/.

---

## Operating

- **Live logs:** `fly logs --app deptex-extraction-worker`
- **List machines:** `fly machine list --app deptex-extraction-worker`
- **Start a machine manually:** `fly machine start <id> --app <app>` (useful for debugging; normally the backend does this)
- **SSH into a running machine:** `fly ssh console --app deptex-extraction-worker` (must be started first)
- **Rotate secrets:** `fly secrets set KEY=val --app <app>` (auto-redeploys)

---

## Cost notes

Scale-to-zero means you pay for actual runtime, not uptime. Rough ballpark for typical usage:

- **extraction-worker:** `performance-8x` @ ~$0.12/min × ~3 min/extraction = ~$0.36/extraction
- **watchtower-worker:** `shared-cpu-1x` @ ~$0.002/min × short runs = negligible
- **aider-worker:** `shared-cpu-4x` @ ~$0.03/min; variable per fix job

Fly offers a 40% discount with annual compute reservations — worth it once your volume is steady.

---

## Non-Fly pieces

- **Database + Auth + Realtime:** Supabase. Not deployed from this repo.
- **Backend API:** Deploy `backend/` to any Node host (e.g. Fly, Railway, Render, a VPS). The three workers above are the only Fly-native pieces.
- **Frontend:** Deploy `frontend/dist/` (from `npm run build`) to any static host (Vercel, Netlify, Cloudflare Pages, S3).

Self-hosting the whole stack on your own infra is tracked in [`docs/self-hosting.md`](./docs/self-hosting.md).
