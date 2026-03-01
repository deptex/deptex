# Fly.io Deployment Checklist — Phase 2 Extraction Worker

Run these steps **after** the Phase 2 code changes (2A–2F) are complete.

## Prerequisites

- Fly.io account (https://fly.io)
- Git Bash (per project conventions)
- `INTERNAL_API_KEY` env var set in backend `.env` (any random string — used by QStash recovery cron)

---

## Step 1: Install flyctl

**Windows (PowerShell):**
```powershell
powershell -Command "iwr https://fly.io/install.ps1 -useb | iex"
```

**macOS/Linux:**
```bash
curl -L https://fly.io/install.sh | sh
```

---

## Step 2: Login

```bash
fly auth login
```

---

## Step 3: Launch the app

```bash
cd backend/extraction-worker
fly launch
```

When prompted:
- App name: `deptex-extraction-worker` (or accept default)
- Region: `iad` (US East)
- No Postgres/Redis (we use Supabase + Upstash)

---

## Step 4: Set secrets

Replace placeholders with values from your `backend/.env`:

```bash
fly secrets set \
  SUPABASE_URL="<your-supabase-url>" \
  SUPABASE_SERVICE_ROLE_KEY="<your-service-role-key>" \
  GITHUB_APP_ID="<your-github-app-id>" \
  GITHUB_APP_PRIVATE_KEY="<your-github-private-key>" \
  NODE_ENV="production"
```

Note: Redis is no longer required for extraction jobs (uses Supabase). Only set `UPSTASH_REDIS_URL` / `UPSTASH_REDIS_TOKEN` if still using Redis for other queues.

---

## Step 5: Deploy

```bash
fly deploy
```

---

## Step 6: Scale to pool of 3 machines

```bash
fly scale count 3
```

---

## Step 7: Stop all machines (creates idle pool)

Machines start in "started" state. Stop them so the backend can start them on demand:

```bash
fly machines list
```

For each machine ID:
```bash
fly machine stop <machine-id>
```

---

## Step 8: Create deploy token for backend

```bash
fly tokens create deploy -a deptex-extraction-worker
```

Copy the token output.

---

## Step 9: Add FLY_API_TOKEN to backend .env

Add to `backend/.env`:

```
FLY_API_TOKEN=<paste-token-from-step-8>
FLY_EXTRACTION_APP=deptex-extraction-worker
FLY_MAX_BURST_MACHINES=5
```

Restart the backend so it picks up the new env vars.

---

## Step 10: Run database migrations

Execute the following SQL files in your Supabase Dashboard (SQL Editor) in order:

1. `backend/database/extraction_jobs_schema.sql` — creates `extraction_jobs` table, RLS, RPC functions
2. `backend/database/extraction_logs_schema.sql` — creates `extraction_logs` table, enables Realtime, RLS

---

## Step 11: Enable Supabase Realtime

If the `ALTER PUBLICATION` in the migration didn't work (requires superuser), manually enable Realtime on `extraction_logs`:

1. Go to Supabase Dashboard → Database → Replication
2. Find `extraction_logs` table and enable it for Realtime

---

## Step 12: Set up QStash recovery cron (optional but recommended)

Create a QStash schedule to call the recovery endpoint every 5 minutes:

- **URL:** `https://<your-backend-url>/api/internal/recovery/extraction-jobs`
- **Method:** POST
- **Schedule:** `*/5 * * * *`
- **Headers:** `X-Internal-Api-Key: <your-INTERNAL_API_KEY>`

This automatically requeues stuck jobs and starts machines for orphaned jobs.

---

## Step 13: Verify

1. Trigger extraction from the frontend (connect a repo or re-sync).
2. Run `fly machines list` — a machine should start, process the job, then stop.
3. Click the eye icon on the connected repo to view live extraction logs.
4. Run a second extraction on a different project to verify concurrency.

---

## Test Checklist (2G)

- [ ] Trigger extraction from frontend
- [ ] Backend inserts into `extraction_jobs` and calls Fly Machines API to start a machine
- [ ] Machine boots, claims job atomically via `claim_extraction_job` RPC
- [ ] Machine processes job (clone, SBOM, deps, vulns, AST, Semgrep, TruffleHog)
- [ ] Live logs appear in real-time in the extraction logs sidebar
- [ ] Error states show as red log lines
- [ ] Second extraction starts a different machine (concurrency)
- [ ] Machine stops after 60s idle timeout
- [ ] Historical log runs are browsable via the run selector dropdown
- [ ] Cancel button stops an in-progress extraction
- [ ] Recovery cron requeues stuck jobs (if configured)
- [ ] Worker heartbeat keeps long-running jobs alive

---

## Token Rotation

Rotate `FLY_API_TOKEN` every 90 days:

```bash
fly tokens create deploy -a deptex-extraction-worker
```

Update `FLY_API_TOKEN` in backend `.env` and restart the backend.

---

## Cost Estimate (Scale-to-Zero)

- 3 stopped machines (rootfs ~2GB each): 3 x 2 x $0.15 = **$0.90/month idle**
- Per extraction job (~5 min): **~$0.065**
- 100 extractions/month: $0.90 + $6.50 = **~$7.40/month**
- 500 extractions/month: $0.90 + $32.50 = **~$33.40/month**

## Machine Sizing

Current: `performance-8x` with 64GB RAM (for dep-scan research profile / deep reachability).

For initial testing without research profile, you can temporarily scale down:

```bash
# In fly.toml, change [[vm]] to:
# cpu_kind = "shared"
# cpus = 4
# memory_mb = 16384
```

Then `fly deploy` to apply. Scale back up when enabling Phase 6B deep reachability.
