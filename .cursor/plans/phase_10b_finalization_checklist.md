# Phase 10B: Watchtower Refactor — Finalization Checklist

Use this checklist after the Phase 10B code changes are merged. Complete steps in order.

---

## 1. Database migration

Run the Phase 10B migration against your Supabase (or Postgres) database:

| File | Purpose |
|------|--------|
| `backend/database/phase10b_watchtower_refactor.sql` | Creates `watchtower_jobs` table, `claim_watchtower_job` and `recover_stuck_watchtower_jobs` RPCs, adds `watchtower_enabled` / `watchtower_enabled_at` to `projects`, creates `project_watchlist` and `cleanup_orphaned_watchlist` trigger |

**How to run (example):**

```bash
# From repo root, using Supabase CLI or psql
psql "$DATABASE_URL" -f backend/database/phase10b_watchtower_refactor.sql
```

Or in Supabase Dashboard: SQL Editor → paste file contents → Run.

**Note:** If you use custom organization roles and want to gate Watchtower actions, add `manage_watchtower: true` to the role’s `permissions` JSONB in `organization_roles`. Default roles (Owner/Admin/Member) can be updated in app or via a one-off SQL update.

---

## 2. Backend environment variables

Ensure the **main backend** (Express API) has:

| Variable | Required | Description |
|---------|----------|-------------|
| `INTERNAL_API_KEY` | Yes | Used by QStash and workers to call internal endpoints (recovery, watchtower-event). Same key as other internal endpoints. |
| `FLY_API_TOKEN` | Yes (for EE) | Fly.io API token so the backend can start Watchtower machines. Same token used for extraction/Aider. |
| `FLY_WATCHTOWER_APP` | No | Fly.io app name for the Watchtower worker. Default: `deptex-watchtower-worker`. Set if you use a different app name. |

---

## 3. Deploy Watchtower worker to Fly.io

The worker runs as a **scale-to-zero** Fly.io app: no HTTP server, no `min_machines`; machines start when jobs are enqueued and stop after idle timeout.

**3.1 Create the Fly.io app (if it doesn’t exist)**

```bash
cd backend/watchtower-worker
flyctl apps create deptex-watchtower-worker
# Or use your preferred app name and set FLY_WATCHTOWER_APP on the backend
```

**3.2 Set secrets on the Watchtower worker app**

```bash
flyctl secrets set \
  SUPABASE_URL="https://<your-project>.supabase.co" \
  SUPABASE_SERVICE_ROLE_KEY="<service-role-key>" \
  BACKEND_URL="https://<your-backend-host>" \
  INTERNAL_API_KEY="<same-as-backend-INTERNAL_API_KEY>"
```

For GitHub App–backed analysis (clone, registry integrity, etc.):

```bash
flyctl secrets set \
  GITHUB_APP_ID="<app-id>" \
  GITHUB_APP_PRIVATE_KEY="<pem-contents-or-base64>"
```

Use `GITHUB_APP_PRIVATE_KEY_PATH` only if you mount a file; in production, `GITHUB_APP_PRIVATE_KEY` is typical.

**3.3 Deploy**

```bash
cd backend/watchtower-worker
npm ci
npm run build
flyctl deploy
```

**3.4 Scale-to-zero behavior**

The worker `fly.toml` has **no `[http_service]`**, so Fly does not keep any "service" machine running. Machines run only when the backend calls `startWatchtowerMachine()` (e.g. after the daily poll or when jobs are enqueued). The worker process exits after 60s with no jobs, and burst machines use `auto_destroy: true`, so they stop when idle. If you had an older deploy with `http_service`, stop any running machines in the Fly dashboard so the app is truly off until the next job run.

**3.4 Confirm no HTTP service**

`backend/watchtower-worker/fly.toml` must **not** define `[http_service]` (the worker has no HTTP server). Fly will run the process and stop the machine when it exits (idle shutdown after 60s with no job).

---

## 4. QStash cron schedules

In the **Upstash QStash** dashboard, configure:

| Schedule | Endpoint | Purpose |
|----------|----------|--------|
| `0 4 * * *` (daily 4:00 UTC) | `POST https://<your-backend>/api/workers/watchtower-daily-poll` | Dependency refresh (npm latest, GHSA), poll sweep (new commits for watched packages), webhook health. Enqueues `new_version` and `poll_sweep` jobs into `watchtower_jobs` and starts a Watchtower machine. |
| `*/5 * * * *` (every 5 min) | `POST https://<your-backend>/api/internal/recovery/watchtower-jobs` | Requeues jobs stuck in `processing` (no heartbeat 5 min), fails exhausted jobs, starts a machine if there are queued jobs and no running worker. |

**Auth:** Use QStash signing (recommended) or send header:

`X-Internal-Api-Key: <INTERNAL_API_KEY>`.

---

## 5. Optional: Deprecate standalone watchtower-poller

If you still run the legacy **watchtower-poller** process (Redis-based, always-on), you can turn it off. Phase 10B uses:

- QStash → `POST /api/workers/watchtower-daily-poll` (enqueues into Supabase)
- Watchtower worker on Fly.io (polls Supabase, scale-to-zero)

No Redis queue is used for Watchtower jobs after migration.

---

## 6. Testing

Before or after merge, run tests to ensure Phase 10B code paths are covered:

**Backend (from `backend/`):**

```bash
npm test
```

**Phase 10B test files and coverage:**

| File | What it covers |
|------|----------------|
| `backend/src/lib/__tests__/watchtower-poll.test.ts` | **runDependencyRefresh**: inserts `new_version` jobs when npm version changes, calls `startWatchtowerMachine`, returns `newVersionJobs`; no jobs when version unchanged; does not throw when fly-machines unavailable. **runPollSweep**: inserts `poll_sweep` jobs for ready packages, calls `startWatchtowerMachine`; zeros when no ready packages; `jobsQueued: 0` when insert fails. |
| `backend/src/routes/__tests__/watchtower-recovery.test.ts` | **POST /api/internal/recovery/watchtower-jobs**: 401 without/wrong key; 200 with valid key/Bearer; `recovered` from RPC; starts machine when orphaned queued jobs exist; **500 when RPC fails**; **200 with `machines_started: 0` when startWatchtowerMachine throws**. |
| `backend/src/routes/__tests__/watchtower-event.test.ts` | **POST /api/internal/watchtower-event**: 401 without key; 400 missing required fields; 200 CE no-op (no emitEvent); EE mode calls emitEvent with watchtower source; **optional project_id**; **default priority normal**; **200 when EE emitEvent throws** (fire-and-forget). |
| `ee/backend/lib/__tests__/watchtower-queue.test.ts` | **queueWatchtowerJob**: insert + startWatchtowerMachine; defaults; **success false when insert fails**. **queueWatchtowerJobs**: batch insert + one startWatchtowerMachine call; empty array; **success false when batch insert fails**. |
| `backend/src/routes/__tests__/project-watchtower.test.ts` | **POST watchtower/toggle**: 401 unauthenticated; 403 not org member; 200 enable (no direct deps, packages_watched 0); 200 disable. **GET watchtower/stats**: 401; 200 cache hit; 200 enabled: false when disabled. |
| `backend/src/routes/__tests__/org-watchtower.test.ts` | **GET watchtower/overview**: 401; 403 not member; 200 cached overview. **GET watchtower/projects**: 401; 403 not member. |

**Edge cases covered:**

- Recovery: RPC error → 500; machine start throws → 200, machines_started 0.
- Event: EE emitEvent throws → 200; optional fields; default priority.
- Poll: Version unchanged → no jobs; insert fails in poll_sweep → jobsQueued 0; fly-machines throw → newVersionJobs still returned.
- Queue: Insert/batch failure → success false, no startWatchtowerMachine.

**PR guardrails (Watchtower block):** Logic lives inside the GitHub webhook handler in `ee/backend/routes/integrations.ts`. Covered by manual or E2E testing (upgrade to quarantined/failed version → PR blocked; not on watchlist → skip; version not analyzed → allow).

**Existing tests still apply:**

- `backend/src/routes/__tests__/watchtower.test.ts` — Per-package Watchtower API (summary, commits).
- `backend/src/__tests__/watchtower-worker.test.ts` — Worker job logic (mocked analyzer/storage); worker now uses Supabase claim, job-handling behavior still exercised.

**Watchtower worker build (from `backend/watchtower-worker/`):**

```bash
cd backend/watchtower-worker
npm run build
```

Ensures the worker compiles (e.g. after `AnomalyResult` or oxc-parser type changes).

**Note:** If tests that import the full app (e.g. project-watchtower, org-watchtower) fail with module resolution (e.g. `jsonwebtoken` or ee→backend paths), ensure `backend/jest.config.js` has `moduleNameMapper` for `jsonwebtoken` pointing to `backend/src/__mocks__/jsonwebtoken.js`. Other env-specific failures (e.g. ai-infrastructure rate limit) are pre-existing.

---

## 7. Verify

1. **Migration:** In Supabase/Postgres, confirm `watchtower_jobs`, `project_watchlist`, and `projects.watchtower_enabled` exist and RPCs `claim_watchtower_job` and `recover_stuck_watchtower_jobs` are present.
2. **Worker:** In Fly.io, open app `deptex-watchtower-worker` (or your `FLY_WATCHTOWER_APP`). After the daily poll or a manual “Enable Watchtower” on a project, a machine should start, process jobs, then stop when idle.
3. **Recovery:** Call recovery manually (e.g. with Postman or curl) with `X-Internal-Api-Key`; response should include `recovered`, `orphaned_jobs_found`, `machines_started`.
4. **Notifications:** If the worker emits events (`security_analysis_failure`, `supply_chain_anomaly`, `new_version_available`), ensure `BACKEND_URL` and `INTERNAL_API_KEY` on the worker point at the backend so `POST /api/internal/watchtower-event` succeeds. Add the “Watchtower Alerts” notification rule template in the UI to receive them.

---

## Summary

| Step | What |
|------|------|
| 1 | Run `phase10b_watchtower_refactor.sql` |
| 2 | Set backend env: `INTERNAL_API_KEY`, `FLY_API_TOKEN`, optional `FLY_WATCHTOWER_APP` |
| 3 | Deploy Watchtower worker to Fly.io and set its secrets (Supabase, BACKEND_URL, INTERNAL_API_KEY, GitHub App) |
| 4 | Add QStash crons: watchtower-daily-poll (daily 4AM UTC), recovery watchtower-jobs (every 5 min) |
| 5 | (Optional) Turn off legacy watchtower-poller |
| 6 | Run backend tests (`npm test`) and watchtower-worker build |
| 7 | Verify DB, worker runs, recovery endpoint, and notifications |

After this, enabling Watchtower on a project (Project → Watchtower tab → Enable) will add direct dependencies to the watchlist, enqueue jobs in `watchtower_jobs`, and start a Fly.io machine to process them. The organization Watchtower page will show aggregated status across projects.
