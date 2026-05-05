# DAST v2.1a deploy runbook

Phase 24a is the **additive half** of the two-phase migration that introduces
multi-target DAST scanning, encrypted form/JWT/cookie credentials, SPA detection,
scope rules, and three-layer cross-tenant validation. The destructive half
(phase24b — drop legacy columns, flip `findings.target_id NOT NULL`, drop wrapper
RPCs, drop `DAST_RUNNER_MODE=helper_script`) lands separately after a ≥7-day
shadow window proves the new path safe.

This runbook covers the v2.1a rollout DAG. The steps **must** run in order — the
worker has to speak both the legacy `commit_dast_run(uuid, text)` and the new
`commit_dast_target_run(uuid, text)` signatures **before** the migration applies,
or in-flight scans will fail their atomic-commit step.

## Pre-flight checks

- Confirm `backend/database/phase24a_dast_v2_engine_additive.sql` exists on the
  feature branch.
- Confirm `backend/database/schema.sql` was regenerated on the feature branch
  (per `feedback_schema_dump_rebase` — regenerating on `main` after merge will
  silently drop the diff during rebase).
- Confirm `DAST_CREDENTIAL_KEY` (32-byte hex) is set on the depscanner Fly app
  env. Routes will refuse credential PUT with 503 `dast_encryption_not_configured`
  until this is in place.
- Confirm `INTERNAL_API_KEY` is unchanged.

## Deploy DAG

### Step 1 — Pause new DAST submissions

```bash
# Backend API (Vercel env)
INTERNAL_DAST_PAUSED=true
```

The drain-mode middleware in `backend/src/index.ts` returns
`503 { error: 'dast_queue_paused' }` for `POST /api/projects/:projectId/dast/scan`
when this flag is set. All other routes continue passing through so the UI can
surface state and operators can clean up.

### Step 2 — Wait for the queue to drain

Poll until in-flight count is zero. Hard cap: 60 minutes. Stuck jobs get killed
via the existing `fail_exhausted_scan_jobs` cron.

```sql
SELECT COUNT(*)
FROM scan_jobs
WHERE type IN ('dast', 'dast_zap', 'dast_nuclei')
  AND status IN ('queued', 'processing');
```

The phase24a migration's verification block also logs this count via
`RAISE NOTICE` — non-blocking, but a non-zero value is the canonical signal that
the deploy DAG was skipped.

### Step 3 — Roll out the depscanner image with the dual-call shim

The new depscanner image must call **either** `commit_dast_run` (legacy) or
`commit_dast_target_run` (new) successfully. The wrapper RPC handles both
signatures; the image just needs to be deployed before the migration applies so
that any concurrent worker process speaks the right version regardless of which
half of the deploy sees its commit first.

```bash
fly deploy --app deptex-depscanner --image-label dast-v2-1a
```

Verify scale-to-zero machine spawn picks up the new image by triggering a
manual scan against a staging project.

### Step 4 — Apply the migration

Apply `phase24a_dast_v2_engine_additive.sql` via the Supabase MCP tooling
(`mcp__claude_ai_Supabase__apply_migration`). Per `feedback_apply_migrations_via_mcp`,
**never** paste SQL for Henry to run manually — the migration's two-pass
backfill needs the same transactional context as the DDL ahead of it.

The migration logs three verification SELECTs via `RAISE NOTICE`:

- `project_dast_targets` row count (≥ distinct projects with `project_dast_config`)
- `project_dast_findings` rows still NULL on `target_id` (orphans, non-blocking)
- in-flight DAST scan_jobs (must be 0 — drain runbook precondition)

A `RAISE WARNING` fires if the target count is below the project count from
`project_dast_config`. Investigate before phase24b.

### Step 5 — Roll out the backend API

The backend API release must:

- Pass `p_target_id` to the new `queue_scan_job` signature for any new DAST scan.
- Read DAST findings via the new target-scoped paths (`/api/projects/:id/dast/targets`,
  `/api/projects/:id/dast/findings?target_id=...`).
- Continue accepting the legacy single-target route shape during the shadow
  window — the wrapper RPCs handle the back-compat translation.

### Step 6 — Unset the drain flag

```bash
INTERNAL_DAST_PAUSED=false  # or unset entirely
```

POST scan requests resume. The existing `fail_exhausted_scan_jobs` cron continues
catching stuck jobs.

### Step 7 — Watch the shadow window

Monitor for **≥7 days** (≥30 days for prod). Hold phase24b until **all** of:

- `pg_stat_user_functions` shows zero calls to legacy `commit_dast_run(uuid, text)`
  in the last 24 hours. Query:
  ```sql
  SELECT funcname, calls
  FROM pg_stat_user_functions
  WHERE funcname IN ('commit_dast_run', 'commit_dast_target_run')
  ORDER BY funcname;
  ```
- `commit_dast_target_run` accumulates calls (i.e., new RPC is being exercised).
- Juice Shop e2e (`backend/depscanner/dast/__tests__/juice-shop.e2e`) reproduces
  v1 anonymous-baseline finding count within ±10% under both `helper_script`
  and `automation_framework` runner modes.
- No `tenant_drift_detected` or `dast_credential_key_*` aborts in the last 7 days.

Once those conditions hold, plan and apply phase24b (destructive cleanup).

## Roll-back

If step 4's migration application succeeds but a downstream issue surfaces:

- The migration is **additive only** — every old RPC, every old column, every
  old finding-table shape stays in place.
- Roll back the API + worker images. The legacy `commit_dast_run(p_project_id, p_dast_run_id)`
  signature still works because the wrapper delegates via "first target row for
  project."
- The new tables remain populated but unread until the next forward roll. No
  destructive cleanup required.

If step 4's migration application fails partway through:

- The migration runs as a single transaction; any failure rolls back the whole
  file. Verify by running:
  ```sql
  SELECT to_regclass('public.project_dast_targets'),
         to_regclass('public.project_dast_credentials');
  ```
  Both `NULL` = clean roll-back. Both `<oid>` = applied successfully.
- A partial state (one table created, the other missing) means the migration
  was modified mid-flight and should not exist in practice. If it does, drop
  the partial artifacts manually and re-apply the file from scratch.

## Step ordering — non-negotiable

Step 3 (worker rollout) **must** complete before step 4 (migration). The new
depscanner image needs to know how to call both legacy and canonical RPCs **before**
the new RPCs exist. If the migration applies first and a worker on the old image
is mid-scan, the worker will call `commit_dast_run` with the old single-target
behavior — fine, the wrapper handles it — but **any new logic added in v2.1a's
runner.ts (auth strategy resolution, SPA-aware machine sizing, credential
audit-hash check) requires the new image**. Skipping step 3 leaves you running
v1 logic against v2 schema, which is the worst of both worlds.
