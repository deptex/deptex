# DAST v2.1b deploy runbook

Phase 24b is the **destructive half** of the v2.1 two-phase migration. Pairs with phase24a (additive landing, PR #27 merged 2026-05-06).

Single-transaction migration. Any failure between BEGIN and COMMIT aborts atomically — DB unchanged. Safe to rerun after diagnosing the cause.

## Step 0 — Snapshot

Trigger a Supabase manual snapshot via the dashboard (or note the current PITR timestamp) immediately before applying. Record the timestamp in the PR description. Solo-pre-launch makes this near-zero-cost insurance.

## Step 1 — Deploy backend FIRST

Merging this PR triggers a Vercel rebuild that drops the legacy reads from the route + DTO. The route's findings-list now returns `[]` when `target_id` is omitted (instead of falling back to the about-to-be-dropped `projects.active_dast_run_id`). Wait for the deploy to land green before Step 2.

`INTERNAL_DAST_PAUSED` is **not** required for v2.1b. The new backend handles a missing column gracefully (it doesn't read those columns at all), and there are no in-flight scans to drain in solo-pre-launch. (Drain mechanism is generic infra retained for v2.1c when scheduled scans land.)

## Step 2 — Apply migration via MCP

```
mcp__claude_ai_Supabase__apply_migration {
  name: "phase24b_dast_v2_engine_destructive",
  query: "<contents of backend/database/phase24b_dast_v2_engine_destructive.sql>"
}
```

Verify the `RAISE NOTICE` row counts in the Supabase logs match expectations (zero or small for solo-pre-launch).

If `apply_migration` succeeds but `schema:dump` (run locally) fails: do NOT re-apply the migration — it will error on the NOT NULL flip and the function-overload assertion. Re-run only `cd backend/depscanner && npm run schema:dump`.

## Step 3 — Verify

Run the post-merge smoke checklist:

```sql
-- Confirm legacy columns gone
SELECT column_name FROM information_schema.columns
WHERE table_name='projects' AND column_name LIKE '%dast_run_id';
-- expected: 0 rows

SELECT column_name FROM information_schema.columns
WHERE table_name='project_dast_config' AND column_name='target_url';
-- expected: 0 rows

-- Confirm target_id is NOT NULL
SELECT is_nullable FROM information_schema.columns
WHERE table_name='project_dast_findings' AND column_name='target_id';
-- expected: 'NO'

-- Confirm legacy wrapper is gone
SELECT proname, pronargs FROM pg_proc WHERE proname='commit_dast_run';
-- expected: 0 rows

-- Confirm exactly one queue_scan_job overload
SELECT count(*) FROM pg_proc WHERE proname='queue_scan_job';
-- expected: 1

-- Confirm legacy indexes gone
SELECT indexname FROM pg_indexes
WHERE schemaname='public'
  AND indexname IN ('project_dast_findings_resolved','project_dast_findings_unresolved');
-- expected: 0 rows

-- Confirm new target-keyed indexes don't carry the redundant predicate
SELECT indexdef FROM pg_indexes
WHERE indexname LIKE 'project_dast_findings_target_%';
-- expected: WHERE clause is just `WHERE handler_file_path IS [NOT] NULL` — no `target_id IS NOT NULL`
```

## Step 4 — Recovery (last-resort)

The migration is single-transaction; mid-migration failure leaves the DB unchanged. The realistic failure mode is "migration succeeded, then post-deploy traffic reveals a regression."

### If a regression appears post-deploy (solo-pre-launch — no real traffic, but documented for v2.1c/d's inheritance):

1. **Fix-forward path (preferred):** identify the broken caller, patch in a follow-up PR. The dropped columns/functions cannot be recreated cheaply, but a new caller can be patched against the new schema.
2. **Rollback path (last-resort):** restore from the Step 0 Supabase snapshot. This reverts ALL DB state to pre-migration, including any non-DAST changes accumulated in between. Use only if Step 1 isn't tractable. Coordinate with backend redeploy to a pre-PR Vercel tag.

### If the regression involves a previously-undiscovered caller of `projects.active_dast_run_id` or `commit_dast_run`:

See "v2.1b.5 fallback sketch" in the plan. The pattern is to ship phase24c with ONLY the column drop deferred until the new caller is updated.

## Step 5 — Re-create credentials post-merge

The migration deleted all `project_dast_credentials` rows (encrypted form/JWT/cookie payloads). Solo-pre-launch means likely zero rows existed, but if any DAST credentials were configured on the dev instance, re-PUT them via:

```
PUT /api/projects/:projectId/dast/credentials/:targetUrl
```

Re-extraction will repopulate `project_dast_findings` on next scan.
