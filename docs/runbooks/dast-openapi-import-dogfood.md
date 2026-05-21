# DAST OpenAPI Import — Dogfood validation runbook

**Phase:** v1.1 Phase D Task 15 (Round 2 plan review patch 10 — throwaway DB only)
**When to run:** before merging the v1.1 OpenAPI feature into `main`.

## Scope guardrails (load-bearing — read first)

Per the round-2 plan review (`test-strategy-r1-f6`), dogfood DAST scans
**must not** point at any backend bound to dev/prod Supabase. Active-scan
SQLi/XSS payloads against real routes generate hundreds of garbage
audit-log rows + may trip rate limits / security policies.

**Pinned rules:**
- Throwaway Supabase project (or PGLite-backed local stack) only.
  NEVER `localhost:3001` against `SUPABASE_URL=<prod>` or `<dev>`.
- First dogfood run uses `scan_profile='quick'` (passive only). Escalate
  to `scan_profile='api'` ONLY after one clean quick pass.
- Tear down the throwaway DB after the run — no manual cleanup of
  `scan_jobs` / `project_dast_targets` / `activity` rows.

## Pre-flight

1. Worktree is on `worktree-dast-openapi-import` and Phase A + B + C are
   committed (e2e:dast-openapi green; backend tests 2499+/2502; frontend
   tests 473+/480).
2. `phase35_dast_api_spec.sql` applied to the throwaway Supabase project.
   Bucket `dast-openapi-specs` created (private, no RLS).
3. ZAP image pulled:
   ```
   docker pull ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a
   ```
4. Backend + frontend running against the throwaway project. `.env` files
   have `SUPABASE_URL=<throwaway-project-url>` and
   `SUPABASE_SERVICE_ROLE_KEY=<throwaway-key>`.

## Procedure

### Step 1 — Extraction on a real repo

Pick one supported-framework repo. Deptex's own backend (`/c/Coding/Deptex/backend`)
is the path of least resistance — it's a real Express app with ~40 routes
and is the repo the worker can already extract.

1. Connect the repo via the frontend (`Connect → GitHub → select repo`).
2. Wait for the extraction job to complete. Note the resulting
   `active_extraction_run_id`.
3. Confirm `project_entry_points` is populated:
   ```sql
   SELECT framework, COUNT(*)
   FROM project_entry_points
   WHERE project_id = '<from-frontend>'
     AND extraction_run_id = '<from-step-2>'
     AND entry_point_type = 'http_route'
   GROUP BY 1;
   ```
   For Deptex backend expect `express` with ≥30 routes.

### Step 2 — Configure spec source

1. In the frontend, navigate to the project's DAST tab.
2. Add a target pointing at the throwaway backend's local URL (e.g.
   `http://localhost:3001`). Confirm the target is created and the
   synthesized chip appears with `Synthesized · 0` (no scan yet).
3. Open the target edit dialog → "API Specification" section. Source
   defaults to "Synthesized" (existing-rows backfill is moot for the
   freshly-created target). Save with no changes.

### Step 3 — Quick-profile scan (passive)

Per the round-2 guardrail, the FIRST dogfood scan must be quick-mode.

1. Set `project_dast_config.scan_profile = 'quick'` in the throwaway DB:
   ```sql
   UPDATE project_dast_config SET scan_profile = 'quick'
   WHERE project_id = '<project>';
   ```
2. Trigger a DAST scan from the frontend.
3. Watch the worker logs for the `[dast-openapi-metric]` line and the
   `Job openapi added N URLs` line from ZAP.
4. Confirm `last_synthesis_ok = true`, `last_synthesis_endpoint_count =
   N` matches Step 1's count (or comes close — health-check paths are
   filtered).
5. `GET /api/projects/:projectId/dast/targets/:targetId/spec/download`
   returns a signed URL; opening it yields the synthesized YAML.

### Step 4 — API-profile scan (active)

Only proceed if Step 3 was clean.

1. Set `scan_profile = 'api'`. Trigger another scan.
2. Watch for ZAP's `activeScan` job running. Findings appear in
   `project_dast_findings` with `engine='zap'`.
3. **Required check:** for at least one finding, confirm:
   - `handler_file_path` is non-null.
   - `cross_link_metadata.match_method = 'sidecar'`.
   - `cross_link_metadata.via = 'sidecar'`.

   ```sql
   SELECT id, endpoint_url, handler_file_path, cross_link_metadata
   FROM project_dast_findings
   WHERE dast_run_id = (
     SELECT active_dast_run_id FROM project_dast_targets WHERE id = '<target>'
   )
   AND cross_link_metadata->>'via' = 'sidecar'
   LIMIT 5;
   ```

4. Record results in this runbook (append a `## Run YYYY-MM-DD` section
   below).

### Step 5 — URL mode smoke

1. Switch target spec source to `url` via the panel; URL = the local
   backend's `/api/openapi.json` (if present) or a public OpenAPI sample
   (e.g. <https://petstore3.swagger.io/api/v3/openapi.json>).
2. Save. Confirm the toast says the URL validated OK.
3. Trigger a scan. Worker fetches at scan start; ZAP imports.
4. Confirm `last_synthesis_ok = true` and findings are emitted.

### Step 6 — Soft-fail probes

1. Switch target back to `synthesized`. Delete the project's entry
   points: `DELETE FROM project_entry_points WHERE project_id = '<...>'`.
2. Trigger a scan. Should run spider-only; `last_synthesis_ok = false`,
   `endpoint_count = 0`. UI banner: "No endpoints detected…"
3. Switch to `url`; set URL to a 404 endpoint. Worker fetch fails;
   spider-only; banner: "URL spec fetch failed…"

### Step 7 — Tear down

```bash
# Throwaway Supabase project: delete from dashboard.
# OR if using local PGLite stack: rm -rf <pglite-dir>
```

## Run log

### Run YYYY-MM-DD — initial

- Repo: <name + SHA>
- Extracted entry points: <count> across <frameworks>
- Quick-mode scan: <pass / fail + notes>
- API-mode scan: <pass / fail + notes>
- Sidecar cross-link hits: <count> / <total findings>
- Issues found: <list>

(Append further runs as needed.)

## Known gaps (deferred to the 1-week e2e testing phase per `dast_v1_1_direction`)

- Multi-framework dogfood across Express + FastAPI + Spring/Rails. v1.1
  acceptance bar is one repo; the full 3-repo matrix lives in the locked
  1-week e2e phase.
- Real-host URL-mode fetch against multiple OpenAPI versions
  (3.0.x / 3.1.x / 2.0). The smoke spike covered 3.1 acceptance against
  ZAP; broader version coverage lives in the e2e phase.
- Recorded-login + OpenAPI interaction. Per the round-2 review patch 9
  Gate 3, if smoke shows recorded user-replay misbehaves on
  openapi-seeded URLs, the route layer forces `api_spec_source='none'`
  for recorded-strategy targets — but Phase 35 does NOT include that
  route-side guard. Add it (~10 LOC in `routes/dast.ts` PATCH /spec)
  if dogfood surfaces the issue.
