# DAST v2.1d deploy runbook

v2.1d adds **recorded-login** as a fourth DAST auth strategy (alongside
form / jwt / cookie). Ships a step-list credential editor, a Test-login
dry-run flow, a user-initiated scan cancel endpoint, and worker-side
ZAP browser-auth replay + `auth-report-json` parsing.

Three migrations pair with the code:

- `phase34_cancel_scan_job_rpc` — new `cancel_scan_job` RPC.
- `phase34a_dast_zap_dry_run_type` — new `scan_jobs.type='dast_zap_dry_run'`
  so old workers can't claim a Test-login probe (see /criticalreview
  **SVED-1** for the full rationale).
- `phase34b_cancel_scan_job_bind_project_id` — extends the cancel RPC
  signature with `p_project_id` (closes /criticalreview **HEH-1**) and
  pins `search_path` on the SECURITY DEFINER function (/criticalreview
  **MIG-1**).

All three are pure-additive in the v2.1d direction (one `DROP FUNCTION` +
re-CREATE on the cancel RPC; the CHECK widen accepts new values without
touching existing rows). No two-phase split needed.

## Deploy order (do not skip)

Three artifacts ship: **migrations**, **depscanner worker image**, and
**backend**. The required order is:

1. **Migrations** (Step 1) — apply via Supabase MCP. The backend's POST
   `/dast/targets/.../credentials/test` route fails with 500 if
   `cancel_scan_job(p_job_id, p_organization_id, p_project_id)` isn't
   present (the 2-arg phase34 version is dropped + replaced by phase34b).
2. **Depscanner worker image** (Step 2) — ships the new
   `dast_zap_dry_run` capability in `getSupportedJobTypes()`, the
   `runRecordedLoginProbe` pre-flight branch for real recorded-strategy
   scans, the auth-report-json parser, and the digest-pinned ZAP base.
3. **Backend** (Step 2b) — starts queuing `type='dast_zap_dry_run'` rows
   on Test-login. Until this deploys, the route doesn't exist.

The backend MUST be last. Critically: per /criticalreview **SVED-1**, the
backend queuing `type='dast_zap_dry_run'` BEFORE the depscanner image is
fleet-wide on v2.1d means an old worker won't advertise the new type and
the row will sit queued forever. Worker-before-backend is the supported
ordering.

## Step 0 — Snapshot

Trigger a Supabase manual snapshot (or note the PITR timestamp) before
applying. Record it in the PR description.

## Step 1 — Apply the migrations via MCP

Apply in order (each is a separate `apply_migration` call):

```
mcp__claude_ai_Supabase__apply_migration {
  name: "phase34_cancel_scan_job_rpc",
  query: "<backend/database/phase34_cancel_scan_job_rpc.sql>"
}
mcp__claude_ai_Supabase__apply_migration {
  name: "phase34a_dast_zap_dry_run_type",
  query: "<backend/database/phase34a_dast_zap_dry_run_type.sql>"
}
mcp__claude_ai_Supabase__apply_migration {
  name: "phase34b_cancel_scan_job_bind_project_id",
  query: "<backend/database/phase34b_cancel_scan_job_bind_project_id.sql>"
}
```

After all three apply, refresh schema.sql locally:

```
cd depscanner && npm run schema:dump
git add backend/database/schema.sql
```

Commit the schema dump in the same PR — CI fails otherwise.

Rollback: each migration is `CREATE OR REPLACE`-shaped on a new RPC name
(phase34, phase34b's cancel_scan_job is a separate signature). To revert
phase34a, drop the new CHECK and re-add the narrow one; any existing rows
with `type='dast_zap_dry_run'` would block that — find them with
`SELECT id FROM scan_jobs WHERE type='dast_zap_dry_run'` and either let
them drain or update to type='dast_zap'.

## Step 2 — Build + deploy the depscanner image

The ZAP base is **digest-pinned** (/criticalreview SVED-2):
`ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e...` (see `depscanner/Dockerfile`
header comment for the bump procedure). The auth-report-json shape v2.1d
parses is contractual; a future upstream rev could break it silently
without the pin.

Rebuild and deploy:

```
docker buildx build --platform linux/amd64 -t <registry>/deptex-depscanner:v2.1d depscanner/
# then fly deploy for the depscanner app
fly deploy --app deptex-depscanner
```

**Verify ALL machines are on the new image SHA before promoting backend.**
A scale-to-zero machine pinned to the previous revision will be restarted
on the SAME image (Fly machine restart does not pull a new image), so
list and confirm:

```
fly machines list --app deptex-depscanner
# expected: every row's image column matches the v2.1d SHA
```

If any machines still show the previous revision, force-restart them or
wait for the rolling deploy to complete.

## Step 2b — Deploy the backend (Vercel)

Deploy the backend **after** the depscanner image is fully rolled out.
`backend/src/routes/dast.ts` queuing `type='dast_zap_dry_run'` is the
critical change — only v2.1d workers advertise that type. If the backend
is promoted while old workers still exist, Test-login dry-run rows sit
queued; user-visible symptom is a 60-180s timeout with no banner.

## Step 3 — Verify the image

In a shell on the running depscanner machine (`fly ssh console`):

```
# ZAP version (pinned to 2.17.0 by the digest)
/zap/zap.sh -version
# expected: 2.17.0

# authhelper add-on present + version
/zap/zap.sh -addon-status authhelper 2>&1 | grep -i version
# expected: 0.39.0+

# the supportedTypes startup log shows the new type
# (look in `fly logs --app deptex-depscanner`)
# expected line: "supported_types=extraction,dast,dast_zap,dast_nuclei,dast_zap_dry_run"
```

## Step 4 — Smoke: Test-login dry-run against the fixture

Stand up the fixture login app locally OR against a public test target.
Configure a recorded credential on a project's DAST target with the right
selectors. Click the **Test login** button in the editor.

Expected:

- 202 from `POST /api/projects/:projectId/dast/targets/:targetId/credentials/test`
  with `{test_job_id, status:'queued'}`.
- Polling `GET /dast/jobs?id=<test_job_id>` shows the row transition
  `queued → processing → completed` within ≤90 seconds (p95 budget).
- Terminal state: `status='completed'`, `error_category=null`,
  `error_payload.kind='test_result'`,
  `error_payload.test_result.success=true` on a working credential.
- Editor banner: ✓ Logged in (XXs).

Failure-case smoke: configure a credential with a deliberately-bad
selector. Expected: `error_payload.test_result.success=false`,
`failed_at_step.reason='selector_not_visible_after_timeout'`, banner
displays the actionable failure reason.

## Step 5 — Smoke: cancel endpoint

While a Test-login or real scan is in `status='processing'`:

```
POST /api/projects/:projectId/dast/jobs/:jobId/cancel
```

Expected:

- 200 `{job_id, status:'cancelled'}` on a queued/processing job in the
  caller's project.
- 404 `{error:'job_not_found'}` on cross-project / cross-org / non-DAST
  job ID (the /criticalreview HEH-1 fix).
- 409 `{code:'job_not_cancellable', current_status:'<terminal>'}` on a
  job that exists in the caller's project but is already terminal.

The worker's existing `isJobCancelled()` poll reads the cancellation on
its next heartbeat tick (~5s) and short-circuits the scan loop.

## Step 6 — Smoke: real recorded-strategy scan (pre-flight producer)

Configure a working recorded credential. Trigger a **real** scan via
`POST /:projectId/dast/scan` (NOT Test-login). The /criticalreview RH-4
fix means the worker now runs the same `runRecordedLoginProbe` as a
pre-flight before spider/active-scan dispatch — on probe failure the
row finalizes with `error_payload.kind='pre_flight_failed'` and the
spider/scan never runs.

Test this by re-configuring the credential to have a broken selector,
then trigger a real scan. Expected:

- `status='failed'`, `error_category='auth_failed'`,
  `error_payload.kind='pre_flight_failed'`,
  `error_payload.failed_at_step` populated.
- No findings inserted; no PDV flip.
- Total duration ~ the probe budget (≤90s), NOT the scan timeout.

## Known limitations

- **DNS-rebinding TOCTOU.** Same as v2.1c — the pipeline re-resolves the
  target host + the credential's `login_page_url` immediately before
  ZAP spawn (/criticalreview ssrf-1 fix added the recorded-strategy
  re-check), but Firefox then resolves DNS itself per navigation. A
  short-TTL hostile record can rebind in the small window. Engine-agnostic;
  durable fix is an IP-pinning egress proxy (tracked follow-up).
- **Per-step failure attribution.** ZAP's `auth-report-json` exposes only
  a roll-up verdict — not which step failed. `failed_at_step.step_index`
  is always 0 on failure. AI selector-suggest is a v2.1e candidate.

## Rollback / escape hatch

If recorded login behaves badly in prod:

1. **Backend rollback (preferred):** revert the `POST /credentials/test`
   route addition. New Test-login attempts return 404. Existing in-flight
   probe jobs (max ~5min hard cap each) drain naturally.
2. **Worker image rollback:** Fly `fly deploy --image <prior digest>` —
   the depscanner image just before v2.1d. Old workers won't claim
   `dast_zap_dry_run` rows; they sit queued and time out via the
   stuck-job recovery cron (5min) → status='failed'.
3. **Migration rollback:** none of the three migrations break old code
   if rolled back. Cancel-RPC arity change (3 → 2 args) would break the
   v2.1d backend `cancel_scan_job` call; revert the backend first.

There is no per-org kill switch. The 1/project DAST concurrency cap
already gates blast radius — at worst one bad recorded credential
prevents that project from running DAST until corrected.
