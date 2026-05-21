# DAST v2.1d — Recorded Login Authentication — Implementation Plan (v3)

> Brief: `.cursor/plans/feature-brief-dast-v2-1d-recorded-login.md` (locked).
> Reviews: v1 → REWORK (5 P0s); v2 → REWORK (5 P0s, mostly schema-correctness); v3 = this — patched against both reviews.
> Branch base: `origin/main` @ `43c9ddf` (v2.1c MERGED).
> Worktree: `.claude/worktrees/dast-v2-1d-recorded-login` / branch `worktree-dast-v2-1d-recorded-login`.

## Overview

Add a 4th DAST auth strategy — `recorded` — that lets a user author an ordered step list (CLICK / TYPE-USERNAME / TYPE-PASSWORD / TYPE-TOTP / TYPE-CUSTOM / WAIT / RETURN / ESCAPE with CSS or XPath selectors) inline in `DastAuthPanel.tsx`. The depscanner ZAP path translates the step list into ZAP's Automation Framework `browser` authentication method block (`firefox-headless`, already in the image — installability + CLICK/TYPE replay + AF fail-fast semantics all confirmed in M0). The "Test login" button queues a regular `dast_zap` scan job carrying `payload.dry_run: true`; `runDastPipeline` branches early on that flag, builds a login-only YAML, runs only the auth replay + `requestor` indicator probe, writes the test result to `scan_jobs.error_payload` under a `kind: 'test_result'` discriminated variant, finalizes `status='completed'`, and short-circuits BEFORE any spider/active-scan code runs and BEFORE any `findings`/`PDV` mutation. On a normal scan, the same auth-context block is reused as a pre-flight inside the **same ZAP process** as the spider/active-scan (one autorun YAML), then the spider/active-scan continues — no double cold-start, no doubled `scan_timeout_minutes` budget. Pre-flight failure halts subsequent ZAP jobs via the M0-verified mechanism (Spike-5: `onFail: exit` on the `requestor` job, or a worker-side two-YAML-one-daemon flow if AF doesn't support it). Nuclei aborts on `recorded` with the v2.1c actionable error. TOTP supported via an encrypted `totp_secret` and ZAP's native `TOTP_FIELD` step. Cross-origin SSO supported (Spike-2 outcome shapes the `sso_origins[]` field — pre-baked optional regardless). Session-loss mid-scan triggers a bounded re-login (existing `retry_login_on_lost` column; Spike-2B verifies). All credential material encrypted in `project_dast_credentials.encrypted_payload`. **Zero SQL migrations on data tables.** One small RPC + route addition: `cancel_scan_job` + `POST /dast/jobs/:jobId/cancel` (the existing UX gap of "cancel a running scan" that the test-login concurrency mitigation depends on).

## Competitive Research & Design Rationale

(Full landscape in the brief.) Two design moves from research:

1. **Engine: ZAP `browser` AF method, not HAR replay.** Confirmed by [ZAP docs](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/browser-auth/) — step types `USERNAME` / `PASSWORD` / `TOTP_FIELD` / `CLICK` / `WAIT` / `CUSTOM_FIELD` / `RETURN` / `ESCAPE` / `AUTO_STEPS` map 1:1 to our step editor. HAR replay rejected because tokens regenerate per session.
2. **Pre-scan auth probe + Test-login = same probe, two entry paths.** Burp's "status checker" is the de-facto pattern. We share ONE function (`runRecordedLoginProbe`) between the dry-run job and the pre-flight step inside a real scan.

## Codebase Analysis

### Files we will modify

| File | Why |
|---|---|
| `backend/src/types/dast.ts` | Widen `DastAuthStrategy` to include `'recorded'`. Add `RecordedCredentialPayload` to `DastCredentialUpsertPayload` (incl. `sso_origins?: string[]`, `label?: string`). Add the discriminated `DastJobErrorPayload` union (see §Data Model). Add `DastLoginTestResult` shape. Add `DastJobPayloadSchema` (Zod or hand-rolled) — incl. `dry_run?: boolean`, `source?: ...` — to eliminate typo risk on the dispatch flag. |
| `backend/src/lib/dast-credential-validate.ts` | Add `'recorded'` to `VALID_STRATEGIES`; extend `checkShape` and `summarizePayload` for recorded. Add `validateRecordedSteps` with the bounds in §Data Model. Add Spike-4 grep-verify as the first line of M1 (confirms `'recorded'` is in the `auth_strategy` CHECK). |
| `backend/src/routes/dast.ts` | (a) Extend `PUT /credentials` to accept `recorded`. (b) Add `POST /credentials/test` → queue a `dast_zap` job with validated `payload={dry_run:true, source:'credential_test', ...}` and call `startDastMachine(detected_runtime)` — **on `startDastMachine` failure, return `503 fly_machine_unavailable` and either delete the queued row or mark it `failed`** (the existing scan-route's warn-and-keep posture is incompatible with the 60s Test-login budget). (c) Engine validator: reject `engine='nuclei' + auth_strategy='recorded'` (fetch `auth_strategy` via a second guarded query — do NOT widen `loadTargetOrDeny`). (d) Audit-log row on PUT (redacted summary) and POST `/test` (job_id only). (e) **Widen `GET /dast/jobs` SELECT to include `error_payload`**, mirrored into `DastJobDTO`. |
| `backend/src/routes/dast.ts` (cancel surface) | (f) Add `POST /api/projects/:projectId/dast/jobs/:jobId/cancel`. Permission: `manage_integrations`. Calls `cancel_scan_job` RPC. Writes audit-log entry. Returns `200 {status:'cancelled'}` on success, `409 job_not_cancellable` if status NOT IN ('queued','processing'). |
| `backend/database/phase34_cancel_scan_job_rpc.sql` | New **small** migration: `CREATE OR REPLACE FUNCTION cancel_scan_job(p_job_id uuid, p_organization_id uuid) RETURNS scan_jobs LANGUAGE plpgsql SECURITY DEFINER` — atomically sets `status='cancelled'`, `completed_at=NOW()` when status IN ('queued','processing') AND the row's org matches (defense-in-depth on top of the route's org check). No CHECK changes; no signature changes to other RPCs. Self-contained. The worker's existing `isJobCancelled` poll (pipeline.ts:1099-1101) reads the resulting status. |
| `depscanner/src/dast/auth-config.ts` | Replace the `recorded` `UnsupportedAuthStrategyError` throw with `buildRecordedAuthForZap(payload): {contextAuthentication, contextUsers, internalIndexToZapIndex}`. `buildNucleiAuthHeaders` keeps throwing on recorded. |
| `depscanner/src/dast/yaml-builder.ts` | Branch on `authStrategy === 'recorded'`: call `buildRecordedAuthForZap()`; emit `authhelper` in `addOns` only if Spike-1 outcome says AF install path works; emit a `requestor` AF job post-auth that issues a GET against `loginPageUrl` so `verification.loggedInRegex` fires (with `onFail: exit` per Spike-5 outcome). For dry-run YAML (`loginOnly: true`): omit spider/spiderAjax/activeScan/report. For normal scans: same auth-context block + same `requestor` probe + spider/scan jobs in one autorun. Reduce `activeScan.maxScanDurationInMins` by 3 (auth budget reserve) for recorded strategy. |
| `depscanner/src/dast/pipeline.ts` | Add `runRecordedLoginProbe(target, cred, controlPlane): Promise<DastLoginTestResult>` — the shared core. **Top of `runDastPipeline`, immediately after credential decrypt, branch on `job.payload.dry_run === true`** with an explicit early-exit (see §M3.3 code sketch). |
| `depscanner/src/dast/runner.ts` | New `parseZapLoginDiagnostics(rawDiagnosticLog: string, internalIndexToZapIndex: number[]): DastLoginTestResult` — fixture-corpus-driven per Spike-3 outcome. Applies `redactCredentials()` to every string field. Best-effort populates `failed_at_step.dom_excerpt?: string` (≤1KB redacted) when the diagnostic log carries surrounding HTML — reservation for future Aegis selector-suggest assistant. |
| `depscanner/Dockerfile` | Per Spike-1 outcome: install geckodriver/selenium-server if needed; bake `authhelper` JAR unconditionally to remove per-cold-start download tax. |
| `frontend/src/lib/api.ts` | Mirror TS types, add `postDastLoginTest`, `cancelDastJob`. Widen `DastJobDTO` to include `error_payload: DastJobErrorPayload | null`. Widen `DastAuthStrategy`. |
| `frontend/src/components/dast/DastAuthPanel.tsx` | Add `'recorded'` to `STRATEGY_OPTIONS`, wire `<RecordedStrategyEditor>`. |
| `frontend/src/components/dast/RecordedStrategyEditor.tsx` | New — step list + credentials + TOTP + timing + Test-login button + result banner. Cancel-running-scan affordance on 409 (calls `cancelDastJob`). Render switches on `error_payload.kind`. |
| `frontend/src/hooks/useJobResult.ts` | **NEW hook used only by the new editor in v1.** Backoff 1.5s → 5s → 15s; max 5 min; AbortController on unmount; Supabase Realtime + fallback poll. **DastScanningTab.tsx NOT refactored in this PR** (deferred to post-launch when both consumers exist). |
| `frontend/src/components/dast/__tests__/RecordedStrategyEditor.test.tsx` | RBAC, dirty Save, step add/remove/reorder, validation (`goto` at index >0), Test-login state machine, polling timeout/abort/network-error, 409 → cancel affordance flow, render switches on `error_payload.kind`. |
| `docs/runbooks/dast-v2-1d-recorded-login.md` | Selector authoring tips, common SSO patterns, troubleshooting `failed_at_step` reasons, TOTP secret format, cancel-affordance flow. |
| `docs/spikes/dast-v2-1d-spikes.md` | M0 outcomes (consolidated empirical session for Spike-1+3+5; Spike-2 + 2B). |

### Files we will NOT touch (with reasons)

- **No data-table migrations.** `project_dast_credentials.auth_strategy` CHECK already includes `'recorded'` (Spike-4 verifies in M1). `scan_jobs.type` stays at the current four values. `queue_scan_job` RPC body unchanged. `scan_jobs_dast_columns_match_type` CHECK unchanged. The ONLY migration in v2.1d is the `cancel_scan_job` RPC create (self-contained, no schema overlap with v2.1c-era objects).
- `loadTargetOrDeny` — kept single-SELECT (timing-side-channel posture preserved). Callers fetch `auth_strategy` via a second guarded query.
- `DastScanningTab.tsx` — not refactored in this PR. `useJobResult` ships as a new hook used only by the recorded-login editor; the dedup pass is a post-launch chore.
- `finalize_dast_login_test` SQL helper — not created; existing `finalizeJob` / `recordJobError` helpers handle both paths.

### Patterns we'll follow

- **Credential validation:** mirror `validateAndPrepareCredential`'s `{ok, payload, serializedPlaintext, summary}` envelope.
- **Pipeline entry:** `runDastPipeline` branches at the top on `job.payload.dry_run`. Both branches use the shared `runRecordedLoginProbe` for the auth+verification probe. Real-scan path appends spider/scan jobs in the same autorun YAML.
- **Result storage:** discriminated union `error_payload.kind` — `'test_result'` (dry-run completion, success or fail); `'pre_flight_failed'` (real-scan recorded-auth failure); `'session_loss'` (existing form-strategy mid-scan auth-lost shape). FE renderer switches on `kind`.

## Pre-flight Spikes (Milestone 0)

Consolidated to **2 empirical sessions** (~3h total) — down from v2's 4 spikes.

### M0-Session-A: ZAP browser-auth empirical session (~2h)

ONE fixture YAML run captures all of Spike-1, Spike-3, and Spike-5 outcomes.

**Spike-1 (image replay):** Stand up a 3-page static fixture (form with `#email`, `#pass`, `button[type=submit]`); write a minimal AF YAML using `browser` auth with `loginPageUrl` + 3 steps; run `zap.sh -cmd -autorun` inside the depscanner image. **Tight success criterion (all three must hold):** (a) ZAP exits with code 0; (b) stderr/diagnostic log contains a literal marker indicating browser-auth ran (capture the exact marker string in the spike doc); (c) `verification.loggedInRegex` set to a user-specific string only present post-login (e.g. "Welcome, alice") matches. Outcome decides: AF install path works → no Dockerfile change beyond baking `authhelper`; addon installs but CLICK fails → add geckodriver/selenium-server; addon install itself fails → bake JAR.

**Spike-3 (diagnostic log capture):** Same fixture, run TWICE — once green (3 steps succeed) and once red (bad selector on step 2). Capture raw `diagnostics: true` output (file path or stdout/stderr) to `depscanner/test/fixtures/zap-login-diagnostics/<exact-ZAP-version>/{success,selector_not_visible}.log`. Outcome decides `parseZapLoginDiagnostics` contract: structured / semi-structured / unstructured.

**Spike-5 (AF fail-fast):** Extend the failure-run YAML with a spider + active-scan job appended after the `requestor` verification probe. Verify: does ZAP halt spider/active-scan when verification regex misses? Outcome decides:
- **Green:** `onFail: exit` on the requestor job aborts subsequent jobs cleanly → emit it in M2 YAML. Same-process pre-flight + scan works.
- **Yellow:** ZAP runs subsequent jobs regardless of `onFail` → fall back to a worker-side two-YAML-one-daemon flow (run login-only YAML, parse, on success spawn a separate scan YAML in the same ZAP daemon via a second `-autorun` invocation if ZAP supports it, otherwise accept a separate-process scan). Document the chosen path.
- **Red:** No way to chain; recorded-strategy real scans use TWO ZAP invocations (login-only YAML → exit → real-scan YAML). NFR adjusts accordingly (`scan_timeout_minutes` budget split documented).

**Deliverable:** `docs/spikes/dast-v2-1d-spikes.md` records all three outcomes, the exact log markers, the parser contract, and the AF-fail-fast resolution. Commits the fixtures.

### M0-Session-B: cross-origin SSO + session-loss re-trigger (~1h)

**Spike-2 (SSO scope):** AF YAML with `includePaths` pinned to one origin + `browser` auth navigating off-origin mid-flow. Verify scope behaviour. Outcomes: green = no schema change; yellow = `sso_origins[]` populates widened `includePaths` for auth phase + `pruneSiteTree` AF job narrows pre-spider.

**Spike-2B (session-loss re-trigger):** AF YAML against a short-TTL-cookie fixture; let scan exceed TTL; inspect for browser-auth re-login. Outcomes: green = `retry_login_on_lost` works for recorded; yellow = document as v1 limitation; Success Criterion #6 moves to v2.1e.

**Side-task during Session-B (~5 min):** Spike-4 grep-verify — Read `backend/database/phase24a_dast_v2_engine_additive.sql:130-145` and confirm `'recorded'` is in the `auth_strategy` CHECK. (Spike-4 from v2 plan folded here to avoid a separate milestone bullet.)

**Side-task during Session-B (~10 min):** also verify whether v2.1c added a `runtime_confirmed_via_auth` column on PDVs (opportunity-scout-r2-f6). If present, M3 finalize sets the marker for recorded scans flipping PDVs; if absent, defer to a v2.1e card.

### Output of M0 → 2-3 commits

- `chore(dast): commit v2.1d preflight spike outcomes (auth, diagnostics, AF fail-fast)`
- `chore(dast): commit cross-origin SSO + session-loss spike outcomes`

M1 starts after M0; M2-M7 gate on M0 fully complete.

## Data Model

### No data-table migrations

`project_dast_credentials.auth_strategy` CHECK already accepts `'recorded'`. `scan_jobs.type` stays at its current four values. All state lives in encrypted_payload (ciphertext) or `payload` / `error_payload` JSONB.

### One small RPC migration

`backend/database/phase34_cancel_scan_job_rpc.sql`:

```sql
-- Phase 34 (v2.1d): cancel_scan_job RPC for user-initiated cancellation
-- of queued or processing scan_jobs rows. Atomically flips status to
-- 'cancelled'; the worker reads this status via isJobCancelled() and
-- short-circuits its scan loop. The org_id parameter defends-in-depth
-- on top of the route handler's tenant check.

CREATE OR REPLACE FUNCTION cancel_scan_job(
  p_job_id          UUID,
  p_organization_id UUID
)
RETURNS SETOF scan_jobs
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
    UPDATE scan_jobs
       SET status = 'cancelled',
           completed_at = NOW()
     WHERE id = p_job_id
       AND organization_id = p_organization_id
       AND status IN ('queued', 'processing')
     RETURNING *;
END;
$$;

REVOKE ALL ON FUNCTION cancel_scan_job(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cancel_scan_job(UUID, UUID) TO authenticated, service_role;

COMMENT ON FUNCTION cancel_scan_job IS
  'Phase 34 (v2.1d): atomically cancel a queued/processing scan_jobs row scoped to the caller org. Returns the updated row, or empty set if the job is not in a cancellable state or org mismatch.';

-- After applying: refresh schema.sql via `cd depscanner && npm run schema:dump`.
```

PostgREST signature: `(uuid, uuid) → setof scan_jobs`. No existing signature collision. PGLite test asserts (a) queued/processing → cancelled, (b) completed/failed/cancelled rows untouched (RETURNING empty), (c) cross-org call returns empty even with valid job id.

### Payload shape (TS only)

```ts
// backend/src/types/dast.ts

export interface RecordedCredentialPayload {
  kind: 'recorded';
  login_page_url: string;
  steps: RecordedStep[];        // 1..50
  username: string;
  password: string;
  totp_secret?: string;
  login_page_wait_ms?: number;  // default 5000, [0, 30000]
  step_delay_ms?: number;       // default 0, [0, 5000]
  label?: string;               // ≤80 chars (per opportunity-scout-f6)
  sso_origins?: string[];       // forward-compat per Spike-2; max 5; each https
}

export type RecordedStepAction =
  | 'goto'            // ONLY valid as steps[0]
  | 'click'
  | 'type_username'
  | 'type_password'
  | 'type_totp'
  | 'type_custom'     // REDACTED in summaries + logs
  | 'wait'
  | 'return'
  | 'escape';

export interface RecordedStep {
  action: RecordedStepAction;
  selector?: string;
  selector_kind?: 'css' | 'xpath';     // default 'css'
  value?: string;
  timeout_ms?: number;                  // default 1000, [100, 30000]
  wait_ms?: number;                     // [0, 30000]
}

export type DastCredentialPayloadSummary =
  | { kind: 'form'; username_masked: string }
  | { kind: 'jwt'; token_prefix: string; token_length: number; expires_in_minutes: number }
  | { kind: 'cookie'; cookie_count: number; cookie_names: string[] }
  | { kind: 'recorded'; step_count: number; has_totp: boolean; login_page_url_host: string; label?: string };

export type DastAuthStrategy = 'form' | 'jwt' | 'cookie' | 'recorded';

// Discriminated union for scan_jobs.error_payload — replaces the previously-overloaded shape.
export type DastJobErrorPayload =
  | { kind: 'session_loss'; consecutive_lost_count: number; last_logged_out_url?: string; last_logged_out_at?: string }      // existing form-strategy shape
  | { kind: 'pre_flight_failed'; failed_at_step: FailedAtStep; consecutive_lost_count: 0 }                                   // NEW: recorded-strategy pre-flight on a real scan
  | { kind: 'test_result'; test_result: DastLoginTestResult };                                                                // NEW: dry-run job completion (success OR fail)

export interface FailedAtStep {
  step_index: number;          // UI-coordinate (0-indexed against payload.steps)
  action: RecordedStepAction;
  selector?: string;
  reason:
    | 'selector_not_visible_after_timeout'
    | 'cross_origin_blocked'
    | 'totp_generation_failed'
    | 'browser_crashed'
    | 'logged_in_indicator_missed'
    | 'logged_out_indicator_present_after_login'
    | 'unknown';
  detail?: string;             // redacted
  dom_excerpt?: string;        // ≤1KB redacted; reserved for v2.1e Aegis selector-suggest
}

export interface DastLoginTestResult {
  success: boolean;
  duration_ms: number;
  steps_run: number;
  step_index?: number;
  failed_at_step?: FailedAtStep;
  raw_log?: string;            // present in Spike-3 unstructured outcome
}

// Validates scan_jobs.payload at queue time + worker re-load (defense-in-depth against typos).
export interface DastJobPayloadSchema {
  target_url?: string;
  scan_profile?: 'auto' | 'quick' | 'full' | 'api';
  scan_timeout_minutes?: number;
  detected_runtime?: 'unknown' | 'classic' | 'spa';
  source?: 'manual_dast_scan' | 'credential_test' | 'webhook' | 'scheduled' | 'on_deploy' | 'aegis';
  dry_run?: boolean;
  engine?: 'zap' | 'nuclei';
}
```

### `goto` step mapping decision

`goto` is **only valid as `steps[0]`** — validator rejects with `error_code='invalid_credential_shape'`, `detail='goto only valid as the first step; intermediate navigation must use click'` if at index > 0.

Step → ZAP mapping table (`buildRecordedAuthForZap`):

| Our step | ZAP step | Notes |
|---|---|---|
| `goto` (steps[0] only) | `loginPageUrl` parameter on the auth method | Collapsed into context's auth-method config |
| `click` | `CLICK` | CSS or XPath |
| `type_username` | `USERNAME` | Selector + credential ref |
| `type_password` | `PASSWORD` | Selector + credential ref |
| `type_totp` | `TOTP_FIELD` | Selector + decrypted TOTP secret |
| `type_custom` | `CUSTOM_FIELD` | Selector + literal value (REDACTED in logs) |
| `wait` | `WAIT` | wait_ms |
| `return` | `RETURN` | Enter |
| `escape` | `ESCAPE` | Escape |

`internalIndexToZapIndex[i]` maps UI step list position → ZAP step array position (off-by-one when step[0]=`goto` is collapsed). Computed ONCE in `buildRecordedAuthForZap()`, held in `runRecordedLoginProbe`'s local scope, passed explicitly to `parseZapLoginDiagnostics(rawLog, internalIndexToZapIndex)`. Never serialised into the YAML; never stored in the DB; re-derived deterministically on retry from the same encrypted payload (unit-tested for determinism).

### `error_payload` discriminated namespace

For dry-run jobs (`payload.dry_run=true`):
- **Success:** `status='completed'`, `error_category=NULL`, `error_payload={"kind":"test_result", "test_result": {success:true, ...}}`.
- **Failure:** `status='completed'`, `error_category=NULL`, `error_payload={"kind":"test_result", "test_result": {success:false, failed_at_step:{...}, ...}}`.

For normal scans with `auth_strategy='recorded'` where pre-flight probe fails:
- `status='failed'`, `error_category='auth_failed'`, `error_payload={"kind":"pre_flight_failed", "failed_at_step":{...}, "consecutive_lost_count":0}`.

For session-loss exhaustion mid-scan (existing form-strategy + new recorded-strategy):
- `status='failed'`, `error_category='auth_failed'`, `error_payload={"kind":"session_loss", "consecutive_lost_count":N, "last_logged_out_url":"...", "last_logged_out_at":"..."}`.

Frontend renderer switches on `error_payload.kind`. Update `phase24a_2_dast_v2_engine_pipeline.sql`'s `COMMENT ON COLUMN scan_jobs.error_payload` (docs-only refresh via `schema:dump`; no migration on the column itself).

### Concurrency

Dry-run `dast_zap` jobs count against existing 1/project + 5/org caps (intentional — credential races + Fly machine economy). Mitigation: the **new POST `/dast/jobs/:jobId/cancel` route** (M4) lets the user cancel a running real scan to free the slot for Test-login. UI surfaces a "Cancel running scan" link on the editor's 409 banner; click → calls `cancelDastJob` → worker reads `isJobCancelled` next heartbeat → scan terminates → editor retries Test-login automatically. No `queue_scan_job` body change required.

## API Design

### Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| PUT | `/api/projects/:projectId/dast/targets/:targetId/credentials` | JWT | `manage_integrations` | Accepts `auth_strategy: 'recorded'`. Skip `runFormProbe` for recorded. Audit-log written to `organization_activities` with redacted summary (step_count, has_totp, login_page_url_host, label?). NO selectors, NO values, NO secrets. |
| POST | `/api/projects/:projectId/dast/targets/:targetId/credentials/test` | JWT | `manage_integrations` | **NEW.** Queue `dast_zap` job with `payload={dry_run:true, source:'credential_test', detected_runtime}`. Call `startDastMachine(detected_runtime)` — **on failure return 503 `fly_machine_unavailable` and delete the queued row** (synchronous fail; Test-login budget doesn't tolerate Fly outages silently). Return `202 {test_job_id, status:'queued'}`. Audit-log row. |
| GET | `/api/projects/:projectId/dast/jobs?id=…` | JWT | `manage_integrations` | **MODIFIED.** Widen SELECT to include `error_payload`. `DastJobDTO` gains `error_payload: DastJobErrorPayload \| null`. FE renderer switches on `kind`. |
| POST | `/api/projects/:projectId/dast/jobs/:jobId/cancel` | JWT | `manage_integrations` | **NEW** (B4). Calls `cancel_scan_job(p_job_id, p_organization_id)` RPC. Returns `200 {status:'cancelled'}` if cancelled, `409 job_not_cancellable` if status NOT IN ('queued','processing'), `404 job_not_found` for cross-org or missing. Audit-log row with `{event:'dast_scan.cancelled', job_id}`. Also: emit a `dast_login_test.completed` activity event on dry-run completions (per opportunity-scout-r2-f7) — added in M3 finalize, not on this route. |
| GET | `/api/projects/:projectId/dast/targets/:targetId/credentials` | JWT | `manage_integrations` | Summary returns recorded variant (host only). |
| DELETE | `…/credentials` | JWT | `manage_integrations` | Unchanged. |
| POST | `/api/projects/:projectId/dast/scan` | JWT | `manage_integrations` | **MODIFIED.** If `engine='nuclei' && auth_strategy==='recorded'`, reject with `400 unsupported_recorded_on_nuclei`. `auth_strategy` fetched via a second guarded query (not via `loadTargetOrDeny`). |

### Request/response types

```ts
interface DastLoginTestResponse {
  test_job_id: string;
  status: 'queued';
}

interface DastJobCancelResponse {
  job_id: string;
  status: 'cancelled';
}
```

Polled job returns `error_payload: DastJobErrorPayload | null` per the discriminated union.

## Frontend Design

### Pages & routes

No new routes. Editor lives inline in `DastAuthPanel.tsx`.

### Component tree

```
DastAuthPanel
  StrategyPicker (form | jwt | cookie | recorded)
  CurrentCredentialSummary?
  FormStrategyFields | JwtStrategyFields | CookieStrategyFields | RecordedStrategyEditor   ← NEW
    LabelInput  (≤80 chars)
    LoginPageUrlField
    StepList (sortable via up/down chevrons)                                                ← NEW
      StepRow
        StepActionSelect
        SelectorInput (CSS | XPath toggle; hidden for wait/return/escape/goto)
        ValueInput  (goto / type_custom; for type_custom, input type=password)
        TimeoutInput / WaitInput
        RemoveStepButton
      AddStepButton
    CredentialsBlock (Username, Password, TotpSecret)
    TimingBlock (LoginPageWaitMs, StepDelayMs)
    TestLoginButton  → POST /credentials/test → useJobResult(test_job_id) → ResultBanner
      ResultBanner — switches on error_payload.kind:
        kind='test_result' + success → "Logged in (took 7.4s, 5 steps)"
        kind='test_result' + !success → "Step 4 (click): selector `#submit` not visible after 1000ms" + raw_log toggle
        409 dast_target_busy → "A scan is running on this target. [Cancel scan] to test."
  IndicatorFields (logged-in / logged-out)
  ResultBanner (save/remove status — existing)
  ActionButtons (Save / Remove)
```

### `useJobResult` shared hook

**New hook in `frontend/src/hooks/useJobResult.ts`, consumed only by `RecordedStrategyEditor` in v1.** Signature:

```ts
function useJobResult<T = unknown>(
  jobId: string | null,
  opts: { onTerminal?: (job: JobRow) => void; maxWaitMs?: number; pollFallback?: boolean }
): { status: 'idle' | 'polling' | 'completed' | 'failed' | 'cancelled' | 'timeout' | 'error'; job?: JobRow; error?: Error };
```

Backoff 1.5s → 5s → 15s; default `maxWaitMs` 5 min; AbortController on unmount; "Still running…" past 90s without ending the poll. **`DastScanningTab.tsx` is NOT refactored in this PR** (per pragmatist-f5) — leaves zero refactor blast radius on existing v2.1c surface. Refactor lands post-launch when both consumers exist.

### Design specifications

- Step list: `divide-y divide-border`. Up/down chevrons (16px, `text-foreground-muted` → hover `text-foreground`).
- Test-login button: `<Button variant="outline" size="sm">Test login</Button>`. Disabled while in flight or while a real scan is running on this target. When disabled because of 409: shows inline "Cancel running scan" link.
- Result banner: emerald-500 success / destructive failure. Failure shows step/action/reason in mono + "Show raw log" expandable if `raw_log` present.
- "Currently testing" row: `bg-amber-500/10`. Failed step: `border-l-2 border-destructive`.
- Empty state (strategy switch): one starter step `{action:'goto', value:''}`.
- TOTP input: monospace, base32 hint, `?` tooltip.
- Card layout + dirty-check Save + fixed-width spinner per `account_settings_parity_standard`.

### Edge UI cases

- Step count > 50 → client-side block.
- Missing selector on click/type_* → red border + inline error.
- `goto` at index > 0 → red border + inline "Only step 1 can be 'Go to URL'; use 'Click' to navigate".
- Test-login result older than 5 min → "stale — re-test recommended" hint.
- Save without test → yellow banner "Save anyway?" with [Cancel] [Save without testing].
- 409 dast_target_busy → "A scan is running. [Cancel scan] to test." Click → calls `cancelDastJob` → polls until scan reaches `cancelled` → automatically retries the test.

## Implementation Tasks

**Branching:** one branch (`worktree-dast-v2-1d-recorded-login`), no children. Each task is a single commit (Conventional Commits, no milestone labels, no Claude trailer).

### M0 — Pre-flight spikes (M, ~3h)

- [ ] **0.1** Session-A: stand up 3-page fixture; run ZAP browser-auth YAML (success + failure runs); capture diagnostic logs to `depscanner/test/fixtures/zap-login-diagnostics/<ZAP-version>/`. Resolve Spike-1 (Dockerfile change list + `authhelper` bake decision), Spike-3 (parser contract: structured / semi / unstructured), Spike-5 (AF fail-fast: `onFail: exit` works / fall back to two-YAML-one-daemon / fall back to two ZAP invocations). (M, ~2h)
- [ ] **0.2** Session-B: cross-origin SSO scope (Spike-2); session-loss re-trigger (Spike-2B); Spike-4 grep-verify of `auth_strategy` CHECK; check for `runtime_confirmed_via_auth` column existence (opportunity-scout-r2-f6). (M, ~1h)
- [ ] **0.3** Write + commit `docs/spikes/dast-v2-1d-spikes.md` with all outcomes, exact log markers, parser contract, AF resolution, Dockerfile change list. Lock decisions before M1+.
- [ ] **Commits:** `chore(dast): commit v2.1d preflight outcomes` (×1-2 split as natural)

### M1 — Types + validator (M, 3-4h)

- [ ] **1.0** Spike-4 grep-verify (folded from v2's separate spike): Read `backend/database/phase24a_dast_v2_engine_additive.sql:130-145`; confirm `'recorded'` in CHECK. (S, 5 min)
- [ ] **1.1** `backend/src/types/dast.ts`: widen `DastAuthStrategy`, add `RecordedCredentialPayload` (`sso_origins`, `label`), widen `DastCredentialPayloadSummary`. Add `DastJobErrorPayload` discriminated union (`session_loss`, `pre_flight_failed`, `test_result` variants). Add `FailedAtStep`, `DastLoginTestResult`, `DastJobPayloadSchema`. (M)
- [ ] **1.2** `backend/src/lib/dast-credential-validate.ts`: add `'recorded'` to `VALID_STRATEGIES`. `validateRecordedSteps(payload)`:
  - step count [1, 50]; `goto` only at steps[0]
  - selector required for click / type_*; ≤ 1024 chars; no NUL / control chars
  - `selector_kind` ∈ {css,xpath}
  - `value` required for goto + type_custom
  - `timeout_ms` ∈ [100, 30000]; `wait_ms` ∈ [0, 30000]
  - `login_page_url` is https
  - `login_page_wait_ms` ∈ [0, 30000]; `step_delay_ms` ∈ [0, 5000]
  - `totp_secret` matches `/^[A-Z2-7]{16,256}$/` if present
  - `label` ≤ 80 chars; `sso_origins` ≤ 5 entries, each https
  - serialized plaintext ≤ 64 KB
  - `logged_in_indicator` / `logged_out_indicator` pass `safe-regex2`
- [ ] **1.3** Extend `checkShape` + `summarizePayload` for recorded.
- [ ] **1.4** Add `validateDastJobPayload(payload)` consuming `DastJobPayloadSchema`. Route uses it at queue time; worker uses it after job load (defense-in-depth against typo'd `dry_run` keys). (S)
- [ ] **1.5** Unit tests `dast-credential-validate.recorded.test.ts` — ≥18 cases:
  - 1 valid, boundary on step_count (0/1/50/51), selector_length (0/1023/1024/1025), timeout_ms (-1/0/100/30000/30001/NaN/Infinity), `goto` at 0 vs 2, `type_custom` w/o value, oversize encoded (>64KB), TOTP non-base32 / unicode, non-https URLs, invalid `selector_kind`, missing username for `type_username` step, regex-DoS on `logged_in_indicator`, `label` >80, `sso_origins` >5
  - + tests for `validateDastJobPayload`: `dry_run` true/false/missing/typo'd (`dryRun`, `dry-run`) all handled correctly
- [ ] **Commit:** `feat(dast): widen credential validator + payload schema for recorded strategy`

### M2 — ZAP auth-config + YAML builder (L, 3-4h, gated on M0)

- [ ] **2.1** `depscanner/src/dast/auth-config.ts`: `buildRecordedAuthForZap(payload)` returns `{contextAuthentication, contextUsers, internalIndexToZapIndex}`. Per-step mapping per §Data Model table. (M)
- [ ] **2.2** Unit tests `dast-recorded-auth.test.ts`:
  - every action maps to right ZAP step type
  - `internalIndexToZapIndex` deterministic over same payload (replay-safe)
  - cross-origin `sso_origins` (Spike-2 yellow) → widened `includePaths`
  - missing selector / invalid timeout → typed error
- [ ] **2.3** `depscanner/src/dast/yaml-builder.ts`:
  - branch on `authStrategy === 'recorded'`
  - addOns includes `authhelper` only if Spike-1 outcome says AF install works (else Dockerfile bake + omit from list)
  - emit `requestor` AF job post-auth with `onFail: exit` per Spike-5 outcome (or worker-side gating if Spike-5 yellow/red — both supported by yaml-builder via a `loginOnly` flag)
  - `loginOnly: true` → omit spider/spiderAjax/activeScan/report
  - normal scan: same auth context + requestor probe + spider/scan jobs in one autorun (or two-YAML flow per Spike-5)
  - reduce `activeScan.maxScanDurationInMins` by 3 for recorded strategy (auth budget reserve)
- [ ] **2.4** Snapshot tests `dast-yaml-builder-recorded.test.ts`:
  - 9 per-action minimal-emit snapshots (one snapshot per action as sole step) — diff-readable per action mapping
  - all 9 actions in one composite YAML
  - XPath selector_kind variant
  - normal-scan YAML with recorded auth (asserts `requestor` job present, `activeScan.maxScanDurationInMins` reduced by 3)
  - sso_origins-populated YAML (if Spike-2 yellow)
- [ ] **2.5** `depscanner/Dockerfile` deltas per Spike-1: bake `authhelper`; add geckodriver/selenium-server if needed. Only the diff lines, no churn.
- [ ] **Commit:** `feat(dast): emit ZAP browser-auth YAML from recorded credentials`

### M3 — Pipeline: dry-run branch + parser (L, 4-5h, gated on M0)

- [ ] **3.1** `depscanner/src/dast/runner.ts`: `parseZapLoginDiagnostics(rawDiagnosticLog, internalIndexToZapIndex)` per Spike-3 contract. Applies `redactCredentials()` to every string field. Best-effort populates `failed_at_step.dom_excerpt?` (≤1KB redacted) when Spike-3 outcome includes HTML context. For multi-replay logs (Spike-2B re-login interleave), returns FIRST replay's verdict; subsequent re-logins go through the `session_loss` envelope. (M)
- [ ] **3.2** `depscanner/src/dast/pipeline.ts`: `runRecordedLoginProbe(target, credential, controlPlane): Promise<DastLoginTestResult>` — shared core. Holds `internalIndexToZapIndex` in local scope, passes to parser. (M)
- [ ] **3.3** `runDastPipeline` dispatch — explicit code-shape sketch baked into the implementation:
  ```ts
  // top of runDastPipeline, after credential decrypt, BEFORE any YAML emit:
  const payload = validateDastJobPayload(job.payload);  // throws on schema drift
  if (payload.dry_run === true) {
    const probeResult = await runRecordedLoginProbe(target, credential, controlPlane);
    await supabase.from('scan_jobs').update({
      status: 'completed',
      error_payload: { kind: 'test_result', test_result: probeResult } satisfies DastJobErrorPayload,
      findings_count: 0,
      duration_seconds: Math.round(probeResult.duration_ms / 1000),
      completed_at: new Date().toISOString(),
    }).eq('id', job.id);
    // emit dast_login_test.completed activity event
    await supabase.from('organization_activities').insert({
      organization_id: job.organization_id,
      event: 'dast_login_test.completed',
      payload: { test_job_id: job.id, success: probeResult.success, reason: probeResult.failed_at_step?.reason },
    });
    return; // NEVER spider, NEVER scan, NEVER call populateDependencies, NEVER flip PDVs
  }
  // normal-scan path: recorded auth → pre-flight probe inside the autorun YAML;
  // failure → finalize with error_payload: { kind: 'pre_flight_failed', failed_at_step, consecutive_lost_count: 0 }
  // success → continue spider/scan in same ZAP process (or two-YAML flow per Spike-5)
  // ... existing logic
  ```
- [ ] **3.4** Worker unit tests `dast-recorded-pipeline.test.ts`:
  - **dry-run negative invariants** (tsa-r2-f1): asserts `SELECT count(*) FROM dast_findings WHERE scan_job_id=…` = 0; jest spies confirm `populateDependencies` NOT called and PDV-mutation helpers NOT called for dry-run jobs (success AND failure paths)
  - dry-run shape variants: success / each failure reason (one fixture per reason from Spike-3 corpus)
  - normal scan + recorded, pre-flight green → spider/scan jobs run, findings emitted
  - normal scan + recorded, pre-flight red → `error_payload.kind='pre_flight_failed'`, status=failed, no spider/scan, no findings
  - session-loss exhaustion → `error_payload.kind='session_loss'`, expected discriminator + counter values
  - secret redaction grid: every fixture echoes username/password/totp/type_custom value; asserts `***REDACTED***` in every output surface (failed_at_step.detail, raw_log, log lines)
  - missing `DAST_CREDENTIAL_KEY` → pipeline returns structured error before decrypt
  - typo'd dispatch (`dryRun`, `dry-run`) → `validateDastJobPayload` rejects at top of pipeline
- [ ] **3.5** Audit task: `git grep "error_payload" backend/src` to enumerate readers; confirm none filter `WHERE error_payload IS NOT NULL` as a failure proxy without also checking `error_category IS NOT NULL`. Document outcomes in spike doc. (S)
- [ ] **Commit:** `feat(dast): runDastPipeline dry-run branch + pre-flight recorded auth`

### M4 — Backend routes: test endpoint + cancel route + nuclei guard (M, 3-4h)

- [ ] **4.1** `phase34_cancel_scan_job_rpc.sql` migration (body in §Data Model). Apply via Supabase MCP. `cd depscanner && npm run schema:dump`. (S)
- [ ] **4.2** PGLite test for `cancel_scan_job`: (a) queued → cancelled, (b) processing → cancelled, (c) completed/failed/cancelled → empty return, (d) cross-org call → empty return. (S)
- [ ] **4.3** `backend/src/routes/dast.ts` POST `/credentials/test`:
  - Permission `manage_integrations`
  - Validate target + credential exist; `auth_strategy === 'recorded'` (422 otherwise)
  - `queue_scan_job(p_type='dast_zap', p_payload={dry_run:true, source:'credential_test', ...})`
  - Call `startDastMachine(detected_runtime)` — **on throw, return 503 `fly_machine_unavailable` AND delete the queued row** (cleanup; the 60s budget can't tolerate orphaned queued rows)
  - Return `202 {test_job_id, status:'queued'}`
  - Audit-log row `{event:'dast_login_test.run', test_job_id, target_id}`
- [ ] **4.4** `backend/src/routes/dast.ts` POST `/dast/jobs/:jobId/cancel`:
  - Permission `manage_integrations`
  - Verify job belongs to a project the caller can access (existing project-access helper)
  - Call `cancel_scan_job(p_job_id, p_organization_id)`; empty return → distinguish 404 (not found / cross-org) from 409 (not cancellable) by a second `.from('scan_jobs').select('status').eq('id', jobId).maybeSingle()` lookup
  - Return `200 {job_id, status:'cancelled'}` or `409 job_not_cancellable` or `404 job_not_found`
  - Audit-log row `{event:'dast_scan.cancelled', job_id}`
- [ ] **4.5** Modify POST `/dast/scan`: fetch `auth_strategy` via second guarded `.from('project_dast_credentials').select('auth_strategy').eq('target_id',…).maybeSingle()`. If `engine='nuclei' && auth_strategy==='recorded'` → `400 unsupported_recorded_on_nuclei`. (S)
- [ ] **4.6** Modify PUT `/credentials`: when `recorded`, skip form-login probe; write audit-log with redacted summary. Assert NO selectors/values/secrets in activity payload. (S)
- [ ] **4.7** Modify GET `/dast/jobs`: widen SELECT to include `error_payload`. Widen `DastJobDTO`. (S)
- [ ] **4.8** Route tests `dast-credentials-test-route.test.ts` + `dast-cancel-route.test.ts` — ≥14 cases:
  - 200 happy path POST /test
  - 403 RBAC: user without `manage_integrations`
  - 404 cross-tenant (caller org A, project B); 404 cross-tenant (caller org A, target B)
  - 422 wrong strategy / no credential
  - 409 concurrency: real scan in flight; another test in flight
  - 409 concurrency: simultaneous 2-parallel POSTs barrier test
  - 400 nuclei+recorded
  - 503 `fly_machine_unavailable` synthetic Fly throw → queued row deleted
  - cancel route: 200 cancel queued; 200 cancel processing; 409 cancel completed; 404 cross-org; 404 missing
  - audit-log assertion: PUT recorded writes redacted summary; POST /test writes activity; POST /cancel writes activity; M3 dry-run completion writes `dast_login_test.completed`
  - RBAC matrix (5 user states): no-org / member-without-perm / member-with-perm / team-member-only / owner
- [ ] **Commit:** `feat(dast): credential test endpoint + cancel route + nuclei+recorded guard`

### M5 — Frontend: RecordedStrategyEditor + useJobResult (L, 4-5h)

- [ ] **5.1** New `frontend/src/hooks/useJobResult.ts` (consumed only by RecordedStrategyEditor in v1). Backoff 1.5s→5s→15s, max 5 min, AbortController, Supabase Realtime + fallback poll. **DastScanningTab.tsx NOT touched.** (M)
- [ ] **5.2** `frontend/src/lib/api.ts`: mirror TS types incl. `DastJobErrorPayload` union, add `postDastLoginTest`, `cancelDastJob`. Widen `DastJobDTO`. (S)
- [ ] **5.3** `DastAuthPanel.tsx`: add `'recorded'` to `STRATEGY_OPTIONS`; wire `<RecordedStrategyEditor>`. (S)
- [ ] **5.4** New `RecordedStrategyEditor.tsx`: full editor per §Frontend Design. ResultBanner switches on `error_payload.kind`. Cancel-running-scan affordance on 409 → calls `cancelDastJob` → polls until cancelled → automatically retries Test-login. (L)
- [ ] **5.5** Tests `RecordedStrategyEditor.test.tsx`:
  - RBAC: disabled editor without `manage_integrations`
  - dirty-check Save
  - step add/remove/reorder (up/down chevrons)
  - validation: `goto` at index 2 inline error
  - Test-login state machine: idle → polling → success / failure
  - failed step row highlighted
  - polling timeout (`vi.useFakeTimers`, advance past `maxWaitMs`)
  - polling network error → retry hint
  - AbortController on unmount (no React act() warnings)
  - strategy-switch cancels in-flight poll
  - stale `test_job_id` across re-mount
  - 409 → "Cancel scan" affordance → calls `cancelDastJob` → editor retries
  - render switches on `error_payload.kind`: test_result success + failure; pre_flight_failed (synthetic shape via mocked job); session_loss (synthetic shape)
  - TOTP base32 hint
- [ ] **Commit:** `feat(dast): recorded-login editor + cancel affordance`

### M6 — Real-app smokes + runbook + memory (M, 3-4h)

- [ ] **6.1** Juice Shop (or Deptex internal app) smoke: author recorded login; Test-login green; full scan reaches authenticated routes. (M)
- [ ] **6.2** 2FA smoke: small Node fixture wrapping `oathtool` OR Juice Shop with 2FA toggle enabled (per scope-cutter-f3 — same fixture if convenient). Assert TOTP step completes. (M)
- [ ] **6.3** SSO smoke (gates on Spike-2 outcome): mock-OIDC or Auth0 free tier; cross-origin chain completes; spider stays confined post-auth. (M)
- [ ] **6.4** Session-loss smoke (gates on Spike-2B): short-TTL cookie fixture; ≥1 re-login event fires; bounded retry. (S)
- [ ] **6.5** Cancel-affordance smoke: queue a long real scan; click Test-login → 409 + cancel affordance; cancel scan; Test-login auto-retries; result lands. (S)
- [ ] **6.6** `docs/runbooks/dast-v2-1d-recorded-login.md`: selector tips, SSO patterns, `failed_at_step` reasons, TOTP format, cancel flow. (M)
- [ ] **6.7** Memory updates: `dast_v2_1d_state.md` → IMPLEMENTED with PR link; `MEMORY.md` index. (S)
- [ ] **Commits (×2):** smoke results doc + runbook.

### M7 — CI e2e gate (M, 2-3h)

- [ ] **7.1** Commit `depscanner/test/e2e/fixtures/login-app/` — small Express app, deps pinned. (M)
- [ ] **7.2** `depscanner/test/e2e/dast-recorded.ts`:
  - Boots fixture + depscanner Docker image (per `feedback_docker_vs_source_e2e`)
  - Happy path: dry-run → asserts `error_payload.kind='test_result'`, `test_result.success=true`, `findings_count=0`
  - Failure path: bad selector → asserts `error_payload.test_result.success=false`, `failed_at_step.step_index=N`, `reason='selector_not_visible_after_timeout'`
  - Negative-side e2e: asserts no rows in `dast_findings` for the dry-run scan_job
  - Gated on `DAST_CREDENTIAL_KEY` presence (fail-loud if missing)
- [ ] **7.3** `depscanner/package.json`: `e2e:dast-recorded` script + CI matrix entry. Add CI guard: workflow fails if `Dockerfile` ZAP version changes without the `depscanner/test/fixtures/zap-login-diagnostics/<version>/` directory name being updated. (S)
- [ ] **Commit:** `test(dast): e2e harness for recorded-login dry-run + scan paths`

### Totals: 8 milestones, ~22-28 hours (vs v2: 7 milestones / 20-25h — cancel route + Spike-5 + new tests add ~2-3h).

## Testing & Validation Strategy

### Unit (~55 cases total)

- `dast-credential-validate.recorded.test.ts` — 18+ cases (M1.5)
- `dast-recorded-auth.test.ts` — 8 cases incl. determinism (M2.2)
- `dast-yaml-builder-recorded.test.ts` — 14 snapshot variants (9 per-action + 5 composite/variant) (M2.4)
- `dast-recorded-pipeline.test.ts` — dry-run negative invariants + shape variants + secret redaction grid + payload-typo rejection + missing-key rejection (M3.4)

### Integration

- `dast-credentials-test-route.test.ts` + `dast-cancel-route.test.ts` — 14+ cases (M4.8) incl. cross-tenant + RBAC matrix + audit-log + directional concurrency + Fly-failure 503
- `RecordedStrategyEditor.test.tsx` — 13+ cases (M5.5) incl. polling failure modes + 409→cancel→retry + render-by-`error_payload.kind`
- PGLite test for `cancel_scan_job` RPC (M4.2)
- Re-run v2.1c integration suite (`dast-routes.test.ts`, `dast-pipeline-engine-dispatch.test.ts`, `dast-cross-link-cve.test.ts`, `finalize-extraction.test.ts`) on the v2.1d branch — explicit required-status-check.

### E2E

- `npm run e2e:dast-recorded` CI gate (M7) — fixture Docker e2e.
- Manual real-app smokes (M6.1–6.5) — runbook entries.

### Performance targets

- POST `/credentials/test` first response: <100ms (queue + Fly startup async).
- Test-login end-to-end with warm worker: p50 ≤ 60s, p95 ≤ 120s, hard cancel at 180s.
- Cold worker: surface "Still running…" past 90s; total budget 5 min.
- Encrypted payload size cap: 64 KB.

### Regression

- Re-run v2.1c suite (above).
- Form/jwt/cookie strategies still save + scan + flip PDVs unchanged (snapshot the form scan YAML before M2; assert byte-identical after).
- DastScanningTab.tsx **NOT touched** — zero regression risk by construction.

## Risks & Open Questions

| Risk | Severity | Mitigation |
|---|---|---|
| ZAP browser-auth doesn't work end-to-end in current image. | High | M0 Session-A. Dockerfile change list emerges from outcome. |
| AF YAML can't deliver same-process pre-flight fail-fast. | High | Spike-5 outcome decides: `onFail: exit` works (green) / two-YAML-one-daemon (yellow) / two-process (red). Yaml-builder shape supports all three via `loginOnly` flag. |
| Cross-origin SSO blocked by `includePaths`. | Medium | Spike-2. `sso_origins[]` pre-baked optional. |
| Diagnostic logs unstructured / version-coupled. | Medium | Spike-3 captures real fixtures; CI guard couples fixture-dir to Dockerfile ZAP version. |
| `loggedOutRegex` doesn't re-fire browser-auth. | Medium | Spike-2B. If yellow, Success Criterion #6 → v2.1e; `retry_login_on_lost` disabled for recorded. |
| Real scan blocks Test-login (1/project cap). | Low | Cancel-affordance: user cancels scan → auto-retry. Cancel route is part of v2.1d. |
| `parseZapLoginDiagnostics` brittle. | Low | Fixture-pinned per ZAP version; CI guard. |
| 50-step cap too low. | Low | Survey in M6; raise validator one-liner. |
| Plaintext leakage. | Low | M3.4 redaction grid; `type_custom.value` REDACTED. |
| `error_payload` downstream readers misclassify success as failure. | Low | M3.5 audit + discriminator union forces FE to switch on `kind`. |

### Open questions (informational)

- [ ] Sortable step list: chevron buttons in v1; `@dnd-kit/sortable` only if already in `frontend/package.json`. Decide in M5.4.
- [ ] If selector-iteration friction in dogfood proves real (cancel-affordance roundtrip too slow), v2.1e considers a separate cap lane for dry-run jobs (would require a real `queue_scan_job` migration per `feedback_two_phase_migration_pattern`).
- [ ] `runtime_confirmed_via_auth` marker (opportunity-scout-r2-f6): if Spike-2's column-check confirms it exists on PDVs (v2.1c), set in M3 finalize for recorded scans flipping PDVs; otherwise defer to v2.1e card.
- [ ] Aegis "Suggest selector fix" assistant on `failed_at_step.dom_excerpt` (Tier 1 Gemini Flash) — reserved in parser; v2.1e+.
- [ ] `auth_health` pill on target list — small follow-up.
- [ ] Sample-steps gallery — small follow-up.
- [ ] Customer-facing changelog + docs page (per `feedback_docs_content` — confirm scope before drafting).
- [ ] Browser-extension recorder, AI-recorded login, cURL/Playwright importer — v2.1e+ unlocks; `meta?: Record<string,unknown>` reservation REMOVED from payload per scope-cutter-f5 / pragmatist-f6 (add typed `imported_from` when importer actually ships).

## Dependencies

- **v2.1a (PR #27)** — credential storage, encryption, target model. Shipped.
- **v2.1c (PR #43)** — multi-engine dispatch, Nuclei `recorded` abort path, `runtime_confirmed_*` carry-forward. Shipped.
- **ZAP image** — must support browser-based auth end-to-end. M0 Session-A resolves Dockerfile delta.
- **No new env vars.** Reuses `DAST_CREDENTIAL_KEY`.
- **One small RPC migration** (`cancel_scan_job`) — self-contained, no signature collisions with v2.1c objects.

## Success Criteria

1. ☐ Step editor authors a 5+-step login including TOTP, persists, dirty-check Save.
2. ☐ Test-login against deployed Juice Shop returns `success` within 60s p50 / 120s p95 (warm worker). Bad selector → `failed_at_step={step_index, selector, reason}` with correct UI-coordinate step index.
3. ☐ Full scan against same target discovers authenticated-only routes.
4. ☐ 2FA fixture: TOTP step completes login using only stored secret.
5. ☐ SSO target: cross-origin redirect completes; spider stays confined post-auth.
6. ☐ Session-loss recovery: scan completes after ≥1 re-login event (conditionally Spike-2B).
7. ☐ Pre-scan failure: bad selector fails the scan with `error_payload.kind='pre_flight_failed'` + correct `failed_at_step` BEFORE any spider work (validated via AF or worker-side gating per Spike-5 outcome).
8. ☐ Nuclei + recorded: scan_job fails immediately with the actionable error.
9. ☐ All existing v2.1c tests pass unchanged (explicit CI required-status-check).
10. ☐ `npm run e2e:dast-recorded` CI gate green on both happy + failure paths.
11. ☐ Only one SQL migration in this PR (`phase34_cancel_scan_job_rpc.sql`); no widening of `scan_jobs.type` CHECK, no re-create of `queue_scan_job`.
12. ☐ Audit-log rows written on PUT recorded credential, POST /credentials/test, POST /dast/jobs/:id/cancel, and dry-run completion (`dast_login_test.completed` activity).
13. ☐ Cancel route (`POST /dast/jobs/:jobId/cancel`) operational; editor's 409 → cancel → auto-retry flow validated by M6.5 smoke + M5.5 unit test.
14. ☐ `error_payload` schema is discriminated union (`kind` field); FE renderer switches on `kind`; no overloaded shape per category.

## Recommended next step

`/implement`. Plan is patched against both prior reviews; the v3 architecture is concrete enough for /implement to consume without surprises. Optional: one more `/review-plan --lean` pass to confirm — but the patches are all mechanical (rename, discriminator union, widen SELECT, add route+RPC, add Spike-5, rewrite M3.3 with code sketch) and verifiable against git diffs.
