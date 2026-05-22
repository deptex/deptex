# DAST HAR Import (Replay-Based Auth) — Implementation Plan

> **Brief:** `.cursor/plans/feature-brief-dast-har-import.md` (15 locked decisions; brainstorm 2026-05-21). Extended below with Decisions 16 + 17 (Round 1) + 18 (Round 2 Patch A).
> **Reviews:** `.cursor/plans/review-dast-har-import.md` — Round 1 REWORK (7 P0s, 19 P1s) → Round 2 REWORK (1 converged P0, 8 P1s). This revision applies Round 2 Patches A–H.
> **Direction:** `[[dast_v1_1_direction]]` — second of two remaining v1.1 scanner-gap features.
> **Status:** Post-Round-2-patches. Ready for third `/review-plan dast-har-import` pass before `/implement`.

## Overview

Add a fifth DAST auth strategy — `auth_strategy = 'replay'` — that ingests a browser-DevTools HAR file, extracts the captured request list, and replays it via ZAP **Script-Based Authentication** + **Cookie-Based Session Management** at scan start (and on `logged_out_indicator` miss). Reuses existing `project_dast_credentials` row + `encrypted_payload` AES-256-GCM column (no new tables). Test-replay reuses v2.1d's `POST /credentials/test` → `dast_zap_dry_run` job type → `useJobResult` polling. TOTP is supported via a vendored RFC 6238 JS helper inlined into the auth script, regenerating fresh codes on every ZAP auth invocation (initial AND mid-scan re-auth).

**Important corrections to the brief** (grep-verified per [[feedback_brief_grep_verify]]):

1. Credential PUT/POST/GET routes gate on **org `manage_integrations`** (`backend/src/routes/dast.ts:606,914`), NOT team `manage_projects`. Pre-existing inconsistency in DAST surface; future harmonization is a separate PR.
2. Route is `PUT /credentials` (plural), not `PATCH /credential` (`dast.ts:595`).
3. Existing CHECK constraint at `phase24a_dast_v2_engine_additive.sql:137` — phase36 widens it via DROP+recreate (additive, single transaction).
4. Test-login route hard-codes `auth_strategy !== 'recorded'` at `dast.ts:934` — must widen.
5. yaml-builder dispatches via `buildAuthForStrategy()` at `yaml-builder.ts:158`. Replay branch lands inside the dispatcher.
6. Test-login queues `p_type: 'dast_zap_dry_run'` (`dast.ts:995`) — replay reuses this same type.
7. DAST encryption env vars: `DAST_CREDENTIAL_KEY` + `_PREV` + `_VERSION` (`backend/src/lib/dast-encryption.ts:12,18`), NOT `AI_ENCRYPTION_KEY`.
8. **[Patch C correction — Round 2]** `pipeline.ts:480` is the `decryptCredential()` CALL, not the strategy switch. The discriminated-union dispatch lives in `depscanner/src/dast/auth-config.ts:buildAuthForStrategy()`. There are exactly **3 widen sites in pipeline.ts** (1412, 1528, 1632) — see M3 step 7 — and **4 widen sites in yaml-builder.ts** (245, 289, 330, 362) — see M3 step 8.

## Competitive Research & Design Rationale

Full landscape in the feature brief. Summary:

- **Whitespace:** No competitor ships HAR-as-replay-auth cleanly. StackHawk uses HAR for URL seed; Burp uses a browser-embedded recorder (not actual HAR); Snyk/Probely have no HAR import. M0 step 0 (NEW per Round 2) does a 30-minute verification check that no public ZAP community recipe already chains `importHar` + Script-Based SM — if one exists, soften framing to "first productized" in the PR description.
- **ZAP integration mechanism:** Script-Based Authentication, engine resolved at M0 (Nashorn or Graal.js per the pinned ZAP image). Script body generated from HAR-extracted requests + a vendored RFC 6238 JS function for TOTP codegen.
- **TOTP pattern from Burp:** detect-the-step + accept-the-secret + regen-per-scan. **Round 2 Patch A correction:** the TOTP base32 secret IS inlined into the on-disk AF YAML alongside cookies/bearers. A vendored ~30-LOC RFC 6238 JS function runs inside the script body, regenerating a fresh 6-digit code at EVERY ZAP auth invocation (initial + indicator-miss re-auth). Marginal privacy increment over the existing cookie/bearer surface is bounded by the same unlink-in-finally + Buffer.fill(0) zeroing pattern.
- **Privacy pattern from Cloudflare HAR Sanitizer:** preview-before-commit UI. Full hardening in **Threat Model + Privacy Hardening**.

## Codebase Analysis

### Existing infra reused verbatim

| Surface | File | What we reuse |
|---|---|---|
| Credential storage | `project_dast_credentials` (schema.sql:1033) | `auth_strategy` text + `encrypted_payload` text. No new columns. |
| Validator entry point | `backend/src/lib/dast-credential-validate.ts:118 validateRecordedSteps` | Pattern, error-code shape, SSRF helper. Replay gets sibling `validateReplayPayload`. |
| Encryption | `backend/src/lib/dast-encryption.ts` (`encryptCredential`, `isDastEncryptionConfigured`) | Round-trip unchanged. Env: `DAST_CREDENTIAL_KEY`. |
| Worker decrypt | `depscanner/src/dast/encryption.ts:decryptCredential` (called at `pipeline.ts:480`) + dispatch at `auth-config.ts:buildAuthForStrategy()` | Add `case 'replay':` branch to dispatcher. |
| Auth dispatcher | `depscanner/src/dast/auth-config.ts buildAuthForStrategy` + yaml-builder.ts:158 | Add `case 'replay':` returning `buildReplayAuthForZap()` result. |
| ZAP integration | `yaml-builder.ts` AF YAML emit | New `scripts:` block + `contextAuthentication.method = 'script'` (engine field per M0 outcome). |
| Test-login route | `backend/src/routes/dast.ts:903 POST /credentials/test` | Widen line 934 strategy gate; queue same `dast_zap_dry_run` type. |
| Test-login UX | `frontend/src/components/dast/RecordedStrategyEditor.tsx` | **[Patch 5a]** v1 duplicates the ~150 LOC test-job pattern inline in ReplayStrategyEditor. `useDastTestJob` extraction deferred to follow-up cleanup PR. |
| Activity log | `dast.ts:1066 dast_login_test.run` | **Decision 16:** reuse with `metadata.strategy: 'replay'`. |
| Strategy enum (FE) | `frontend/src/components/dast/DastAuthPanel.tsx:52 STRATEGY_OPTIONS` | Add 5th entry. |
| Authchip | `DastTargetsList.tsx authChip()` | Add `Replay · N` chip. |
| Cross-package sync | `scripts/sync-encryption.ts` + CI `git diff --exit-code` | New `scripts/sync-dast-har.ts`. |
| FE↔BE error-code parity | `frontend/src/lib/dast-error-codes.ts` + `scripts/check-dast-error-codes-match.sh` | Extend with `HAR_ERROR_CODES`. |
| Session-loss machinery | `depscanner/src/dast/pipeline.ts:1661+` (form-only today) | **[Patch D]** Extended to recorded + replay in this PR — see M3 step 7b. |

### Existing files we WILL modify

```
backend/database/phase36_dast_replay_auth.sql                  (NEW — migration)
backend/database/schema.sql                                    (regen via npm run schema:dump)
backend/src/types/dast.ts                                      (EDIT — ReplayCredentialPayload + DTOs)
backend/src/lib/dast-credential-validate.ts                    (EDIT — validateReplayPayload + ssrf)
backend/src/lib/dast-har-parse.ts                              (NEW — HAR shape + detector heuristics + privacy scrubbers)
backend/src/lib/dast-har-constants.ts                          (NEW — caps + detector patterns; synced to worker)
backend/src/routes/dast.ts                                     (EDIT — POST /replay/preview, widen PUT /credentials + POST /credentials/test)
backend/src/index.ts                                           (EDIT — Patch B: mount dast router with own express.json BEFORE global 100kb)
backend/src/__tests__/dast-routes.test.ts                      (EDIT — cross-tenant 404 + replay branches + 403 + body-cap + canary log tests)
backend/src/lib/__tests__/dast-har-parse.test.ts               (NEW)
backend/src/lib/__tests__/dast-har-privacy.test.ts             (NEW — Patch 1 + Patch E broadened canary suite)
backend/src/lib/__tests__/dast-credential-validate.replay.test.ts  (NEW)

depscanner/src/dast/auth-config.ts                             (EDIT — buildReplayAuthForZap + replay branch in buildAuthForStrategy + Nuclei UnsupportedAuthStrategyError)
depscanner/src/dast/har-parse.ts                               (NEW — synced from backend)
depscanner/src/dast/har-constants.ts                           (NEW — synced from backend)
depscanner/src/dast/replay-zap-auth.ts                         (NEW — engine-neutral script generator; module-scoped ZAP_SCRIPT_ENGINE const per Patch F)
depscanner/src/dast/_helpers/totp-rfc6238.ts                   (NEW — Patch A: vendored ~30 LOC RFC 6238 §5.1 + 10 LOC test)
depscanner/src/dast/yaml-builder.ts                            (EDIT — scripts: block + script auth method + 4 widen sites)
depscanner/src/dast/pipeline.ts                                (EDIT — 3 widen sites + session-loss extension per Patch D)
depscanner/src/__tests__/dast-replay-auth-config.test.ts       (NEW)
depscanner/src/__tests__/dast-har-parse.test.ts                (NEW)
depscanner/src/__tests__/dast-replay-totp-rfc6238.test.ts      (NEW — Patch A: RFC 6238 §5.1 test vectors)
depscanner/src/__tests__/dast-yaml-builder.test.ts             (EDIT — replay path structural tests)
depscanner/src/__tests__/dast-replay-contracts.test.ts         (NEW — bundles strategy-coverage + parseability + forward-compat per pragmatist-prag-r2-1)
depscanner/src/__tests__/dast-replay-yaml-cleanup.test.ts      (NEW)
depscanner/src/__tests__/dast-replay-session-loss.test.ts      (NEW — Patch D: engine-wide threshold → session_loss pin for replay)
depscanner/src/__tests__/dast-pipeline-session-loss-recorded.test.ts  (NEW — Patch I-4: pins v2.1d recorded behavior under extended machinery; first-miss → session_loss per b-recorded asymmetric threshold)
depscanner/test/e2e/dast-har.ts                                (NEW — in-process structural e2e + optional real-ZAP)
depscanner/package.json                                        (EDIT — add e2e:dast-har script)

frontend/src/components/dast/DastAuthPanel.tsx                 (EDIT — 5th strategy option)
frontend/src/components/dast/ReplayStrategyEditor.tsx          (NEW — ~300 LOC, drag-drop + summary preview + Test-replay)
frontend/src/components/dast/DastTargetsList.tsx               (EDIT — authChip extends to 'replay')
frontend/src/lib/api.ts                                        (EDIT — types + parseDastHar + replay variant)
frontend/src/lib/dast-error-codes.ts                           (EDIT — add HAR_ERROR_CODES + friendlyHarErrorMessage)
frontend/src/components/dast/__tests__/ReplayStrategyEditor.test.tsx  (NEW)

scripts/sync-dast-har.ts                                       (NEW — mirror pattern from sync-dast-openapi.ts)
scripts/check-dast-error-codes-match.sh                        (EDIT — also check HAR_ERROR_CODES)

.gitignore                                                     (EDIT — Patch 1 + skeptic-r2-f6: root-level `**/*.har`)

docs/runbooks/dast-har-import-dogfood.md                       (NEW — throwaway-Supabase-only procedure with explicit prod-HAR prohibition)
```

### Worker boundary

Per `[[dast_openapi_import_state]]` pattern. Shared concerns sync via `scripts/sync-dast-har.ts`:

1. `dast-har-constants.ts` — caps, detector regexes, `HAR_ERROR_CODES`, `HAR_NON_REPLAYABLE_PATTERNS`, `HAR_TOKEN_QUERY_KEYS`, `HAR_KEEP_HEADERS`.
2. `dast-har-parse.ts` — pure-function parser + detector heuristics + privacy scrubbers.
3. `url-guard.ts` (already synced for PR #51) — reused for per-entry SSRF.

`ReplayCredentialPayload` interface mirrors hand-by-hand into `depscanner/src/dast/auth-config.ts` (precedent: v2.1d); shape-coverage test in M1 step 7 round-trips every optional field.

## Data Model

### Phase 36 migration

**No new tables. No new columns.** Widens existing CHECK to admit `'replay'`.

File: `backend/database/phase36_dast_replay_auth.sql`

```sql
-- Phase 36 (v1.1): DAST replay-based authentication strategy.
-- Widens project_dast_credentials.auth_strategy CHECK to admit 'replay'.
-- Single transaction; idempotent. No data migration needed.

BEGIN;

ALTER TABLE public.project_dast_credentials
  DROP CONSTRAINT IF EXISTS project_dast_credentials_auth_strategy_check;

ALTER TABLE public.project_dast_credentials
  ADD CONSTRAINT project_dast_credentials_auth_strategy_check
  CHECK (auth_strategy = ANY (ARRAY['form'::text, 'jwt'::text, 'cookie'::text, 'recorded'::text, 'replay'::text]));

COMMIT;
```

**Why single-cutover is safe:** The only write path for `auth_strategy = 'replay'` is `PUT /credentials` with `payload.kind === 'replay'` accepted by `validateAndPrepareCredential`. Until backend code is merged, that validator path rejects the request regardless of whether migration applied. depscanner is scale-to-zero Fly — image current at cold-start is what runs. **Deploy order: depscanner image FIRST → merge backend → frontend auto-deploys.** Migration may apply at any point.

Apply via Supabase MCP. Refresh `schema.sql` via `cd depscanner && npm run schema:dump` in same commit.

### Data shape inside `encrypted_payload`

```ts
// In backend/src/types/dast.ts — added next to RecordedCredentialPayload.
// Mirrored by hand into depscanner/src/dast/auth-config.ts.

export interface ReplayedRequest {
  method: string;
  url: string;
  headers: Array<{ name: string; value: string }>;
  body?: string;
  body_encoding?: 'utf8' | 'base64';
}

export interface HarTotpStep {
  entry_index: number;
  body_field: string;
  body_kind: 'form' | 'json';
}

export interface ReplayCredentialPayload {
  kind: 'replay';
  requests: ReplayedRequest[];
  totp_step?: HarTotpStep;
  totp_secret?: string;          // RFC 6238 base32. PATCH A: this IS inlined into the on-disk AF YAML alongside other captured secrets; the vendored RFC 6238 JS function inside the script regenerates fresh codes on every ZAP auth invocation.
  origins_observed: string[];
  // diagnostic_responses are NOT persisted to this row — see Threat Model Step 6.
  label?: string;
}
```

### Validator caps (`backend/src/lib/dast-har-constants.ts`)

```ts
export const HAR_MAX_ENTRIES = 100;
export const HAR_MAX_TOTAL_BYTES = 1_048_576;
export const HAR_MAX_BODY_BYTES = 51_200;
export const HAR_MAX_HEADER_VALUE_LEN = 4_096;
export const HAR_MAX_HEADERS_PER_REQUEST = 50;
export const HAR_MAX_ORIGINS = 10;
export const HAR_MAX_SERIALIZED_PLAINTEXT_BYTES = 1_048_576;

export const HAR_TOTP_PATHS = [/\/verify[-_]?(?:totp|otp|mfa|2fa)\b/i, /\/mfa\/verify\b/i, /\/totp\b/i, /\/otp\b/i, /\/2fa\/verify\b/i];
export const HAR_TOTP_BODY_FIELDS = ['code', 'otp', 'token', 'mfa_code', 'verification_code', 'totp', 'one_time_code'];

export const HAR_NON_REPLAYABLE_PATTERNS = [
  { regex: /\/webauthn\b/i,  hint: 'WebAuthn (hardware key required)' },
  { regex: /\/fido\b/i,      hint: 'FIDO authenticator required' },
  { regex: /\/passkey\b/i,   hint: 'Passkey (hardware key required)' },
  { regex: /\/sms\/verify\b/i,  hint: 'SMS code (single-use)' },
  { regex: /\/sms\/code\b/i,    hint: 'SMS code (single-use)' },
];

export const HAR_TOKEN_QUERY_KEYS = new Set([
  'access_token', 'id_token', 'refresh_token', 'token', 'code', 'state', 'nonce',
  'session', 'sid', 'jwt', 'bearer', 'auth', 'key', 'secret', 'password', 'pwd',
]);

export const HAR_KEEP_HEADERS = new Set<string>([
  'authorization', 'cookie', 'content-type', 'content-length', 'accept',
  'sec-fetch-site', 'sec-fetch-mode', 'sec-fetch-dest', 'sec-fetch-user',
  'x-csrf-token', 'x-xsrf-token', 'x-requested-with',
  'origin', 'referer',
]);

// Patch I-6: strict TOTP secret validation + script-injection defense.
// The base32 secret is inlined into the generated JS script body (Patch A);
// strict-regex validation makes script-injection structurally impossible.
export const TOTP_BASE32_RE = /^[A-Z2-7]+={0,6}$/;  // RFC 4648 base32 alphabet only, optional trailing padding
export const TOTP_MAX_SECRET_LEN = 256;

// Patch I-6: U+2028 + U+2029 are valid JSON characters but break JS string
// literals when embedded in source (historical CVE source for pre-ES2019
// templating systems). Reject in ALL user-supplied string fields, not just TOTP.
export const JS_LINE_TERMINATOR_RE = /[  ]/;
```

## API Design

### Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| `POST` | `/api/projects/:projectId/dast/targets/:targetId/replay/preview` | `authenticateUser` | org `manage_integrations` | **NEW.** Stateless: parse HAR JSON, return preview. No DB writes. Caps + `isDastEncryptionConfigured()` enforced. |
| `PUT` | `/api/projects/:projectId/dast/targets/:targetId/credentials` | `authenticateUser` | org `manage_integrations` | **EDITED.** New `kind === 'replay'` branch. |
| `POST` | `/api/projects/:projectId/dast/targets/:targetId/credentials/test` | `authenticateUser` | org `manage_integrations` | **EDITED.** Widen line 934: `auth_strategy === 'recorded' || 'replay'`. |
| `GET` | `/api/projects/:projectId/dast/targets/:targetId/credentials` | `authenticateUser` | org `manage_integrations` | **EDITED.** Returns extended `DastCredentialSummaryDTO` for replay. **[Patch G]** Strips `error_payload.diagnostic_responses` from any associated test-job row for non-`manage_integrations` callers. |

Route placement: `/replay/preview` placed AFTER `/spec/*` block (around dast.ts:712-880), matching PR #51's `/spec/parse-url-or-synth` sub-resource pattern.

### Request / response shapes

**`POST /replay/preview`**

```ts
interface DastReplayPreviewRequest {
  har: unknown;
}

interface DastReplayPreviewResponse {
  requests: Array<{
    index: number;
    method: string;
    url_scrubbed: string;       // query-string scrubbed via HAR_TOKEN_QUERY_KEYS
    response_status: number;
    has_auth_header: boolean;   // boolean, never the value
    has_cookie_header: boolean;
    has_password_body: boolean;
    body_size: number;
    flag_chips: Array<'auth_header' | 'set_cookie' | 'password_body' | 'totp_detected' | 'non_replayable_pattern'>;
  }>;
  summary: {
    request_count: number;
    origins: string[];          // hostname() only
    cookies_set: number;
    auth_headers_observed: number;
    dropped_header_count: number;
    dropped_bytes: number;
    kept_header_count: number;
  };
  totp_detected: HarTotpStep | null;
  non_replayable_warnings: Array<{ entry_index: number; pattern_hint: string }>;
  rejected?: { error_code: HarErrorCode; detail: string };
}
```

**`PUT /credentials`** (replay branch)

```ts
interface DastReplayUpsertRequest extends DastCredentialUpsertDTO {
  payload: ReplayCredentialPayload;
  logged_in_indicator?: string | null;
  logged_out_indicator?: string | null;
}

interface ReplayPayloadSummary {
  kind: 'replay';
  request_count: number;
  origins_observed: string[];
  totp_detected: boolean;
  has_totp_secret: boolean;
  has_non_replayable_pattern: boolean;
  label?: string;
}
```

### Error codes

```ts
export const HAR_ERROR_CODES = [
  'invalid_har_shape',
  'har_too_large',
  'har_too_small',
  'har_entry_too_large',
  'har_non_https_entry',
  'har_private_ip_entry',
  'har_origin_count_exceeded',
  'har_no_replayable_requests',
  'har_totp_secret_invalid',
  'replay_payload_too_large',
  'dast_encryption_not_configured',
] as const;
```

### Performance

- `POST /replay/preview` p95 ≤300ms for 1MB HAR.
- `PUT /credentials` (replay) p95 ≤200ms.
- `POST /credentials/test` (replay) p95 ≤500ms (RPC queue + Fly start + 202).
- Worker replay startup + Test-replay end-to-end: **observed during dogfood**; `[dast-replay-metric]` log line captures actuals.

## Threat Model + Privacy Hardening

Load-bearing for feature correctness — HAR files carry the exact class of secrets that caused the 2023 Okta breach. The 4 BS-P0 + 4 BS-P1 findings from Round 1 + 1 P0 + 2 P1 from Round 2 consolidate here.

### Where plaintext exists at each step

```
Step                             Plaintext present?  Blast radius if leaked here
─────────────────────────────────────────────────────────────────────────────────
1. FE: user picks .har file       Yes — in browser    Browser only
2. FE → BE upload (HTTPS POST)    Yes — in transit    Network (TLS protects)
3. BE: express.json parse         Yes — in memory     Memory + any body-parser logs
4. BE: validate + extract         Yes — in memory     Memory + console.error sites
5. BE: scrub + build preview      Partial — scrubbed  Response body (URL params scrubbed)
6. BE → FE preview response       Partial — scrubbed  Browser cache; DOM render
7. FE: user clicks Save           Yes — in memory     Browser only
8. FE → BE upsert (HTTPS POST)    Yes — in transit    Network (TLS protects)
9. BE: encrypt with DAST_CREDENTIAL_KEY  No (cipher)  Encrypted at rest
10. DB: project_dast_credentials  No (cipher)         Compromise of DAST_CREDENTIAL_KEY only
11. Worker: decrypt at scan-time  Yes — in memory     Worker memory + script-render
12. Worker: AF YAML on disk       Yes — file bytes    Fly machine disk (encrypted-at-rest by Fly default; ephemeral RAM-backed)
13. ZAP runs script               Yes — script body   ZAP process memory
14. AF YAML unlinked              No                  Clean
```

**Note on table publication:** Equivalent plaintext windows exist in every comparable scanner (Burp / StackHawk / ZAP-direct). Publishing this table makes mitigations auditable rather than informing a novel attack — same prior-art posture as Cloudflare's HAR Sanitizer launch.

### Mitigations by step

**Step 3 (Express body-parser):**
- **[Patch B]** Mount dast router with its own `express.json({ limit: '1.5mb' })` BEFORE the global `express.json({ limit: '100kb' })` at `backend/src/index.ts:109`. M2 step 1 specifies the diff explicitly.
- Custom route-scoped error handler converts any `entity.parse.failed` / `SyntaxError` to `{ error_code: 'invalid_har_shape' }` with NO detail field containing user input.
- Audit `backend/src/index.ts` global error handler at lines 186-189 before merge: `console.error('Error:', err)` passes the WHOLE err object; if `err.body` is truthy (body-parser populates it), route-scoped handler must strip it BEFORE rethrowing to global. M2 step 1 acceptance.

**Step 4 (validate + extract):**
- `console.*` lines on HAR paths log only error CODE + request shape metadata (size, content-type, project_id). NEVER `e.message`, NEVER body excerpts.

**Step 5 (scrub):**
- `scrubUrlQueryParams(url)`: parses URL, replaces values whose keys match `HAR_TOKEN_QUERY_KEYS` with `[REDACTED]`.
- `extractOriginsObserved(requests)`: uses `URL.hostname` only.

**Step 6 (preview response + diagnostic_responses lifecycle):**
- Response shape returns header VALUES nowhere; only booleans.
- **[Patch G — diagnostic_responses lifecycle, Round 2]** `diagnostic_responses` NEVER persisted to credential row. They live ONLY on the transient `scan_jobs.error_payload.kind === 'test_result'` shape with: (a) **256-byte excerpts** (tightened from 2KB in brief), (b) JWT-shape regex scrubber that replaces matches with `[REDACTED_JWT]`, (c) **drop entirely** if response Content-Type is application/json AND any top-level field name matches `(access|id|refresh|bearer)_token`.
- **Test-job row lifecycle:**
  - **On test SUCCESS:** worker writes `error_payload.diagnostic_responses = null` before marking the row complete (1-line addition to test-job completion path in `pipeline.ts` per M3 step 7c).
  - **On test FAILURE: most-recent-only retention** (Patch I-3 corrected — `scan_jobs_retention` cron was grep-cold; descope to worker-side cleanup). The worker, on every NEW test_job dispatch for a given credential (target_id), nulls `error_payload.diagnostic_responses` on ALL prior `dast_zap_dry_run` rows for that credential BEFORE writing the new test_job's result. Net: at most ONE test_job row per credential carries `diagnostic_responses` at any time, bounded by the next test attempt. No new cron required. Implementation: `UPDATE scan_jobs SET error_payload = jsonb_set(error_payload, '{diagnostic_responses}', 'null'::jsonb) WHERE target_id = $1 AND type = 'dast_zap_dry_run' AND id <> $2` at the start of the worker's test-job handler.
  - **GET endpoint role-gate:** any GET that exposes `scan_jobs.error_payload` (verify in `dast.ts /jobs` route) MUST strip `diagnostic_responses` for any caller lacking `manage_integrations` on the project. Test added to `dast-har-privacy.test.ts`.
- Response headers set: `Cache-Control: no-store, no-cache, must-revalidate, private` on the preview endpoint.

**Step 8–10 (encrypt at rest):**
- Encryption uses existing `encryptCredential` round-trip with `DAST_CREDENTIAL_KEY`.
- Audit log: `[dast-replay-crypto] op=encrypt cred_id=… bytes=… key_v=… organization_id` emitted from backend at PUT. Same shape `op=decrypt` from worker before any HAR contents touch ZAP.
- `cred_id` (UUID) is **intentionally correlatable** across audit logs — this is the incident-response feature the log line exists for. Hashing or redacting `cred_id` would defeat the purpose. Documented here so future hardening reviews don't regress this.

**Step 11 (worker decrypt + script render):**
- **[Patch A — TOTP redesign, Round 2]** The TOTP base32 secret IS inlined into the script body alongside captured cookies/bearers. A vendored ~30-LOC RFC 6238 JS function (`generateTotpCode(secret)`) is also inlined into the script body. ZAP runs the script (initial OR re-auth on `logged_out_indicator` miss); the function regenerates a fresh 6-digit code at every invocation. This eliminates the stale-code problem from the original Patch 1 design (which inlined a literal code that went stale after 30s). The marginal privacy increment over the existing cookie/bearer plaintext window is bounded by the same unlink-in-finally guarantee.

**Step 12 (AF YAML on disk):**
- YAML written to disk in try-finally; `unlink()` happens in finally regardless of success/exception.
- Test (`dast-replay-yaml-cleanup.test.ts`): asserts file removed even when `buildAutomationYaml` throws or `spawnExternal` rejects.
- Fly machine disk is encrypted-at-rest by Fly's volume encryption default; the on-disk plaintext window is bounded to the active machine's RAM-backed scratch FS and to the seconds between YAML write and `unlink()`.

**Step 13–14 (ZAP exec + cleanup) — Patch I-5 expanded:**

The v2.1d `Buffer.fill(0)` pattern was designed when the only secret in the YAML was the decrypted JSON payload buffer. Patch A adds `totp_secret` to the script body string AND the assembled YAML string. Enumerate the four in-memory artifacts that hold plaintext at this step:

| # | Artifact | Zeroable? | Bound by |
|---|---|---|---|
| (i) | Decrypted `ReplayCredentialPayload` JSON buffer | **Yes — `Buffer.fill(0)` immediately after YAML write** | v2.1d pattern (`pipeline.ts:6`); explicit |
| (ii) | Generated script source string (contains base32 `totp_secret` + RFC 6238 helper) | **No — V8 strings are immutable** | GC + worker process lifetime + Fly machine ephemerality |
| (iii) | Assembled YAML string (contains script body + cookies/bearers) | **No — same as (ii)** | Same as (ii) |
| (iv) | `Buffer.from(yamlString)` written by `fs.writeFile` | **Yes — `Buffer.fill(0)` in finally** (NEW per Patch I-5) | Try-finally around `fs.writeFile` + unlink |

**Decision 18 rationale correction:** the "marginal privacy increment is bounded by `Buffer.fill(0)`" claim applies to (i) and (iv) only. Artifacts (ii) and (iii) are bounded by GC + process ephemerality — strictly weaker than zeroing, but Fly machines on the depscanner scale-to-zero app are destroyed shortly after the scan completes (typically <5min idle TTL), so the GC-bounded window is operationally short.

**Implementation requirements:**
- Add explicit comment in `replay-zap-auth.ts` next to the script-body assembly: `// SECURITY: this string contains plaintext totp_secret + session cookies until V8 GC. Worker process is killed by Fly idle timeout (<5min); accept window.`
- M3 step 10 (AF YAML cleanup hardening) extended: the pre-write Buffer (artifact iv) is also zeroed in the finally block. Test in `dast-replay-yaml-cleanup.test.ts` adds assertion: pre-write Buffer is `Buffer.alloc(0)` or filled with zeros after `spawnExternal` returns/throws.

### M5 dogfood runbook prohibitions

See `docs/runbooks/dast-har-import-dogfood.md` header for the verbatim dev-tenant prohibition; M5 step 4 lands the runbook. Summary: dev tenants only, no real prod HARs, post-dogfood revoke + rotate + `shred -u` + `git log --all --diff-filter=A --name-only | grep -i '.har$'` check.

### Fixture corpus prohibition

- `.gitignore` (root) adds `**/*.har` per Patch 1 + skeptic-r2-f6.
- All test fixtures use synthetic HARs constructed in code (via factory helpers) or captured from public test apps. No real third-party HAR is ever committed.
- Meta-test `fixtures-only-contain-canary.test.ts` asserts every checked-in HAR-shaped file (anywhere in repo) contains only literal canary strings — never anything matching a JWT-shape regex OR a high-entropy opaque-token shape (Shannon entropy >4.5 over 30+ char runs).
- TruffleHog already runs in CI per CLAUDE.md; M0 step 0 verifies it scans test-fixture paths and uses its bearer-token detector (not just JWT).

### Encryption key rotation (BS-P1-005)

Inherits v2.1d status quo (re-encrypt on read with PREV; `error_category='dast_credential_key_stale'` on PREV-loss). Backfill cron is v2 backlog — affects all 5 strategies together, not this feature's scope.

## Frontend Design

### Pages & Routes

**No new routes.** Replay tab mounts inside existing `DastTargetEditDialog`.

### Component Tree

```
ReplayStrategyEditor (NEW, ~300 LOC)
├── HarUploadZone                  (drag-drop + file picker; client-side .har + ≤1.5MB pre-checks + paste-from-clipboard)
├── (inline) parsing spinner
├── HarPreviewCard                 (compact summary; NO expandable detail in v1 — v1.1)
│   └── (inline) SummaryRow        (4 metrics + sanitization sub-line)
│   └── (inline) NonReplayableAlert (single combined WebAuthn + SMS alert)
├── (inline) IndicatorsBlock
├── TotpSecretBlock                (conditional on totp_detected)
├── (inline) LabelBlock
├── TestReplayButton + TestResultBanner   (uses inlined ~150 LOC test-job pattern per Patch 5a)
```

### Design Specifications

- **HarUploadZone:** Drag-drop from `frontend/src/components/aegis/AttachmentDropZone.tsx`. Client-side reject for >1.5MB BEFORE upload + paste-from-clipboard fallback.
- **SummaryRow:** `<count> requests · <cookies_set> cookies · <auth_headers> Authorization headers · <flag highlights>` + `Stripped <dropped_header_count> non-auth headers · <dropped_bytes>KB telemetry` sub-line.
- **NonReplayableAlert:** Single alert; copy: `"Detected patterns that can't be replayed at scan time: <pattern_hint list>. Test-replay will likely fail at request {entry_index}."`
- **TestReplayButton + Banner:** Reuses ~150 LOC of test-job state machine from RecordedStrategyEditor (copied with `// SYNCED PATTERN with RecordedStrategyEditor.tsx between // region:test-job-state and // endregion — extract to useDastTestJob() in follow-up PR` per ARCH-NEW-5).
- **TOTP detection callout:** copy mentions RFC 6238 defaults per Decision 17.

## Implementation Tasks

### M0 — ZAP Script-Based Auth feasibility + engine + community-recipe check (2 days) [Patches 4 + 8 + skeptic-r2-f10]

**HARD GATE.** M1 does not start until M0 outcome is documented in this plan file.

**Steps:**

0. **(NEW per skeptic-r2-f10, ~30 min)** Web-search for existing public ZAP community recipes chaining `importHar` + Script-Based SM. Note any recipe in the M0 Outcome subsection. If a recipe exists, M6 PR description softens framing from "first to ship" to "first productized."

0a. **(NEW per skeptic-r2-f8 + ARCH-NEW-6, ~30 min)** `docker inspect ghcr.io/zaproxy/zaproxy@<pinned digest>` from `depscanner/Dockerfile`. Capture ZAP version from `/zap/zap.sh -version`. Check ZAP about-page / `/JSON/script/view/listEngines/` for whether scripts addon is bundled AND which engines are available. If scripts addon is NOT bundled, branch to fallback decision tree (line 4 below) BEFORE sinking M0 implementation cost.

0b. **(NEW per Patch G)** Verify `scan_jobs_retention` cron exists; if not, file a follow-up M5 task to create one. The Patch G test-job TTL claim depends on this cron.

1. Resolve pinned ZAP version + default JS engine. Document engine name verbatim. **The chosen engine becomes the value of `ZAP_SCRIPT_ENGINE` const in `replay-zap-auth.ts` (Patch F).**

2. Stand up `depscanner/test/fixtures/dast-auth-app/server.ts` (NEW per OS-NEW-1 — permanent test harness). Route groups:
   - `/login` + `/dashboard` form-POST + session cookie variant (replaces original `m0-fixture-app.ts`)
   - `/hmac-login` + `/hmac-dashboard` HMAC-signed cookie variant (per OS-NEW-6 — unblocks M5 step 4(d) without separate fixture standup; uses `cookie-signature` npm package, HS256, simple `{userId, expires}` session shape)
   - `/totp/login` + `/totp/verify` + `/totp/dashboard` TOTP variant (Patch A validation; ZAP completes initial + simulated re-auth)
3. Write AF YAML using `contextAuthentication.method: 'script'` + `scripts:` block + `scripts.engine: <resolved engine>` + Cookie-Based SM. Script body: 1 POST to /login + session establishment.

4. **Validate cookie threading + script-engine acceptance.** Run ZAP against fixture. Assert ZAP log shows session establishment, indicator hits. Capture working YAML + script body in `depscanner/src/__tests__/zap-replay-smoke/m0-fixture.yaml` + `m0-fixture-script.js`. **Both files include 5-line header comment with pinned ZAP digest tested against, resolved engine, and when to re-test (image bump trigger)** per OS-NEW-7.

5. **Validate TOTP codegen (Patch A path).** Implement `_helpers/totp-rfc6238.ts` (~30 LOC) ahead of M1 if needed; verify it produces correct codes against RFC 6238 §5.1 test vectors (TOTP secret `12345678901234567890`, T=59 → code `94287082`; T=1111111109 → code `07081804`; etc.). Inline the function into a test script body alongside a TOTP base32 secret; run ZAP; verify the generated code passes the IdP's verify endpoint.

6. **Validate FULL re-auth cycle (Patch A + Patch D).** Run the M0 fixture's `/totp` route group. (a) Initial auth: ZAP runs script → fresh code from RFC 6238 helper → passes. (b) Kill the session cookie via ZAP API mid-scan. (c) Verify `logged_out_indicator` fires → ZAP re-runs script → RFC 6238 helper produces a DIFFERENT code 30+ seconds later → passes. This validates BOTH the TOTP redesign AND the session-loss machinery extension (Patch D) end-to-end before M3 commits.

7. **Measure replay startup time.** Time a 5-step replay against the fixture. Record p95 + p50 as observation target, NOT hard acceptance.

8. **Document outcome in THIS plan file.** Add a "M0 Outcome" subsection with: resolved ZAP version + digest, default engine, `ZAP_SCRIPT_ENGINE` const value, working YAML excerpt, RFC 6238 test-vector match log, re-auth-cycle validation log, measured replay time band, community-recipe verdict.

**Concrete fallback decision tree:**

- **(a) `method: 'script'` AF YAML works + engine supports our script** → Proceed to M1.
- **(b) AF YAML doesn't accept `scripts:` block but ZAP API `/JSON/script/action/load/` accepts the script** → Restructure M3 to drive script via ZAP API calls from worker control-plane. M3 grows by ~0.5d.
- **(c) Scripting addon NOT bundled in pinned image** → BLOCKER. **Preferred path:** bump pinned ZAP image to a version that bundles scripts addon. Budget +3-4 days for v2.1a-d regression rerun. Total plan grows from 11 to ~14 days. Branch (c)-httpsender (lower-level mechanism switch) deferred to v1.2.

**M0 acceptance:** all 8 steps completed; outcome documented in this file; M1 commits start ONLY after this section is rewritten with concrete evidence.

### M0 Outcome — completed 2026-05-22

All 8 steps green. M1 unblocked.

**(Step 0) Community-recipe check:** No public ZAP recipe found that chains `importHar` + Script-Based Authentication into a JS auth script body. Closest adjacencies:
- `https://www.zaproxy.org/docs/desktop/addons/sequence-scanner/automation/` — `sequence-import` ingests HAR into a Zest sequence, NOT Script-Based Auth.
- `https://groups.google.com/g/zaproxy-users/c/zZI2sMHNBE0` — user-group thread, "Import HAR + auth script", unresolved (Simon Bennetts asked clarifying questions, no working recipe ever posted).
- `https://www.zaproxy.org/blog/2025-07-03-authentication-improvements/` — ZAP now pushes Browser-Based / Client-Script Authentication and explicitly *de-recommends* the older Script-Based Authentication path going forward.
- `https://github.com/zaproxy/community-scripts/tree/main/authentication` — 10 hand-authored auth scripts; none HAR-driven.

Verdict: **"first productized" framing holds.** PR description will use that phrasing.

**(Step 0a) `docker inspect` + listEngines:** ZAP pinned image `ghcr.io/zaproxy/zaproxy@sha256:8770b23f9e8b49038f413cb2b10c58c901e5b6717be221a22b1bcab5c9771b8a` (matches `depscanner/Dockerfile`). Direct API probe against a daemon spawned from that digest returned:

```
GET /JSON/core/view/version/                        → {"version":"2.17.0"}
GET /JSON/script/view/listEngines/                  → {"listEngines":["ECMAScript : Graal.js","Zest : Mozilla Zest"]}
GET /JSON/authentication/view/getSupportedAuthenticationMethods/
  → "formBasedAuthentication", "scriptBasedAuthentication", "httpAuthentication",
     "manualAuthentication", "clientScriptBasedAuthentication",
     "browserBasedAuthentication", "jsonBasedAuthentication", "autoDetectAuthentication"
GET /JSON/sessionManagement/view/getSupportedSessionManagementMethods/
  → "autoDetectSessionManagement", "headerBasedSessionManagement",
     "scriptBasedSessionManagement", "cookieBasedSessionManagement",
     "httpAuthSessionManagement"
```

Java in the image is 17.0.19 — Nashorn was removed in Java 15, so Graal.js is the only general-purpose JS engine exposed. Both `scriptBasedAuthentication` and `cookieBasedSessionManagement` are bundled (no addon-install gymnastics). Fallback path (c) — scripts addon missing — is NOT triggered.

**(Step 0b) `scan_jobs_retention` cron:** N/A per Patch I-3. Retention re-scoped to worker-side most-recent-only cleanup (`UPDATE scan_jobs SET error_payload = jsonb_set(...) WHERE target_id = $1 AND type = 'dast_zap_dry_run' AND id <> $2`). No new cron required.

**(Step 1) `ZAP_SCRIPT_ENGINE` const value:** `'ECMAScript : Graal.js'` — the exact string returned by `/JSON/script/view/listEngines/` and the value that must appear in `context.authentication.parameters.scriptEngine` in the AF YAML. M3 step 3 sets this as the module-scoped const in `replay-zap-auth.ts` per Patch F.

**(Step 2) Fixture app:** `depscanner/test/fixtures/dast-auth-app/server.ts` shipped (Node http; no Express dep needed). Three route groups, no dependencies beyond Node stdlib + the vendored `_helpers/totp-rfc6238.ts`:
- `/login` + `/dashboard` — form-POST + opaque session cookie. `/dashboard` returns `WELCOME, ALICE` when authenticated.
- `/hmac-login` + `/hmac-dashboard` — same shape but the session cookie is an HMAC-signed JSON envelope `{userId, expires}` (HS256, randomly-keyed at process start).
- `/totp/login` + `/totp/verify` + `/totp/dashboard` — two-step auth: form-POST → pending session ID → POST verify with fresh RFC 6238 code → totp_session cookie. Verify accepts any code in a ±1 step (30s) window, matching most IdP clock-skew tolerance.

Helper routes: `/healthz`, `/__test/expire-totp-session?session_id=…` (for M5 mid-scan re-auth e2e), and request-level stdout logging that surfaces in M0 / M5 evidence. PERMANENT harness per OS-NEW-1 — re-used by `depscanner/test/e2e/dast-har.ts` (M5) and the dogfood runbook M5 step 4(d).

**(Step 3) AF YAML structure:** `depscanner/src/__tests__/zap-replay-smoke/m0-fixture.yaml` (form) + `m0-fixture-totp.yaml` (TOTP) shipped. Two empirically-confirmed wiring quirks vs. the original plan sketch:

1. **The script body lives in `context.authentication.parameters.scriptInline`, NOT in a separate `type: script` job.** First attempt (the plan's original `scripts:` top-level block) was rejected at parse time with "Neither 'scriptInline' nor 'script' specified". M3 step 9's yaml-builder must emit the body inline at the context-auth level. Second attempt (`script:` as the script-job param name) also rejected — "Unrecognised parameter for job script : script". The actual script-job param key is `inline:`, but the cleaner path is the context-auth-level `scriptInline` because the same field handles both registration and method binding atomically.
2. **`addOns` job omitted.** ZAP 2.17.0's stable image already ships authhelper + scripting + ascanrules + pscanrules pre-baked. Listing them triggers "the addOns job no longer does anything" warnings (same finding as `yaml-builder.ts:183` for v2.1d).

The user-binding convention from v2.1d carries over: the post-auth `requestor` job MUST have `parameters.user: deptex-dast-user`. Without that, ZAP never invokes the auth method and the requestor fires anonymously (empirical finding documented at `yaml-builder.ts:226-244`).

**(Step 4) Cookie threading + script-engine acceptance:** `m0-fixture.yaml` (form) ran against the live fixture via Docker:

```
fixture log evidence:
  [fixture] POST /login -cookie         ← ZAP invoked authenticate(), POSTed form
  [fixture] GET /dashboard +cookie      ← ZAP attached harvested Set-Cookie via cookieBasedSessionManagement
  [fixture] GET /dashboard +cookie      ← verification probe + requestor job both attached cookie
ZAP log: "Automation plan succeeded!"
```

End-to-end auth ↔ session-management ↔ verification chain proven for Script-Based Authentication. M3 yaml-builder's structural shape now has a known-good reference.

**(Step 5) RFC 6238 helper validation:** TS surface (`depscanner/src/dast/_helpers/totp-rfc6238.ts`) shipped — pure-function `generateTotpCode(secret, opts?)` + `base32Decode(b32)`. Jest test at `depscanner/src/__tests__/dast-replay-totp-rfc6238.test.ts` exercises all 6 RFC 6238 §5.1 SHA-1 reference vectors with Digit=8:

```
PASS depscanner/src/__tests__/dast-replay-totp-rfc6238.test.ts
  √ T=59 produces 94287082
  √ T=1111111109 produces 07081804
  √ T=1111111111 produces 14050471
  √ T=1234567890 produces 89005924
  √ T=2000000000 produces 69279037
  √ T=20000000000 produces 65353130
  + 6 default-arg + base32 round-trip tests
Tests: 12 passed, 12 total
```

The Java/Graal.js mirror of the helper (string-inlined into the ZAP script body per Patch A) ALSO ships and is validated by step 6 below. M3 contract test will diff the inlined script body against this reference.

**(Step 6) Full re-auth + freshness cycle:** Validated via two consecutive `m0-fixture-totp.yaml` runs spaced 32 seconds apart. The fixture's `/totp/verify` route echoes the submitted code in its stdout log. Result:

```
fixture log evidence:
  [fixture] /totp/verify submitted_code=465916   ← run 1 at t=0
  [fixture] /totp/verify submitted_code=224826   ← run 2 at t=32
```

Both codes accepted by the fixture (`Automation plan succeeded` on both runs); they differ, demonstrating that the Graal.js helper regenerates a fresh code each invocation from the script-engine clock rather than caching a stale code from script-render time. **Patch A's freshness claim is empirically grounded.**

Mid-scan ZAP-auto-re-invocation (Patch D's `consecutive_lost_count >= 4 → session_loss` envelope for replay) is NOT validated by a live mid-scan probe here — that requires a multi-request scan flow with mid-flow session expiry. Instead, M3 step 7b's `dast-replay-session-loss.test.ts` simulates the threshold trip via the existing `createAuthLostWatcher` machinery (`control-plane.ts:276`), which the v2.1d corpus already exercises for the form-strategy path. The M5 e2e (`depscanner/test/e2e/dast-har.ts`) adds an optional `DEPTEX_E2E_DAST_HAR_RUN_ZAP=1` real-ZAP cycle that hits `/__test/expire-totp-session` mid-flow to close that gap end-to-end.

**(Step 7) Replay startup timing:** Three consecutive timed runs of `m0-fixture-totp.yaml`:

| Run | Wall (docker run → exit) | ZAP requestor job |
|-----|--------------------------|--------------------|
| 1   | 12.534s                  | <1s ("00:00:00")   |
| 2   | 12.446s                  | <1s                |
| 3   | 12.339s                  | <1s                |

Cold-start dominated by ZAP boot (~10-12s); actual auth flow (script invocation + cookie harvest + verification GET) is sub-second. In production on the Fly depscanner worker, ZAP starts once per machine cold-start (~5-30s including Fly scheduler) and the per-scan auth overhead is the sub-second portion. Observed as M5 observation target, not hard acceptance.

**(Step 8) Fallback decision tree:** Path (a) confirmed — `method: 'script'` AF YAML works, Graal.js engine present. Paths (b) and (c) are NOT triggered. M3 proceeds with the inline-script-body design as-planned.

**Files committed in M0:**

- `depscanner/src/dast/_helpers/totp-rfc6238.ts` (TS helper, 80 LOC)
- `depscanner/src/__tests__/dast-replay-totp-rfc6238.test.ts` (12 jest cases)
- `depscanner/test/fixtures/dast-auth-app/server.ts` (permanent test harness, ~230 LOC, 3 route groups + admin helpers)
- `depscanner/src/__tests__/zap-replay-smoke/m0-fixture.yaml` (form-auth working reference)
- `depscanner/src/__tests__/zap-replay-smoke/m0-fixture-totp.yaml` (TOTP-auth working reference, inlines the vendored Graal.js helper)
- `depscanner/src/__tests__/zap-replay-smoke/m0-fixture-script.js` (auditable form-auth body)
- `depscanner/src/__tests__/zap-replay-smoke/m0-fixture-script-totp.js` (auditable TOTP-auth body w/ inlined RFC 6238 helper)

### M1 — Migration + types + validator + parser + privacy scrubbers + TOTP helper (2.5 days)

**Steps:**

1. Apply `phase36_dast_replay_auth.sql` via Supabase MCP. Refresh `backend/database/schema.sql`. Commit both.

2. Add `ReplayCredentialPayload` + `ReplayedRequest` + `HarTotpStep` + `ReplayPayloadSummary` to `backend/src/types/dast.ts`.

3. Create `backend/src/lib/dast-har-constants.ts`.

4. Create `backend/src/lib/dast-har-parse.ts` with `parseHar`, `scrubUrlQueryParams`, `extractReplayedRequests`, `detectTotpStep`, `detectNonReplayablePatterns`, `extractOriginsObserved`.

5. **[Patch A]** Create `depscanner/src/dast/_helpers/totp-rfc6238.ts` (~30 LOC pure-function `generateTotpCode(secret: string, opts?: { time?: number; period?: number; digits?: number; algorithm?: 'SHA1' | 'SHA256' | 'SHA512' }): string`). Defaults: `time=Date.now()/1000`, `period=30`, `digits=6`, `algorithm='SHA1'` (RFC 6238 defaults; Decision 17). Add `depscanner/src/__tests__/dast-replay-totp-rfc6238.test.ts` exercising RFC 6238 §5.1 test vectors (6 named test cases at T={59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000} with secret `12345678901234567890` produce `94287082`, `07081804`, `14050471`, `89005924`, `69279037`, `65353130` respectively). The same file lives in TS at script-render time AND is **string-inlined into the ZAP auth script body** at M3 step 3 — the test-vector test protects against drift.

6. Create `backend/src/lib/__tests__/dast-har-parse.test.ts` with happy path + per-error-code rejection + detector false-positives + privacy scrubbers + URL canary scrub.

7. **[Patch E — broadened canary suite]** Create `backend/src/lib/__tests__/dast-har-privacy.test.ts`:
   - **Stub `process.stdout.write` AND `process.stderr.write`** directly (NOT just `console.*`) using a test helper like `mock-stdin` or capture-console — Pino/Datadog/Vercel forwarders bypass console.
   - **Three canary classes** planted in HAR fixtures: (a) literal `CANARY_BEARER_DO_NOT_LOG_xyz123`, (b) base64-encoded canary, (c) URL-encoded canary. ALL three must appear nowhere in stdout/stderr/response across parse/upsert/test paths.
   - **JWT-shape regex assertion:** captured stdout+stderr contains zero substring matching `/eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/`. Use a real JWT.io test-vector token in one fixture.
   - **Global error handler path triggered explicitly:** POST malformed JSON whose bytes contain canary; assert `backend/src/index.ts:186-189` global handler's `console.error('Error:', err)` doesn't echo bytes. If it does, route-scoped pre-handler strips `err.body`/`err.bodyRaw`.
   - **GET /credentials summary path:** save a replay credential containing canary cookie value `CANARY_COOKIE_xyz`; assert GET response never contains it.
   - **Body-cap canary test:** POST 2MB body with canary in first 200 bytes; assert 413 response contains no canary.
   - **[Patch G test] Test-job lifecycle:** after successful test-replay, GET scan_jobs/:id returns `error_payload.diagnostic_responses === null`.

8. Add `validateReplayPayload` + `validateReplaySsrf` in `backend/src/lib/dast-credential-validate.ts`. Wire into dispatcher. **[Patch I-6]** TOTP validation rules:
   - If `totp_secret` present: reject with `har_totp_secret_invalid` if `!TOTP_BASE32_RE.test(secret)` OR `secret.length > TOTP_MAX_SECRET_LEN`. Strict A-Z + 2-7 only; reject lowercase, whitespace, hyphens (force user to canonical RFC 4648 form pre-save).
   - **Generic line-terminator rejection:** scan ALL user-supplied string fields (headers values, body, URL, label, totp_secret) for U+2028 / U+2029 via `JS_LINE_TERMINATOR_RE`; reject with `invalid_credential_shape` if found. Defense against historical templating CVE class.

9. Create `backend/src/lib/__tests__/dast-credential-validate.replay.test.ts` — full-shape round-trip exercising every optional field (closes type-mirror-drift risk). **[Patch I-6]** Add hostile-secret test cases:
   - `totp_secret = '";eval(1);//'` → rejected (`har_totp_secret_invalid`)
   - `totp_secret = 'JBSWY3DPEHPK3PXP // injection'` → rejected (U+2028 in secret)
   - `totp_secret = 'jbswy3dpehpk3pxp'` (lowercase) → rejected (not canonical uppercase)
   - `totp_secret = 'JBSW Y3DP'` (whitespace) → rejected
   - `totp_secret = 'JBSWY3DPEHPK3PXP'.repeat(20)` (>256 chars) → rejected
   - `totp_secret = 'JBSWY3DPEHPK3PXP'` (canonical RFC 4648) → accepted, round-trips encrypt→decrypt unchanged
   - Body field containing U+2028: rejected via `JS_LINE_TERMINATOR_RE` generic guard

### M2 — Backend routes (1.5 days)

**Steps:**

1. **[Patch B / Patch I-1 corrected]** Edit `backend/src/index.ts` to gate the global `express.json({ limit: '100kb' })` on path so it SKIPS the replay-preview route. **Round 3 correction (skeptic-r3-f1 + ARCH-R3-3):** the original Patch B recommendation (router-internal `express.json({ limit: '1.5mb' })`) is broken — Express middleware fires in mount order; the global parser at index.ts:109 fires BEFORE the dast router mounts at index.ts:156, populating `req._body=true` so a router-internal parser no-ops. **Concrete diff:** replace the existing line 109 `app.use(express.json({ limit: '100kb' }))` with:
   ```ts
   const REPLAY_PREVIEW_PATH = /^\/api\/projects\/[^/]+\/dast\/targets\/[^/]+\/replay\/preview\/?$/;
   app.use((req, res, next) => {
     if (REPLAY_PREVIEW_PATH.test(req.path)) return next(); // dast router installs its own 1.5mb parser
     return express.json({ limit: '100kb' })(req, res, next);
   });
   ```
   Then inside the dast router's `/replay/preview` route definition, mount `express.json({ limit: '1.5mb' })` as route-local middleware (NOT router-level — keep other dast routes on the global 100kb path):
   ```ts
   router.post('/:projectId/dast/targets/:targetId/replay/preview', express.json({ limit: '1.5mb' }), async (req, ...) => { ... });
   ```
   ~6 LOC across two files. Audit confirms no other route mounted before the global parser depends on parsed JSON.

2. Add `POST /:projectId/dast/targets/:targetId/replay/preview` to `backend/src/routes/dast.ts`. Place AFTER `/spec/*` block. Gate on `checkOrgManageIntegrationsPermission` + `isDastEncryptionConfigured()`. Body cap via the dast-router-scoped 1.5mb express.json from Patch B. **Audit middleware chain:** confirm `backend/src/index.ts:186-189` global error handler doesn't log `err.body` on parse failure; add route-scoped error handler that strips body field BEFORE rethrowing. Response: `Cache-Control: no-store, no-cache, must-revalidate, private`.

3. Widen `PUT /credentials` (line 595) — `validateAndPrepareCredential` dispatches by kind. Ensure `runFormProbe: false` when `req.body?.payload?.kind === 'replay'`.

4. Widen `POST /credentials/test` (line 934) — `auth_strategy === 'recorded' || 'replay'`. Activity metadata: `{ test_job_id, target_id, strategy: credRow.auth_strategy }` (Decision 16).

5. Widen `targetRowToDto` (around dast.ts:88) for replay summary fields. Strict assertion in tests that GET response never includes raw header values, raw URLs (origins-hostname-only), raw body content.

6. **[Patch G — diagnostic_responses GET strip]** In any GET endpoint that exposes `scan_jobs.error_payload` (grep `scan_jobs` reads in dast.ts), strip `error_payload.diagnostic_responses` from the response for any caller lacking `manage_integrations` on the project. Add to existing scan_jobs serializer if one exists.

7. Update `backend/src/__tests__/dast-routes.test.ts` cross-tenant matrix:
   - Cross-tenant 404: `POST /replay/preview`, `PUT /credentials (replay)`, `POST /credentials/test (replay)`.
   - `manage_integrations: false` → 403 on all 3.
   - Body-cap denial: 2MB JSON → 413 (post-Patch B, this fires from the dast-router-scoped parser at 1.5MB).
   - HAR over-cap: 1.2MB valid-shape HAR → 422 with `har_too_large`.
   - Encryption-not-configured: mock `isDastEncryptionConfigured()` → false → 503 with `dast_encryption_not_configured`.

### M3 — Worker auth-config + ZAP script generator + strategy widen + session-loss extension (3 days, post-Patches C+D+F)

**Steps:**

1. Create `depscanner/src/dast/har-constants.ts` + `depscanner/src/dast/har-parse.ts` mirrored from backend. Add `scripts/sync-dast-har.ts`; CI guard via `git diff --exit-code`.

2. Add `ReplayCredentialPayload` interface mirror to `depscanner/src/dast/auth-config.ts`.

3. Create `depscanner/src/dast/replay-zap-auth.ts`. **[Patch F]** Define `export const ZAP_SCRIPT_ENGINE: 'nashorn' | 'graaljs' = '<value from M0>'` at module top. Pure function `generateReplayAuthScript(payload: ReplayCredentialPayload): string` (note: NO engine param — reads from module const):
   - Iterates `requests[]` in order; constructs `HttpMessage` via engine-appropriate API.
   - **[Patch A]** Inlines the vendored RFC 6238 JS function from `_helpers/totp-rfc6238.ts` as a string literal at the top of the generated script. **Also inlines the base32 `totp_secret`** alongside cookies/bearers, bound to identifier `__DEPTEX_TOTP_SECRET` (per byok-r3-NEW-4 — double-underscore prefix avoids ZAP API global collisions). For the `totp_step.entry_index`, script body calls `__deptexGenerateTotpCode(__DEPTEX_TOTP_SECRET)` at INVOCATION time (every initial auth + every re-auth), substitutes the fresh code into the body field per `body_kind: 'form' | 'json'`.
   - **[Patch I-6 — script-injection discipline]** ALL user-controlled string interpolations (URL, header values, body content, base32 secret) use `JSON.stringify(value)` for the JS string literal, NEVER raw template substitution. Triple-defense: (a) validator enforces `/^[A-Z2-7]+={0,6}$/` on totp_secret + rejects U+2028/U+2029 in all string fields, (b) `JSON.stringify` at substitution time, (c) `vm.Script` parseability test in M3 step 12 confirms emitted script parses.
   - Calls `httpSender.sendAndReceive(msg, true)` (follow redirects).
   - On 4xx/5xx: log to ZAP logger, continue.
   - Returns final auth state (cookies auto-collected by ZAP cookie jar).
   - Hostile-fixture-safe escaping for URL/header/body bytes. Test fixture: URL with `\"`, header with `</script>`, body with `${injection}` — script still parses.

4. Add `buildReplayAuthForZap(payload, loggedInIndicator, loggedOutIndicator): { contextAuthentication, contextUsers, scriptBody, scriptName }` to `auth-config.ts`. NO engine param — script generator reads the module const.

5. Add `case 'replay':` branch to `buildAuthForStrategy()` dispatcher in `auth-config.ts`. **The dispatch site IS the strategy switch** — there is NO separate edit in `pipeline.ts` for decrypt-routing (correcting Round 1's mis-citation of `pipeline.ts:480`).

6. Update `buildNucleiAuthHeaders` (`auth-config.ts:267`) — throw `UnsupportedAuthStrategyError` for `replay`. **Error message shape locked: `\`unsupported auth strategy for nuclei: ${strategy_name}\`` — strategy name only, no payload reference.** Audit existing v2.1d throw site at the same function; fix if it echoes payload bytes (same hardening surface). Add assertion in `dast-replay-auth-config.test.ts` that error message contains no URL/header/body bytes.

7. **[Patch C — pipeline.ts 3-site widen]** Edit `depscanner/src/dast/pipeline.ts` at THREE widen sites:
   - **(a) Line 1412** verification probe / credential-ref attach: widen `'recorded'` to `'recorded' || 'replay'`.
   - **(b) Line 1528** dry-run gate: **CRITICAL** — `auth_strategy !== 'recorded' && auth_strategy !== 'replay'`. Without this, Test-replay queues are rejected at worker claim.
   - **(c) Line 1632** authReportDir attach: widen.

7b. **[Patch D — session-loss machinery extension, Patch I-2 + I-4 corrected]** Extend the v2.1d form-only session-loss machinery to recorded + replay. **Round 3 corrections (skeptic-r3-f2 + ARCH-R3-1 + TSA3-1):** the prior step (a) miscited file:line; corrected below. The recorded-variant regression test is added to the inventory.

   - **(a) Counter increment site** — the `consecutive_lost_count` INCREMENT lives in `depscanner/src/dast/control-plane.ts:276` (inside `createAuthLostWatcher`, called from pipeline.ts:721) and is **engine-wide, not form-only**. The form-only thing is the mid-scan *re-login* (re-auth) path. No edit needed at the counter site — it already fires for all strategies. The Patch D edits live in (b) and (c) below.
   - **(b-replay) Replay re-invoke:** ZAP's Script-Based Authentication re-runs the script body automatically on `logged_out_indicator` miss (no worker edit needed for replay; ZAP's authhelper handles re-invocation). The script body contains the vendored RFC 6238 helper + inlined base32 secret per Patch A, so re-invocation produces a fresh code at each call.
   - **(b-recorded) Recorded re-invoke:** Recorded has NO in-scan re-invoke entry point today — the browser probe runs once inside the autorun YAML in the same ZAP process (per pipeline.ts:325 comment). For recorded, threshold is REDUCED to 1: **first** indicator miss immediately halts with `session_loss` (no retry attempted, since there's no worker-driven re-probe path to invoke).
   - **(c) Envelope emission:** widen the form-only `session_loss` envelope emit gate to also fire for `recorded || replay` strategies. Today pipeline.ts:1660 hardcodes recorded to emit `pre_flight_failed` with `consecutive_lost_count: 0`; change recorded path to emit `session_loss` on first miss per (b-recorded). For replay, emit `session_loss` once the engine-wide `consecutive_lost_count` threshold at pipeline.ts:1816 (`>= 4`) trips — same threshold as form today.
   - **(d) Tests:** **TWO** test files (Patch I-4):
     - `depscanner/src/__tests__/dast-replay-session-loss.test.ts` — simulate `consecutive_lost_count >= 4` for replay (engine-wide threshold from pipeline.ts:1816); assert `session_loss` envelope emitted with the threshold value the test configures.
     - `depscanner/src/__tests__/dast-pipeline-session-loss-recorded.test.ts` — simulate ONE `logged_out_indicator` miss for recorded; assert `session_loss` envelope emitted immediately (per b-recorded asymmetric threshold). Pins v2.1d recorded behavior under the new machinery: catches accidental regression where the recorded path slips back to the old `pre_flight_failed: consecutive_lost_count: 0` shape.
   - **(e) Patch G hook:** test-job completion path also writes `error_payload.diagnostic_responses = null` on SUCCESS before marking row complete.

7c. **[Patch G GET-strip helper]** Audit GET endpoints exposing `scan_jobs.error_payload` (see M2 step 6). If a serializer exists in worker code, add the strip there too for defense-in-depth.

8. Verify nuclei-engine.ts dispatch (around `pipeline.ts:1756`) — **per ARCH-NEW-6**: grep `engine === ` in `pipeline.ts` for the full-scan engine-selection site. If recorded currently has no symmetric orchestration-layer downgrade (only dry-run path rejects nuclei), add an explicit downgrade in this PR: `if (auth_strategy === 'recorded' || auth_strategy === 'replay') engine = 'zap';`. Closes the gap for BOTH strategies symmetrically.

9. **[Patch C — yaml-builder.ts 4-site widen]** Edit `depscanner/src/dast/yaml-builder.ts`:
   - When `opts.authStrategy === 'replay' && opts.authPayload`: emit `scripts:` block at AF top level with script body inline + `engine:` field from `ZAP_SCRIPT_ENGINE` const.
   - Extend `opts.authStrategy === 'recorded'` branches at lines **245, 289, 330, 362** (FOUR sites — line 330 is the auth-setup budget carveout; **rename `RECORDED_AUTH_BUDGET_MIN` → `AUTH_SETUP_BUDGET_MIN`** for strategy-neutrality) to `=== 'recorded' || === 'replay'`.

10. **AF YAML on-disk cleanup hardening:** try-finally with `unlink()` in finally. Test (`dast-replay-yaml-cleanup.test.ts`): assert file removed even when `buildAutomationYaml` throws or `spawnExternal` rejects.

11. Add `depscanner/src/__tests__/dast-replay-auth-config.test.ts` — full-shape round-trip; assert `contextAuthentication.method === 'script'`, script contains all requests + RFC 6238 helper string + `generateTotpCode(BASE32)` call site, engine field correct.

12. **[Pragmatist consolidation per prag-r2-1]** Add `depscanner/src/__tests__/dast-replay-contracts.test.ts` — single file with THREE describes:
    - **`describe('strategy coverage')`**: grep-based AST walker scanning ALL of `depscanner/src/dast/*.ts` for `/auth_strategy\s*[!=]==?\s*['"]recorded['"]/`; assert each call site is followed within 5 lines by a `replay` branch OR a comment containing `// engine-fallback-ok`. Pins yaml-builder.ts:330 + the future-proofing surface.
    - **`describe('script parseability')`**: emitted script body parses via `new vm.Script(source)` (V8 — close enough to flag syntax errors even though it's not Java-aware). Hostile fixture: URL with `\"`, header with `</script>`, body with `${injection}`.
    - **`describe('decrypt-switch forward-compat')`**: passes `kind: 'unknown_future_strategy'` payload; asserts worker logs `error_category='auth_failed'` (NOT unhandled throw). Pins forward-compat contract for any future strategy add.

13. Add `depscanner/src/__tests__/dast-yaml-builder.test.ts` structural tests for replay path: `scripts:` top-level + `method: 'script'` + user binding on activeScan + spider + engine field correct + line 330 budget carveout applies.

### M4 — Frontend (2 days, post-Patches 5a + 6)

**Steps:**

1. Add types to `frontend/src/lib/api.ts`. Add `parseDastHar(projectId, targetId, har): Promise<DastReplayPreviewResponse>` (hits `/replay/preview`).

2. Add `HAR_ERROR_CODES` + `friendlyHarErrorMessage` to `frontend/src/lib/dast-error-codes.ts`. Update `scripts/check-dast-error-codes-match.sh`.

3. **[Patch 5a]** v1 inlines the ~150 LOC test-job state machine pattern into `ReplayStrategyEditor.tsx` with a header comment using **stable region markers** (per ARCH-NEW-5):
   ```
   // SYNCED PATTERN with RecordedStrategyEditor.tsx between // region:test-job-state
   // and // endregion. Bug fixes here MUST also be applied there until the
   // follow-up cleanup PR extracts useDastTestJob(). Tracked in v1.1 backlog.
   ```
   Add matching `// region:test-job-state` / `// endregion` markers in BOTH files. Optional CI grep guard (~5 LOC) that asserts the two marker blocks have identical line counts.

4. Create `frontend/src/components/dast/ReplayStrategyEditor.tsx` (~300 LOC).

5. Edit `frontend/src/components/dast/DastAuthPanel.tsx` — extend `STRATEGY_OPTIONS` + `DraftState` + `buildPayload()`.

6. Edit `frontend/src/components/dast/DastTargetsList.tsx` — extend `authChip()` for replay + amber sub-chip 'not replayable' when `replay_has_non_replayable: true`.

7. Create `frontend/src/components/dast/__tests__/ReplayStrategyEditor.test.tsx` — vitest cases (renders dropzone empty / drag-drop non-.har reject / >1.5MB reject / parse-mock summary render / TOTP block conditional / NonReplayableAlert combined copy / Test-replay disabled until indicators / Save calls api / privacy DOM assertion that planted Authorization value never renders).

### M5 — Tests, e2e, dogfood runbook, observability (2 days)

**Steps:**

1. Create `depscanner/test/e2e/dast-har.ts` (in-process structural ~250 LOC).

2. **Optional real-ZAP variant** gated on `DEPTEX_E2E_DAST_HAR_RUN_ZAP=1`. Spawns pinned ZAP image via Docker against `depscanner/test/fixtures/dast-auth-app/server.ts` (from M0 step 2). Reuses the same fixture across multiple test scenarios.

3. Add `e2e:dast-har` script to `depscanner/package.json`.

4. Create `docs/runbooks/dast-har-import-dogfood.md`:
   - **Verbatim header prohibitions** (dev tenants only; no prod HARs; post-dogfood revoke + rotate + shred + git-log-check).
   - HAR capture procedure.
   - **4 dogfood targets:** (a) form-POST fixture (M0 auth-app form route), (b) Auth0 dev tenant, (c) Microsoft Entra dev tenant (TOTP path validates Patch A in real IdP), (d) HMAC-cookie fixture (M0 auth-app HMAC route — no separate fixture standup per OS-NEW-6).
   - Stop conditions + `[dast-replay-metric]` symptoms-to-cause table including `totp_regen_error` field.

5. **Observability log lines:**
   - **`[dast-replay-metric]`** at worker (`pipeline.ts` after auth setup): `{ strategy: 'replay', request_count, replay_duration_ms, login_indicator_hit_ms, totp_regen_count, totp_regen_error: 'ok'|'bad_secret'|'algorithm_mismatch'|'no_secret_provided', reauth_count }`.
   - **`[dast-replay-crypto]`** at backend PUT + worker decrypt: `{ op: 'encrypt'|'decrypt', cred_id, bytes, key_v, organization_id }`. Field shape locked here so a future Logflare/alert rule doesn't need to track schema drift (see Threat Model Step 8-10).

### M6 — Reviews + push (1 day)

**Steps:**

1. Run `/review-plan dast-har-import` (lean, 7 personas). Target verdict: READY.

2. After /implement, run `/criticalreview` with `--focus=byok-secrets-auditor,multi-tenancy-auditor,service-role-leakage-auditor,payload-dos-auditor,observability-planner`.

3. **[Patch H — durable v1.1 backlog filing AT MERGE TIME]** Before PR merge:
   - Write `dast_har_import_state.md` to user memory (`C:\Users\hruck\.claude\projects\C--Coding-Deptex\memory\`) mirroring `dast_openapi_import_state.md` shape: what shipped, empirical findings, test posture, open follow-ups, **v1.1 follow-up backlog explicitly listing all 6 items**.
   - Update `dast_v1_1_direction.md` memory: HAR import flipped to ✅ SHIPPED; add bullet "HAR import v1.1 polish (6 items)" linking to `dast_har_import_state.md`.
   - Update `MEMORY.md` index with the new state entry.

4. `/push-changes` opens PR into main. Title: `feat(dast): replay-based authentication via HAR import`.

### Task ordering rationale

M0 first (HARD GATE). M1 before M2 (route handlers depend on validator + types). M2 before M3. M3 before M4. M5 last.

**Total: ~11 dev days** (M0 2d + M1 2.5d + M2 1.5d + M3 3d + M4 2d + M5 2d + M6 1d minus M5 buffer) — fits the brief's 3-week envelope.

## v1.1 Follow-up Backlog (post-merge, per Patch H)

These items defer to a v1.1 polish PR. Filed at merge time in `dast_har_import_state.md` user memory + `dast_v1_1_direction.md`. Each has a one-line context for future-Henry to grok in 30 seconds:

1. **HarRequestTable expandable detail panel** — Per-row method/URL/status + flag chips with collapse-by-default UX. Mirrors Cloudflare HAR Sanitizer detail pane. Deferred per SC-1; ~150-200 LOC + 3 vitest cases.
2. **8-variant flag-chip color system** — Full chip palette (amber/destructive/neutral/violet/etc.) for the request table. Backend response shape can also expand the `flag_chips` union from 3 to 8. Deferred per SC-4 + SC-15.
3. **WebAuthn/SMS detector accuracy corpus** — Tune `HAR_NON_REPLAYABLE_PATTERNS` regex set against a 5-IdP test corpus once dogfood produces real-world misses. Deferred per Open Question 4.
4. **`--coverageThreshold` CI gating** — Wire jest's `--coverageThreshold` for the dast-har files specifically (≥95% lines, ≥85% branches). v1 uses observational coverage. Deferred per TSA-3.
5. **`useDastTestJob` hook extraction** — Lift the ~150 LOC test-job state machine out of both `RecordedStrategyEditor.tsx` and `ReplayStrategyEditor.tsx` into a shared `frontend/src/hooks/useDastTestJob.ts`. Region markers (`// region:test-job-state`) in both files make this a mechanical refactor. Deferred per Patch 5a.
6. **`HAR_ERROR_CODES` enum collapse** — Reduce 11 codes to ~4 with detail strings. Per pragmatist-f4; cosmetic.

**Bonus v1.1 / v2 candidates surfaced during /review-plan:**

7. **Postman collection format support** — extend the parser to also ingest Postman v2 collections (similar JSON shape).
8. **Per-credential TOTP algorithm/period/digits override** — non-RFC-6238-default IdPs. Deferred per Decision 17.
9. **Encryption-key rotation backfill cron** — affects all 5 strategies uniformly; not this feature's scope.
10. **`[dast-replay-crypto]` anomaly-alert wiring** — Logflare rule + Slack/Discord channel posting on orphan-decrypt or byte-divergence patterns. Field shape is locked in v1; only the alert rule is deferred.

## Locked Decisions Addendum

- **Decision 16:** Reuse `dast_login_test.run` activity_type with `metadata.strategy`.
- **Decision 17:** TOTP support is RFC 6238 defaults ONLY for v1 (SHA1 / 30s / 6 digits). Non-default → v2 backlog.
- **Decision 18 (Patch A):** TOTP base32 `totp_secret` IS inlined into the on-disk AF YAML alongside captured cookies/bearers. A vendored ~30-LOC RFC 6238 JS function (`generateTotpCode(secret)`) is also inlined into the script body; it regenerates fresh codes at every ZAP auth invocation (initial + indicator-miss re-auth). Marginal privacy increment is bounded by the existing unlink-in-finally + Buffer.fill(0) zeroing pattern; the YAML is already secret-bearing for the same window. _Rationale (Round 2 architect + skeptic converged P0):_ ZAP re-runs the SAME script body on `logged_out_indicator` miss, so any literal code rendered at script-render-time goes stale after 30s. Inlining the secret + the codegen function is the only viable design for mid-scan re-auth without escalating to ZAP-API-driven control-plane re-auth (out of v1 scope).

## Testing & Validation Strategy

### Backend

- `dast-har-parse.ts` table-driven + privacy scrubbers + detector false-positives.
- **`dast-har-privacy.test.ts`** (Patch E broadened): stdout/stderr stub + 3 canary classes + JWT-shape regex + global-handler trigger + GET summary + body-cap canary + Patch G test-job-success lifecycle.
- `dast-credential-validate.replay.test.ts` — caps + SSRF + TOTP base32 + label + full-shape round-trip.
- `dast-routes.test.ts` — cross-tenant 404 + manage_integrations 403 + body-cap 413 + har-too-large 422 + encryption-not-configured 503.
- **Coverage:** observational only; named test cases above ARE the quality gate (TSA-3 affirmed). `--coverageThreshold` is v1.1 backlog.

### Worker (depscanner)

- `dast-replay-totp-rfc6238.test.ts` — 6 RFC 6238 §5.1 test vectors.
- `dast-replay-auth-config.test.ts` — full-shape round-trip; script body contains RFC 6238 helper + base32 inline + `generateTotpCode(BASE32)` call.
- `dast-replay-contracts.test.ts` (pragmatist consolidation per prag-r2-1) — strategy-coverage + script-parseability + decrypt-switch-forward-compat in one file with 3 describes.
- `dast-replay-yaml-cleanup.test.ts` — file unlinked on throw.
- `dast-replay-session-loss.test.ts` (Patch D) — two-miss → session_loss for replay.
- `dast-yaml-builder.test.ts` — structural assertions for replay path (incl. line 330 budget carveout).
- `dast-har-parse.test.ts` — synced from backend.
- e2e: in-process structural + optional real-ZAP via env-gate.

### Frontend

- `ReplayStrategyEditor.test.tsx` (M4 step 7).
- `DastAuthPanel.test.tsx` — extend for 5th strategy.
- `RecordedStrategyEditor.test.tsx` — UNCHANGED (Patch 5a defers hook extraction).

### Integration (manual + runbook)

- 4 dogfood targets per M5 step 4.
- Mid-scan token expiry: invalidate session mid-scan → verify ONE re-replay → invalidate again → verify `session_loss` halt.
- Cross-origin SSO HAR (dev tenant) → preview multi-origin → replay-test passes.

### Performance targets

- `POST /replay/preview` p95 ≤300ms.
- `PUT /credentials` (replay) p95 ≤200ms.
- Worker replay startup: observed during dogfood; `[dast-replay-metric]` carries actuals.

### Regression surface

- v2.1d recorded login: UNCHANGED for FE (Patch 5a defers hook extraction). Worker pipeline changes from Patch D extend session-loss machinery to recorded TOO — test `dast-pipeline-session-loss-recorded.test.ts` (NEW alongside the replay variant) MUST be added in M3 step 7b to pin v2.1d recorded behavior under the new machinery. Confirm 0 regression on existing v2.1d test suite + 0 regression on the existing 10 RecordedStrategyEditor.test.tsx cases.
- Cross-origin OpenAPI seeding (PR #51): orthogonal.
- DAST scan job dispatch: old workers seeing `replay` row fail at dispatcher with `auth_failed` — pinned by `dast-replay-contracts.test.ts decrypt-switch describe`.

## Risks & Open Questions

### Risks

1. **ZAP Script-Based Auth feasibility** — Gated by M0 HARD GATE with concrete fallback tree.
2. **Nashorn vs GraalVM** — Resolved by M0 step 1; `ZAP_SCRIPT_ENGINE` const baked from M0 outcome.
3. **HAR breach vector** — Mitigated by full Threat Model section. /criticalreview at M6 force-includes byok-secrets-auditor + observability-planner.
4. **TOTP under non-default IdP settings** — Resolved by Decision 17; runbook hints at the cause on failure.
5. **Encrypted payload size vs 1MB cap** — Reject with `replay_payload_too_large` if estimated >950KB. `HAR_KEEP_HEADERS` allowlist preserves Sec-Fetch-*.
6. **diagnostic_responses leak** — Resolved by Patch G: never on credential row; test-job row TTL ≤7d on failure; null on success; role-gated GET.
7. **AF YAML on-disk plaintext window** — Resolved per Step 12: try-finally unlink, Fly volume encryption, RAM-backed scratch. Patch A adds the TOTP secret to this window; marginal increment bounded by same guarantees.
8. **Mid-scan re-auth on non-form strategies** — Resolved by Patch D: form-only session-loss machinery extended to recorded + replay in this PR.
9. **Encryption key rotation** — v1 inherits v2.1d status quo; backfill cron is cross-strategy v2 backlog.
10. **TS-render-time TOTP stale-code** — Eliminated by Patch A (Decision 18). Code regenerated by inlined RFC 6238 helper at every ZAP invocation, not at script-render time.

### Open Questions

All blockers resolved. Remaining minor:

1. ~~Reuse activity_type~~ → Decision 16.
2. ~~Diagnostic wipe policy~~ → Patch G.
3. **(Informational)** Postman collection format support — v2 backlog item 7.
4. **(Defer to dogfood)** Detector heuristic accuracy — v1.1 backlog item 3.
5. ~~CHECK constraint widen~~ → confirmed.
6. ~~ZAP scripting support~~ → M0 HARD GATE.
7. ~~Encryption env var name~~ → DAST_CREDENTIAL_KEY.
8. ~~TOTP non-default algorithm~~ → Decision 17.
9. ~~TOTP stale-code mid-scan~~ → Decision 18 / Patch A.
10. ~~Session-loss machinery for non-form~~ → Patch D.

## Dependencies

- v2.1a/b/c/d DAST pipeline + ZAP runner + scan_jobs.type='dast' + dast_zap_dry_run.
- v2.1d Test-login route + useJobResult + DastJobErrorPayload.
- DAST encryption infra (`DAST_CREDENTIAL_KEY`).
- v2.1d session-loss machinery — EXTENDED to recorded + replay in this PR (Patch D).
- PR #51 sync-script pattern + FE↔BE error-code parity pattern.
- Phase 24a CHECK constraint.

**No new external dependencies.** (TOTP RFC 6238 helper is ~30 LOC vendored, no npm dep — protects against future supply-chain risk on a security-critical primitive.)

## Success Criteria

**Hard acceptance (must hit before merge):**

1. M0 outcome documented in this plan file: resolved ZAP version + digest, default engine, `ZAP_SCRIPT_ENGINE` const value, working YAML excerpt, **RFC 6238 §5.1 test-vector match log**, **full re-auth-cycle validation log** (initial + indicator-miss → fresh code on second invocation), measured replay timing band, community-recipe verdict.
2. Phase 36 migration applied; schema.sql refreshed; CI schema-check passes.
3. User drags a real DevTools HAR into Replay tab; preview shows summary + non-replayable alert if applicable.
4. Test-replay shows green banner on passing throwaway target.
5. Replay credential saves; encrypted payload round-trips with every optional field preserved.
6. Real DAST scan succeeds against an authenticated route on dogfood Auth0 tenant.
7. **Mid-scan token expiry triggers exactly one re-replay; second consecutive miss halts with `error_payload.kind === 'session_loss'`** — verified via Patch D wiring + `dast-replay-session-loss.test.ts`.
8. HAR with TOTP step + valid `totp_secret` produces **fresh codes on EVERY ZAP auth invocation (initial + re-auth)** — verified by capturing two scan-log lines showing different codes for the same credential. RFC 6238 defaults only; non-default is v2.
9. HAR exceeding any cap rejected with mapped friendly message.
10. Cross-origin HAR (SSO) replays successfully.
11. NonReplayableAlert surfaces with correct copy.
12. HMAC-cookie fixture (M0 auth-app `/hmac-login` route group) replays successfully.
13. `dast-har-privacy.test.ts` passes all 7 cases (3 canary classes + JWT-regex + global-handler + GET summary + body-cap + test-job lifecycle).
14. `dast-replay-contracts.test.ts` passes all 3 describes (strategy-coverage + parseability + forward-compat).
15. `dast-replay-session-loss.test.ts` passes (Patch D — engine-wide threshold for replay).
15a. **[Patch I-4]** `dast-pipeline-session-loss-recorded.test.ts` passes — pins v2.1d recorded behavior under extended session-loss machinery (first-miss → session_loss per b-recorded asymmetric threshold; catches accidental regression to the old `pre_flight_failed: consecutive_lost_count: 0` shape).
16. AF YAML cleanup test passes.
17. `[dast-replay-metric]` + `[dast-replay-crypto]` log lines emit with expected fields.
18. /criticalreview verdict ≤REVISE with all P0+P1 addressed.

**Verified via CI** (per pragmatist-prag-r2-3 — these are tautological with green CI; collapsed from separate hard criteria into a single line):

19. All new vitest cases pass; full frontend suite ≥476; `npm run e2e:dast-har` green; sync-dast-har CI diff clean.

**Soft acceptance (v1.1 polish per backlog section above):** items 1–6 in v1.1 Follow-up Backlog. Items 7–10 are v2/cross-strategy candidates.

### Next step

Run `/review-plan dast-har-import` (lean mode, 6 personas — Patches A-H expected to resolve all P0 + most P1 from Round 2). Verdict target = READY. Then `/implement dast-har-import`.
