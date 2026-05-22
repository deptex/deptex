# DAST HAR Import (Replay-Based Auth) — Feature Brief

> **Status:** Brainstorm locked 2026-05-21. Ready for `/plan-feature`.
> **Parent track:** `[[dast_v1_1_direction]]` — the second of two remaining v1.1 scanner-gap features (templates shipped via post-PR-#51 commit `eaddc86`; this is HAR).
> **Scope sibling:** `[[dast_openapi_import_state]]` (PR #51) established the patterns this brief reuses.

## Problem Statement

Deptex DAST currently has three auth pipelines: `form` (single POST), `jwt`/`cookie` (token injection via ZAP replacer), and `recorded` (browser-driven DOM steps via ZAP authhelper, v2.1d). None of these covers the common case where a customer has **complex SSO / federated / custom-auth flows** that are too dynamic to DOM-script reliably. Burp Suite addresses this with a browser-embedded recorder — but for users who already have DevTools HARs from their normal app testing, asking them to re-record in a separate tool is friction.

This feature adds a fourth strategy — **replay-based auth** — where the user uploads a HAR captured during normal browser login, Deptex extracts the request list, and ZAP replays it at scan start (and on mid-scan re-auth) via Script-Based Session Management to establish session cookies and Authorization tokens. Pairs with the just-shipped recorded-login templates (post-PR-#51 commit `eaddc86`) to close the v1.1 scanner-gap track.

## Current State in Deptex

**Existing infra this builds on (do not duplicate):**
- `project_dast_credentials` table (`backend/database/schema.sql:1033`): `auth_strategy text NOT NULL`, `encrypted_payload text NOT NULL` (AES-256-GCM via `AI_ENCRYPTION_KEY`), `logged_in_indicator`, `logged_out_indicator`, `retry_login_on_lost`. **No schema changes needed for storage shape** — `auth_strategy` accepts a new `'replay'` value, payload is a new discriminated-union variant inside the existing encrypted column.
- `DastAuthStrategy = 'form' | 'jwt' | 'cookie' | 'recorded'` (`backend/src/types/dast.ts`, mirrored in `depscanner/src/dast/auth-config.ts:16`). Both surfaces need a `'replay'` addition.
- `validateRecordedSteps` + `validateRecordedSsrf` (`backend/src/lib/dast-credential-validate.ts:113,798`). The SSRF-guard pattern (`validateExternalUrl` per URL) extends to replay request URLs verbatim.
- v2.1d `totp_secret` field on `RecordedCredentialPayload` (`auth-config.ts:68`). **Reused directly** by the replay payload — same RFC 6238 codegen path on the worker.
- v2.1d Test-login flow: `POST /api/projects/:id/dast/targets/:targetId/login-test` → returns `test_job_id` → `useJobResult` hook polls → green/red banner driven by `DastJobErrorPayload.kind === 'test_result'`. **Test-replay reuses 80% of this plumbing.**
- ZAP integration: `buildRecordedAuthForZap` (`auth-config.ts:417+`) emits ZAP AF auth config. **New sibling `buildReplayAuthForZap`** emits Script-Based Session Management JS that fires the captured request list in order.
- `DastTargetEditDialog` → `DastAuthPanel` → mounts the per-strategy editor. New `ReplayStrategyEditor.tsx` sits alongside `RecordedStrategyEditor.tsx`.
- OpenAPI-import patterns from PR #51 (worker↔backend sync script, dogfood-then-prod runbook, structural YAML tests).

**What's missing:**
- No HAR parser. No frontend file-upload UX. No `ReplayCredentialPayload` shape. No `buildReplayAuthForZap`. No TOTP-step detector. No request-preview UI.

## Competitive Landscape

### Burp Suite (PortSwigger)
- **What they call it:** "Recorded login sequences." Calls itself HAR-export-compatible but the input format is browser-recorded interaction events, not HAR.
- **TOTP supported via secret + codegen.** Auto-detects TOTP step during paste; prompts user to upload MFA QR or enter secret. ([portswigger.net](https://portswigger.net/burp/documentation/dast/user-guide/reference/mfa-settings))
- **WebAuthn supported** with caveats (no password manager during recording).
- **SMS / CAPTCHA / character-select: not supported.** No detection — user fails empirically. ([portswigger.net](https://portswigger.net/burp/documentation/scanner/authenticated-scanning/troubleshooting-recorded-logins))
- **Novel vs. table-stakes:** Burp's TOTP detection is **the** mature MFA pattern. Their HAR-shaped-export naming is misleading — input is DOM events, not HAR.

### StackHawk
- **HAR is URL seed for scan discovery, NOT auth.** `hawkscan` reads HAR via `hawk.spider.har.file.paths`, follows routes matching `app.host`. Their `hawk perch start --with-chrome` records HAR for URL seeding. ([docs.stackhawk.com](https://docs.stackhawk.com/hawkscan/authenticated-scanning/))
- **Auth itself: form / cookie / bearer / external-command-script.** No HAR-based session establishment.
- **Novel:** Perch's `--with-chrome` proxy-and-recorder is a nice authoring UX but the output goes to scan-surface, not to auth replay.

### Snyk DAST (formerly Probely)
- **No HAR import at all.** Standard form / cookie / bearer strategies. ([snyk.io](https://snyk.io/articles/dast-scanning-best-practices/))

### OWASP ZAP (engine we sit on)
- **`importHar(filePath)` API + Script-Based Session Management.** The mechanism we'll drive from. ([zaproxy.org](https://www.zaproxy.org/docs/desktop/addons/import-export/))
- ZAP **does not natively** treat a HAR as "use this as my session." We script that via Script-Based SM.

### Cloudflare / Google HAR Sanitizers
- **Both ship client-side sanitizers** because HAR contains cookies + Authorization + plaintext passwords. The 2023 Okta breach was caused directly by uploaded HAR files containing valid session cookies. ([blog.cloudflare.com](https://blog.cloudflare.com/introducing-har-sanitizer/) · [github.com/google/har-sanitizer](https://github.com/google/har-sanitizer))
- **Default-strip wordlist** (cookies / Authorization / common JWT body fields / Set-Cookie response headers); **preview-before-commit** UX.

## Landscape Synthesis

| | Status |
|---|---|
| **Table-stakes** | Form/cookie/bearer auth + logged-in/out indicators + re-auth retry. Deptex has all three. |
| **Frontier** | Browser-recorded login (Burp). Deptex has parity via v2.1d. |
| **Whitespace** | **"Upload HAR from DevTools → we extract login traffic → replay it as session establishment with mid-scan re-auth + TOTP support."** Nobody ships this cleanly. StackHawk gets closest but uses HAR for URL seed only. **Deptex would be first.** |

**Deptex position today:** Behind on the gap this closes (complex SSO without DOM scripting); shipping this puts us **ahead** of StackHawk + Snyk and at parity-with-twist vs. Burp (we accept actual DevTools HARs; Burp accepts only their recorder's output).

**Feasibility verdict: tractable, with one major risk.**
- ZAP Script-Based SM is the documented mechanism; HAR 1.2 spec is stable; parser libraries are mature; encryption infra reuses v2.1d's AES-256-GCM.
- **Risk #1 (load-bearing):** HAR uploads are a known breach vector. The 2023 Okta incident was triggered by employees uploading raw HARs with valid session cookies. We **intentionally need** those same cookies/Authorization headers — so client-side wholesale-strip patterns don't work. Mitigated by: extract-then-encrypt-only-what-we-need (drop response bodies, drop non-auth headers, drop request bodies once parsed for replay), never log raw HAR contents, encrypt-at-rest with existing `AI_ENCRYPTION_KEY`, RLS-gate the read-back. Worth two `/review-plan` passes specifically on this surface.
- **Risk #2:** Mid-scan token expiry. Mitigated by re-replay on `logged_out_indicator` miss + fail-fast on second consecutive failure (matches v2.1d `consecutive_lost_count` machinery).
- **Risk #3:** HAR contains a one-time code (TOTP/SMS/captcha) that won't survive replay. Mitigated by TOTP detection + per-scan codegen (Burp parity); SMS/CAPTCHA/WebAuthn fail-fast with clear banner copy.

## User Stories

- As a **security engineer** who can't easily DOM-script my company's SAML+IdP+app flow, I want to record the login once in DevTools, upload the HAR to Deptex, and have DAST run authenticated scans against my app.
- As an **application developer** with TOTP-based MFA on my staging environment, I want to provide my TOTP secret once and have Deptex regenerate valid codes on every scan replay.
- As a **security engineer auditing what Deptex stores**, I want to see a summary + expandable detail of every captured request before I save the HAR, with cookies + Authorization headers + password fields flagged.

## Locked Scope Decisions

1. **Strategy shape: replay-based auth via `auth_strategy='replay'`, NOT recorded-step generation.** _Rationale: HAR is network-level traffic with zero DOM events; mechanical HAR→RecordedStep conversion is fundamentally impossible. The [[dast_v1_1_direction]] memo's claim that HAR generates a recorded-login step list was wrong — surfaced during brainstorm Phase 1 grounding. (See [[feedback_brief_grep_verify]].)_
2. **Login extraction: replay entire HAR end-to-end in original order at scan start.** _Rationale: simplest semantics; no login-request picker; no auto-detect heuristic to false-positive on. User is told "record from fresh incognito → navigate through login to a logged-in page → stop." ZAP just needs the resulting cookies/tokens; doesn't care about the noise._
3. **Storage: encrypted extracted-request-list-only as new `kind:'replay'` variant in existing `encrypted_payload`.** _Rationale: Drop response bodies (except diagnostic retention — see Decision 13), drop non-auth headers, drop timing/page metadata. Smallest blast radius if AES key ever leaks; reuses v2.1d storage column; no new tables._
4. **Mid-scan re-auth: replay HAR auth requests on first `logged_out_indicator` miss; fail-fast on second consecutive miss.** _Rationale: symmetric with initial auth; reuses v2.1d's `consecutive_lost_count` machinery; covers token expiry without infinite retry loops._
5. **UX placement: new 'Replay' tab alongside form/jwt/cookie/recorded in DastAuthPanel.** _Rationale: consistent strategy-picker pattern users already understand; doesn't conflate replay with DOM recording (different mental model)._
6. **Caps: ≤100 entries, ≤1MB total payload, ≤50KB per body.** _Rationale: a login flow is rarely >50 requests; 100 gives headroom; 1MB keeps `encrypted_payload` column reasonable + replay-time short (~20s p95); 50KB body cap rejects images/scripts that aren't auth-relevant._
7. **Cross-origin posture: any HTTPS, private IPs blocked via url-guard.** _Rationale: SSO bounces through IdP origins (accounts.google.com, login.microsoftonline.com) so domain-allowlist is too restrictive. Extends v2.1d's `validateRecordedSsrf` pattern verbatim._
8. **Test-replay button at full parity with v2.1d Test-login.** _Rationale: worker fires the replay end-to-end, checks `logged_in_indicator`, reports pass/fail with same `useJobResult` polling + banner UX. Critical for catching bad HARs before a real scan wastes hours; reuses ~80% of v2.1d plumbing._
9. **TOTP handling: detect TOTP-shaped requests (6-digit POST bodies to /verify-totp /mfa /totp paths); accept optional `totp_secret` field; regenerate fresh code per scan via existing RFC 6238 codegen.** _Rationale: Burp parity (their TOTP detection is the industry standard); v2.1d already has `totp_secret` field shape on RecordedCredentialPayload — reuses verbatim._
10. **WebAuthn detection: surface 'not replayable' banner at upload; user can still save (override).** _Rationale: WebAuthn fundamentally cannot be replayed (challenge/response with hardware key); telling the user upfront beats Test-replay-then-fail._
11. **SMS detection: warn at upload, allow save.** _Rationale: SMS codes are single-use; replay always fails; but detection is heuristic (any 6-digit field that isn't TOTP-flagged), so we warn not block._
12. **Response-body retention: KEEP response bodies on the replay record for diagnostic-only use.** _Rationale: when Test-replay fails, the user needs to see why — what cookie wasn't set, what redirect didn't fire. Doubles encrypted_payload size budget but stays within the 1MB cap._
13. **Preview UX: compact summary above Save + expandable detail panel** showing per-request method/URL/has-Authorization/has-cookie/has-password-body flags, response status. _Rationale: lifts "what is Deptex about to store" into the UI explicitly; mirrors the Cloudflare HAR-sanitizer preview-before-commit pattern that's the load-bearing trust signal post-Okta-breach._
14. **No feature flag during rollout — dogfood-then-prod pattern.** _Rationale: matches OpenAPI work (PR #51); throwaway Supabase first per [[feedback_apply_migrations_via_mcp]]; no flag-removal cleanup PR; deploy order = worker → backend → frontend._
15. **RBAC: existing team `manage_projects` on PATCH `/credential` route.** _Rationale: uniform with v2.1d credential PATCH; no new permission constants; no migrations to `organization_roles`._

## Data Model

**No new tables.** Reuse `project_dast_credentials` (`backend/database/schema.sql:1033`).

**`auth_strategy` column** gains a 5th value: `'replay'`. Add a `CHECK (auth_strategy IN ('form','jwt','cookie','recorded','replay'))` if one exists today (verify during /plan-feature).

**`encrypted_payload`** decrypts to a new TS discriminated-union variant:

```ts
interface ReplayCredentialPayload {
  kind: 'replay';
  // Extracted request list in original HAR entry order. Replayed via ZAP
  // Script-Based Session Management at scan start + on logged_out_indicator miss.
  requests: ReplayedRequest[];
  // Diagnostic-only response bodies (decision 12). Worker reads but never writes
  // to scan output; surfaced only on Test-replay failure.
  diagnostic_responses?: Array<{ entry_index: number; status: number; body_excerpt: string }>;
  // TOTP detection state (decision 9). Worker uses this to know which request
  // to substitute the regenerated code into. null if no TOTP step detected.
  totp_step?: { entry_index: number; body_field: string };
  totp_secret?: string; // RFC 6238 base32, optional even when totp_step is set
  // Inferred from HAR but user-confirmed during preview (decision 13 transparency).
  origins_observed: string[];
  // Per-credential overrides; default to v2.1d Recorded defaults.
  login_page_wait_ms?: number;
  step_delay_ms?: number;
  label?: string;
}

interface ReplayedRequest {
  method: string;          // GET/POST/PUT/DELETE/PATCH
  url: string;             // absolute, https-only enforced at validate
  headers: Array<{ name: string; value: string }>; // Authorization + Cookie + Content-Type preserved; other request headers dropped
  body?: string;           // captured request body, ≤50KB
  // Captured response state (extracted from HAR entry's response field).
  // Used at replay-time to verify the captured response shape still matches.
  response_status?: number;
  set_cookie_names?: string[]; // names only, values not stored (would dup what cookie jar holds)
}
```

**Validator additions** (`backend/src/lib/dast-credential-validate.ts`): a new `validateReplayPayload()` next to `validateRecordedSteps`. Caps from decision 6, SSRF guard from decision 7, TOTP secret regex from v2.1d.

**Total serialized cap:** 1MB before encryption (decision 6). v2.1d's `RECORDED_MAX_SERIALIZED_BYTES` is similar pattern.

## API Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| `PATCH` | `/api/projects/:projectId/dast/targets/:targetId/credential` | JWT | team `manage_projects` | Existing route. New `payload.kind === 'replay'` branch validates + encrypts + stores. |
| `POST` | `/api/projects/:projectId/dast/targets/:targetId/login-test` | JWT | team `manage_projects` | Existing route. New branch when `auth_strategy === 'replay'` queues a replay test job (vs. recorded-step test job). |
| `GET` | `/api/projects/:projectId/dast/targets/:targetId/credential` | JWT | team `view_projects` | Existing read-back. Returns `DastCredentialPayloadSummary` with new `replay_request_count`, `replay_origins_observed`, `replay_totp_detected` fields (no secrets). |
| `POST` | `/api/projects/:projectId/dast/har/parse` | JWT | team `manage_projects` | **NEW.** Server-side HAR parse for the preview UX. Accepts raw HAR JSON, returns `{ requests: ReplayedRequest[], totp_step, sms_warnings, webauthn_warnings, origins_observed }`. Stateless — does NOT save; only powers the preview before user clicks Save. ~50KB → ~1MB request body. Same caps as decision 6 enforced here. |

**Worker route (internal):** the depscanner worker calls existing scan-job endpoints; no new internal routes.

## Frontend Surface

**`frontend/src/components/dast/DastAuthPanel.tsx`** (EDIT): add `'replay'` to the strategy `Select` options between `recorded` and the existing list. Mount `<ReplayStrategyEditor />` when `auth_strategy === 'replay'`.

**`frontend/src/components/dast/ReplayStrategyEditor.tsx`** (NEW, ~400 LOC):
- Top: drag-drop HAR upload zone (or "Choose File" fallback). Accepts `.har` + `application/json` mimetypes.
- On drop: POST to `/api/projects/.../dast/har/parse` → render preview.
- **Preview block** (decision 13): compact summary card (`47 requests · 3 cookies will be set · 1 Authorization header observed · TOTP step detected at request 12`) + expandable details (collapsed by default) showing per-request table:

  | # | Method | URL (truncated) | Status | Flags |
  |---|---|---|---|---|
  | 1 | GET | `https://app.example.com/login` | 200 | — |
  | 2 | POST | `https://app.example.com/oauth/start` | 302 | sets cookie |
  | 12 | POST | `https://app.example.com/mfa/verify` | 200 | TOTP detected |

  Flag chips: `password body` (red), `Authorization header` (amber), `sets cookie` (neutral), `TOTP detected` (purple), `WebAuthn detected` (red, "not replayable"), `SMS pattern` (amber).

- **Indicators block** (matches v2.1d): `logged_in_indicator`, `logged_out_indicator` text inputs.
- **TOTP secret input** (decision 9): only shown when `totp_step` was detected in parse response. Same `password` input type + base32 validator as v2.1d.
- **WebAuthn warning** (decision 10): inline alert above Save if `webauthn_warnings.length > 0` — "WebAuthn challenges can't be replayed. Your scan will fail at request N. Save anyway?"
- **SMS warning** (decision 11): inline alert "potential SMS code at request N — replay will likely fail."
- **Test replay button** (decision 8): same layout as Test login in RecordedStrategyEditor. Disabled until preview is loaded + indicators filled. Reuses `useJobResult` hook.

**`frontend/src/components/dast/DastTargetsList.tsx`** (EDIT): extend `authChip()` to render `Replay · 47` (or similar) when `auth_strategy === 'replay'`. Pattern from PR #51's `specChip`.

**`frontend/src/lib/api.ts`** (EDIT): add `ReplayCredentialPayload`, `ReplayedRequest`, `ReplayParseResponse` types; add `parseDastHar`, extend `setDastTargetCredential` to accept replay variant.

**No new pages.** Everything mounts inside the existing `DastTargetEditDialog`.

**Design references:**
- Preview table shape mirrors Cloudflare HAR sanitizer's request list ([cloudflare.tv](https://cloudflare.tv/this-week-in-net/okta-compromise-and-har-sanitizer-for-all-special-edition/BZOy4Avw)).
- Drag-drop zone matches the existing Deptex pattern at `frontend/src/components/aegis/AttachmentDropZone.tsx` (Aegis uses it for code attachments — same component family).
- Auth-strategy Select uses the existing pattern from RecordedStrategyEditor (Radix `Select` with description tooltips).

## User Flows

### Flow A — Authoring a replay credential

1. User opens DastTargetEditDialog → Authentication section → Strategy Select → "Replay (HAR)."
2. ReplayStrategyEditor renders the drop zone + indicators block.
3. User drags a HAR file from DevTools' Network tab (or chooses via file picker).
4. Frontend POSTs to `/dast/har/parse`. Backend validates shape + caps, extracts requests, detects TOTP/WebAuthn/SMS patterns, returns preview JSON.
5. Frontend renders compact summary + collapsed detail table. User expands to inspect; sees flag chips.
6. If TOTP detected: TOTP-secret input appears. User pastes their base32 secret (optional).
7. User fills `logged_in_indicator` / `logged_out_indicator` (e.g., "Sign out", "Sign in").
8. User clicks "Test replay." Backend queues a replay test job. Worker runs the HAR end-to-end (with fresh TOTP code if secret provided), checks `logged_in_indicator` against final response. Returns pass/fail + diagnostic info.
9. On pass: user clicks Save. PATCH `/credential` validates + encrypts + stores. Dialog confirms.
10. On fail: banner shows `failed_at_step` + diagnostic_response_body. User adjusts HAR or indicators; retries.

### Flow B — Running a DAST scan with replay auth

1. User triggers a DAST scan (existing flow).
2. Backend dispatches scan job. Worker pulls credential, decrypts payload.
3. **Auth setup (worker):** `buildReplayAuthForZap(payload)` returns:
   - A Script-Based Session Management JS string that ZAP runs at session start. The script fires every `requests[i]` in order, threading cookies through ZAP's internal cookie jar. For the `totp_step.entry_index`, the script substitutes a freshly regenerated TOTP code into the body field.
   - Indicator config (`logged_in_indicator`, `logged_out_indicator`) → ZAP context.
4. ZAP runs the script at scan start. Cookies/Authorization headers are now established for the scan session.
5. Scan proceeds normally. Every N requests, ZAP probes `logged_out_indicator`.
6. **On indicator miss:** Script-Based SM re-runs the same replay script (Decision 4). If second consecutive miss → scan halts with `pre_flight_failed` / `session_loss` error_payload (matches v2.1d shape).

## Edge Cases & Failure-Mode Policy

| Edge case | Policy |
|---|---|
| HAR file >1MB after parse | **Hard-fail at validate** with `error_code: 'har_too_large'` + decision-6 caps in detail message. |
| HAR has <2 entries | **Hard-fail at validate** — almost certainly empty or wrong file. `error_code: 'har_too_small'`. |
| HAR entry URL is non-HTTPS | **Hard-fail at validate** per decision 7. `error_code: 'har_non_https_entry'` + entry index. |
| HAR entry URL resolves to private IP | **Hard-fail at validate** via `validateExternalUrl`. `error_code: 'har_private_ip_entry'`. |
| WebAuthn detected | **Warn at upload + allow override** (decision 10). Scan will fail at the WebAuthn step; surfaced clearly. |
| SMS pattern detected | **Warn at upload + allow save** (decision 11). |
| Test-replay times out | Surface `polling`/`still_running` per v2.1d `useJobResult` states. Cap at 60s (longer than recorded-step test because replay is sequential network calls). |
| Test-replay returns 503 fly_machine_unavailable | Same banner copy as v2.1d recorded test. |
| Mid-scan: first `logged_out_indicator` miss | Re-replay (decision 4); increment `consecutive_lost_count`. |
| Mid-scan: second consecutive miss | Halt with `error_payload.kind === 'session_loss'`. Surface in scan-detail UI with copy-pasteable diagnostic. |
| User uploads HAR from a different origin than the scan target | **Allow** — common case for SAML where final session lands on app.example.com after bouncing through accounts.google.com. Just validate decision 7's SSRF rules per entry. |
| Encryption key version mismatch on read-back | Existing v2.1d behavior: re-encrypt with current key version, log to ops. No user-facing change. |

## Non-Functional Requirements

- **Replay startup time p95:** ≤30s (100 entries × ~250ms each + ZAP scripting overhead).
- **HAR parse time p95:** ≤2s (parser is sync; 1MB payload).
- **Test-replay end-to-end p95:** ≤45s (replay + indicator check + worker spin-up).
- **Storage:** ≤1MB encrypted payload per credential. With existing v2.1d caps, total `encrypted_payload` column row size stays ≤2MB.
- **Concurrency:** existing 5-concurrent DAST per org cap covers replay test jobs naturally; no new limits.
- **No AI calls.** This entire feature is deterministic — HAR parsing, request extraction, TOTP detection, replay scripting are all pure-function. Cost: $0 incremental AI.
- **Worker memory:** replay holds ≤1MB payload in memory + ZAP's working set. Negligible.

## RBAC Requirements

| Action | Permission | Scope |
|---|---|---|
| PATCH replay credential (create/update) | `manage_projects` | team |
| GET replay credential summary | `view_projects` | team |
| POST /har/parse (preview) | `manage_projects` | team |
| POST login-test (Test-replay) | `manage_projects` | team |
| Run DAST scan that uses replay credential | existing `manage_projects` on scan trigger | team |

Decision 15: no new permission constants; no migrations to `organization_roles`. Uniform with v2.1d.

## Dependencies

**Prereq features (all shipped):**
- v2.1a/b/c/d DAST pipeline + ZAP runner + scan_jobs.type='dast' dispatch
- v2.1d recorded-login Test-login hook (`POST /login-test` + `useJobResult` + `DastJobErrorPayload`)
- v2.1d encryption infra (`AI_ENCRYPTION_KEY` + AES-256-GCM round-trip in worker + backend)
- v2.1d session-loss machinery (`consecutive_lost_count`, `retry_login_on_lost`)
- PR #51 worker↔backend sync-script pattern (`scripts/sync-encryption.ts` → mirrored for `replay-har-parser.ts` if any code is shared)

**No new external dependencies required.** HAR parsing is straight JSON.parse + validation; no library needed beyond what we already have.

## Success Criteria

**Hard acceptance (must hit before merge):**
1. User can drag a real DevTools HAR (≥10 requests, includes form-POST login) into the Replay tab and see the request preview.
2. User can click Test-replay and see a green banner when the HAR's login flow succeeds (verified against a throwaway dogfood target).
3. User can save the replay credential; the encrypted payload round-trips through backend→worker→backend without data loss.
4. A real DAST scan against an authenticated route succeeds using the replay credential (verified against a throwaway target during dogfood).
5. Mid-scan token expiry triggers exactly one re-replay; second consecutive miss halts the scan with the session-loss error payload.
6. HAR with detected TOTP step + valid `totp_secret` produces fresh codes on each Test-replay run (verified by inspecting the scan log).
7. HAR exceeding any cap is rejected at parse time with a clear error_code.
8. Cross-origin HAR (SSO bounce through accounts.google.com) replays successfully when target is app.example.com.

**Soft acceptance (defer if needed):**
9. WebAuthn / SMS warnings surface in the preview UI with the right copy.
10. The detail-table preview renders ≤500ms for a 100-request HAR.

**Observability:**
- `[dast-replay-metric]` log-prefix on the worker for replay-startup time + indicator-check outcome (mirrors v2.1d's `[dast-metric]` pattern from the v2.1d runbook).

## Open Questions

1. **(Informational, defer to /implement)** — Should the diagnostic_responses retain full headers or just status + body excerpt? Trade-off: full headers help debug Set-Cookie chain failures but bloat the encrypted payload.
2. **(Can defer to /implement)** — How big can a single TOTP "body field" path be in the request body for substitution? E.g., a JSON body `{"mfa":{"code":"123456"}}` needs path-walk. v1 minimum: support flat field-name match in form-urlencoded and top-level JSON; flag nested paths as TOTP-not-replayable.
3. **(Informational)** — Should the preview UI flag the size of each request body (e.g., "5KB upload of profile.jpg")? Helps users notice they recorded too much.
4. **(Defer to dogfood)** — TOTP detection heuristic accuracy. The 6-digit + /verify-totp /mfa /totp / /2fa path pattern is decent but will false-positive on phone-number entry steps. Tune during dogfood.
5. **(Blocks /plan-feature — but trivial)** — Confirm `auth_strategy` column has no CHECK constraint that needs widening. Verify in /plan-feature against the live schema.

## Recommended Next Step

`/plan-feature dast-har-import` — scope is locked, blocker questions are minor and resolvable during planning. Then `/review-plan dast-har-import` (lean mode, 6 personas) before `/implement`.

**Per [[dast_v1_1_direction]]:** after this feature lands, the v1.1 scanner-gap track is complete (templates ✅, HAR ✅) and the 1-week e2e testing phase begins.

---

**Sources cited:**
- [Burp Suite multi-factor authentication settings](https://portswigger.net/burp/documentation/dast/user-guide/reference/mfa-settings)
- [Burp Suite troubleshooting recorded logins](https://portswigger.net/burp/documentation/scanner/authenticated-scanning/troubleshooting-recorded-logins)
- [StackHawk authenticated scanning](https://docs.stackhawk.com/hawkscan/authenticated-scanning/)
- [Snyk DAST scanning best practices](https://snyk.io/articles/dast-scanning-best-practices/)
- [OWASP ZAP Import/Export add-on](https://www.zaproxy.org/docs/desktop/addons/import-export/)
- [ZAP Session Management](https://www.zaproxy.org/docs/desktop/start/features/sessionmanagement/)
- [Cloudflare HAR Sanitizer launch (Okta breach context)](https://cloudflare.tv/this-week-in-net/okta-compromise-and-har-sanitizer-for-all-special-edition/BZOy4Avw)
- [Google HAR Sanitizer](https://github.com/google/har-sanitizer)
- [Nightfall AI: How to discover and protect sensitive data in HAR files](https://www.nightfall.ai/blog/how-to-discover-and-protect-sensitive-data-in-har-files)
