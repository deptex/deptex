# DAST v2.1d — Recorded Login Authentication — Feature Brief

## Problem Statement

Deptex DAST today can scan anonymous targets and apps with trivial single-POST form / JWT / cookie auth, but breaks on the kind of login most real customer apps have: SPAs whose login page is JS-rendered, multi-step flows with CSRF tokens or redirect chains, SSO sign-ins that bounce to an external IdP, and anything behind MFA. The result is that DAST is demoable but not usable on a real customer app. v2.1d adds a **recorded login** strategy so a user can author the exact click/type sequence their app's login requires, and the scanner replays it in a real browser to establish an authenticated session.

## Current State in Deptex

Read against `origin/main` (primary tree is on `chore/marathon-skill`; v2.1c was merged at `43c9ddf`):

- **Auth strategies today:** `form` | `jwt` | `cookie` (`backend/src/types/dast.ts`). The CHECK constraint on `project_dast_credentials.auth_strategy` (`backend/database/phase24a_dast_v2_engine_additive.sql:136-137`) **already includes `'recorded'`** — phase24a reserved it forward-compat. No migration is needed to widen the enum.
- **Credential storage:** one row per target in `project_dast_credentials`, `encrypted_payload` is AES-256-GCM ciphertext keyed by `DAST_CREDENTIAL_KEY` (depscanner env only). `logged_in_indicator`, `logged_out_indicator`, `retry_login_on_lost` columns already exist.
- **ZAP YAML builder** (`depscanner/src/dast/yaml-builder.ts`) emits an Automation Framework YAML with `addOns`, `passiveScan-config`, `replacer`, `spider` | `spiderAjax`, optional `activeScan`, `report`. The image already ships `firefox-headless` (used by `spiderAjax`).
- **Auth bridge** (`depscanner/src/dast/auth-config.ts`): `buildAuthForStrategy` (ZAP) throws `UnsupportedAuthStrategyError` on `recorded`. `buildNucleiAuthHeaders` does the same — Nuclei has no concept of replaying a flow.
- **Routes:** `PUT|GET|DELETE /:projectId/dast/targets/:targetId/credentials` in `backend/src/routes/dast.ts`. The credential validate library is `backend/src/lib/dast-credential-validate.ts` (`validateAndPrepareCredential`, `summarizePayload`).
- **Frontend:** `frontend/src/components/dast/DastAuthPanel.tsx` is the strategy picker + per-strategy form; this is where the step editor will live inline.
- **Error model:** `scan_jobs.error_category='auth_failed'` already carries `{consecutive_lost_count, last_logged_out_url, last_logged_out_at}` (`backend/database/phase24a_2_dast_v2_engine_pipeline.sql`).

**What's missing:** any way to log in beyond a single POST. The `form` strategy can't handle CSRF tokens, JS-rendered logins, multi-step flows, MFA, or cross-origin SSO redirects.

## Competitive Landscape

### Burp Suite DAST
Recorded login sequences via a [Chrome extension](https://portswigger.net/burp/documentation/scanner/authenticated-scanning/using-recorded-logins) that captures clicks/typing → JSON step script, replayed in Burp's own browser during scans. Burp AI can now [autonomously record login sequences](https://portswigger.net/burp/documentation/dast/user-guide/scanning-web-apps/configure-authentication/recorded-logins) given just credentials. Also ships a **status checker** (URL + confirmation text) to confirm authentication before and during a scan. Frontier-grade.

### OWASP ZAP
**Browser-based authentication built into the Automation Framework YAML** ([docs](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/browser-auth/)). Step types: `AUTO_STEPS`, `CLICK`, `USERNAME`, `PASSWORD`, `TOTP_FIELD`, `CUSTOM_FIELD`, `RETURN`, `ESCAPE`, `WAIT`. Each step targets a CSS selector or XPath with a configurable visibility timeout. Configurable `loginPageUrl`, `loginPageWait`, `stepDelay`, `browserId` (default `firefox-headless`, which the Deptex image already includes). Session success detected via Authorization header / `AccessToken` token in response. **This is the engine v2.1d is built on.**

### StackHawk
HAR file support, but mostly used as a [spider seed for endpoint discovery](https://help.stackhawk.com/en/articles/6875314-getting-started-guide-authenticated-scanning), not for replaying a login. Auth is custom scripts. Confirms our research finding that HAR-for-auth is not the industry pattern.

## Landscape Synthesis

- **Table-stakes:** authenticated DAST against modern logins (SPAs, CSRF, redirects). Every serious DAST vendor has it.
- **Frontier:** AI-recorded logins (Burp AI), in-app step editor with selector debugging (Burp, StackHawk), pre-scan auth probe + in-scan re-login.
- **Whitespace:** the **runtime→SCA reachability flip** v2.1c added is unique to Deptex; recorded login is what makes that flip actually fire on real customer apps (since most apps with interesting vulns are behind a login). The value isn't in matching Burp on raw DAST — it's in unlocking the SCA flip on a wider apps surface.
- **Deptex position today:** behind. The `form` strategy works for vulhub fixtures, not real apps.
- **Feasibility verdict:** known-tractable. ZAP's browser-based authentication is GA in the Automation Framework, ships with step types that map 1:1 to a step editor, runs on the `firefox-headless` browser already in the image. Top risks:
  1. **`authentication-helper` addon installability via AF `addOns` job** — need to confirm it installs cleanly into the headless ZAP image we ship, not just the desktop ZAP.
  2. **Cross-origin SSO behaviour** — ZAP's context scope is normally pinned to the target origin. Browser-based auth needs to navigate off-target during login and come back; need to verify scope rules don't trap the browser.
  3. **Test-login dry-run isolation** — running an ephemeral ZAP just to replay the login (no scan jobs) is a new pipeline shape. Risk of credential cleanup races if the test and a real scan share a target row.

## User Stories

- As a security engineer onboarding DAST, I want to author a recorded login that mirrors my app's actual login flow (including CSRF tokens, JS-rendered forms, and SSO redirects), so that DAST can scan the routes that matter.
- As a security engineer, I want to test my recorded login without running a full scan, so that I can iterate on selectors quickly and know it works before committing to a 30-minute scan.
- As a security engineer with a 2FA-protected app, I want to provide a TOTP seed alongside username/password, so that DAST can complete the MFA step without my intervention.
- As an admin running long DAST scans, I want the scanner to re-login automatically if the session is lost mid-scan, so that one flaky cookie doesn't kill a 30-minute job.
- As an SRE, when the recorded login fails before scanning, I want the scan_job error to tell me which step failed (e.g. "step 4: selector `#submit` not visible after 1000ms"), so that I can fix the recording without grepping ZAP logs.

## Locked Scope Decisions

1. **Engine mechanism: ZAP browser-based authentication, via the AF YAML's `browser` auth method.**
   Reason: research confirmed it's GA in the Automation Framework, step types map 1:1 to a step editor, Firefox is already in the image. HAR replay was rejected — token regeneration makes it fragile and no major competitor uses it for auth.
2. **Nuclei: aborts when target has a `recorded` credential, with the same actionable error v2.1c established.**
   Reason: Nuclei has no browser execution model; "auto-route to ZAP" was rejected because silent engine swaps surprise users. Same posture as form auth on the Nuclei engine today.
3. **Authoring UX: manual step editor inline in `DastAuthPanel.tsx`. No browser extension. No AUTO_STEPS fallback.**
   Reason: extension is a separate codebase/store-listing burden; AUTO_STEPS as a separate mode complicates the model. The editor handles everything; a "single-step AUTO" can still be expressed as one step in the editor if we ever want it.
4. **Pre-scan verification: full. Replay the recorded login → probe `logged_in_indicator` → fail fast with `auth_failed` + the step number / selector that broke.**
   Reason: matches Burp's status checker; without it selector authoring is guess-and-scan. Reuses the existing `logged_in_indicator` / `logged_out_indicator` columns.
5. **TOTP in v1.** Credential payload gains an encrypted `totp_secret` (RFC 6238); step type `TOTP_FIELD` reads it.
   Reason: ZAP supports it natively. Most "real" customer apps have 2FA — punting MFA means v1 still fails the success-criteria bar.
6. **Storage: everything (steps + secrets) encrypted together in `encrypted_payload`.** UI rendering goes through the existing GET-credentials decrypt route.
   Reason: simpler schema, one CHECK strategy, no risk of leaking step structure that reveals app internals. The GET route already exists and is RBAC-gated.
7. **"Test recorded login" button: a dedicated dry-run job that replays only the login + indicator probe, no spider/scan.** Returns success or `failed_at_step={n, selector, reason}`.
   Reason: central to the authoring UX per Burp's pre-scan check. Same machinery as the pre-scan probe, exposed on demand.
8. **Cross-origin SSO supported.** Steps may navigate to a different origin during auth (e.g. `accounts.google.com`, `okta.com`); ZAP browser context relaxed for the auth phase only, re-pinned to the target origin once the indicator fires.
   Reason: "real apps behind a real login" includes SSO. Risk acknowledged (item 2 in feasibility verdict) — spike before committing.
9. **Session loss mid-scan: re-login then continue, bounded retries.** Reuses `retry_login_on_lost` column. After N consecutive losses, fail the scan with `auth_failed` and the existing `consecutive_lost_count` metadata.
   Reason: a single flaky cookie shouldn't kill a 30-minute scan. Bounded retries cap the worst case.
10. **Rollout: ship to all orgs instantly, no feature flag.**
    Reason: strategy is opt-in per target; no existing org has it; no migration to gate.
11. **Acceptance bar: real authenticated app end-to-end.** Step editor authors a login on a real (non-fixture) SPA-with-login, Test login passes, full scan reaches routes only available when authenticated, session-loss recovery fires, an SSO target also works.
    Reason: rules out "fixture-only" success that wouldn't prove customer-usability.

## Data Model

**No new tables. No CHECK widening (`recorded` already in the constraint).** Changes are additive to existing surfaces:

- `project_dast_credentials.encrypted_payload`: payload shape extended for `recorded` strategy:
  ```ts
  type RecordedCredentialPayload = {
    kind: 'recorded';
    login_page_url: string;
    steps: Array<{
      action: 'goto' | 'click' | 'type_username' | 'type_password' | 'type_totp' | 'type_custom' | 'wait' | 'return' | 'escape';
      selector?: string;       // CSS or XPath; required for click / type_* (except totp/username/password if AUTO_STEPS-style)
      selector_kind?: 'css' | 'xpath';
      value?: string;          // for type_custom; literal string
      timeout_ms?: number;     // default 1000
      wait_ms?: number;        // for wait action
    }>;
    username: string;
    password: string;
    totp_secret?: string;      // base32, RFC 6238
    login_page_wait_ms?: number; // default 5000
    step_delay_ms?: number;    // default 0
  };
  ```
- `DastCredentialPayloadSummary` (in `backend/src/types/dast.ts`) gets a `'recorded'` variant: `{ kind: 'recorded'; step_count: number; has_totp: boolean; login_page_url_host: string }`. Same redaction posture as existing summaries (host only, never path/query).
- `DastAuthStrategy` widens from `'form' | 'jwt' | 'cookie'` to `'form' | 'jwt' | 'cookie' | 'recorded'` in `backend/src/types/dast.ts`. The depscanner-side mirror in `auth-config.ts` already has it.
- Existing columns repurposed (no migration): `logged_in_indicator`, `logged_out_indicator`, `retry_login_on_lost`.

**Migration:** none (zero schema changes — only TS DTOs + payload shape). This is a happy path that v2.1a deliberately preserved.

## API Endpoints

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| PUT | `/api/projects/:projectId/dast/targets/:targetId/credentials` | JWT | same as today (`manage_projects` / `manage_integrations` — match existing handler) | Accept `kind: 'recorded'` payload. `validateAndPrepareCredential` extended to validate the step list shape (action enum, selector required where appropriate, timeout/wait_ms bounds) before encrypting. |
| POST | `/api/projects/:projectId/dast/targets/:targetId/credentials/test` | JWT | same | **New.** Queues a `dast_login_test` scan_job that runs only the recorded-login replay + indicator probe. Returns `{ test_job_id }`; client polls for the result via the existing jobs endpoint. |
| GET | `/api/projects/:projectId/dast/targets/:targetId/credentials` | JWT | same | Returns the summary today; for `recorded` strategy returns `step_count`, `has_totp`, `login_page_url_host`. Full payload requires the existing decrypt-and-return path (admin-only). |
| DELETE | `/api/projects/:projectId/dast/targets/:targetId/credentials` | JWT | same | Unchanged. |

**`scan_jobs.type`** gains a third DAST subtype: `dast_login_test`. The `claim_scan_job` RPC's allowed-types list and the `getSupportedJobTypes()` worker registration need to include it.

## Frontend Surface

**Sole edited file (UI):** `frontend/src/components/dast/DastAuthPanel.tsx`. Adds a 4th radio "Recorded login" and an inline step editor below it.

Editor shape (matches the locked preview):
- Header row: "Login page URL" text field, "Logged-in indicator" / "Logged-out indicator" regex fields (existing).
- Step list (sortable rows, add/remove): per-row a step-type dropdown (`Go to URL` / `Click` / `Type username` / `Type password` / `Type TOTP` / `Type custom` / `Wait` / `Press Enter` / `Press Escape`), selector input (with `CSS`/`XPath` toggle), value input (visible only for `Type custom`), timeout input.
- Credentials block (below steps): username, password, TOTP secret (masked, copy-to-reveal). Validation hints on the TOTP secret (base32 only).
- Buttons: `Test login` (outline) → triggers POST `/credentials/test`, surfaces a live status block (`Testing…` → `✓ Logged in (took 7.4s)` or `✗ Step 4 — selector "#submit" not visible after 1000ms`). `Save` (white per Vercel-style; respects dirty-check + spinner pattern per `account_settings_parity_standard`).
- Empty state: a single starter step `Go to {loginPageUrl}` + a `+ Add step` button.
- Sortability via `@dnd-kit/sortable` (already in `frontend/package.json` if a reachability/sortable component uses it; otherwise simple up/down buttons).

**Design references:** the existing `DastAuthPanel` for the field spacing and indicator-input pattern; `frontend/src/components/policy-engine/PolicyCodeEditor.tsx` for the step-list / preview side-by-side feel. Card layout per `account_settings_parity_standard`.

## User Flows

1. **Authoring a recorded login.**
   `Project → DAST → Target → Edit credentials` → pick "Recorded login" → fill login page URL → add steps (each: action + selector + optional value) → fill credentials block → click **Test login** → see live result. If it fails, the failing step is highlighted with the selector + reason; edit the step, click Test again. When green, click **Save** (encrypts + stores).
2. **Running a scan.**
   Identical to today — `Scan now` button on the target. Pipeline detects `auth_strategy='recorded'`, decrypts the payload, emits a ZAP AF YAML whose `env.contexts[0].authentication` is a `browser` method block with the step list translated to ZAP step types (`USERNAME` / `PASSWORD` / `TOTP_FIELD` / `CLICK` / `WAIT` / etc.). Pre-scan: replay login → probe indicator → if fail, scan_job fails with `auth_failed` + step metadata before any spider/active-scan work.
3. **Session lost mid-scan.**
   ZAP's `verification.loggedOutRegex` fires → ZAP attempts a re-login via the same browser auth block → if it succeeds, scan resumes; if N consecutive failures, scan_job fails with `auth_failed` + `consecutive_lost_count`.
4. **Nuclei scan against a recorded-credential target.**
   Identical to v2.1c behaviour: job fails immediately with `auth_failed` and message "Nuclei does not support recorded login; re-run with the ZAP engine."

## Edge Cases & Failure-Mode Policy

- **Selector not found within timeout** → step fails → test/scan returns `failed_at_step={n, selector, reason: 'not_visible_after_timeout'}`. Never fall back to anonymous.
- **TOTP secret invalid base32** → server-side validation rejects on save. Never persist.
- **Cross-origin step but ZAP context refuses navigation** → step fails with a specific `cross_origin_blocked` reason → docs link to "enable cross-origin SSO" (a per-credential boolean we may need; spike will tell).
- **Test-login while a real scan is running on the same target** → reject the test job with HTTP 409 `dast_target_busy`. (Reuses the existing 1/project + 5/org concurrency caps in `queue_scan_job`.)
- **Credential decryption fails at scan time** → existing `dast_credential_key_*` error categories already handle this.
- **HAR uploads** → not accepted in v1 (research-driven non-goal). Documented in docs.
- **Recorded payload exceeds reasonable size** → server-side cap on step count (e.g. 50 steps) and per-step selector length (e.g. 1024 chars) to keep encrypted payload bounded.
- **Plaintext leakage** → recorded steps may contain non-secret CSS selectors, but the encrypted_payload still holds them. The Test-login worker must redact logs the same way ZAP logs are redacted today (`redactCredentials` in `runner.ts`). Selectors are not secret but log them only at the worker's debug level.

## Non-Functional Requirements

- **Test-login latency target:** end-to-end ≤ 60 s from POST `/test` to a final `success` / `failed_at_step` payload, on a target with a 5-step login.
- **Encrypted payload size cap:** 64 KB (existing `encrypted_payload` is TEXT — practical cap).
- **Concurrency:** test-login jobs count against the same per-project (1) / per-org (5) DAST concurrency caps; a test job blocks a real scan and vice versa.
- **No new external integrations** required (ZAP image already ships Firefox + the `authentication-helper` addon path).
- **AI cost:** zero (no AI in v1 — defer Burp-AI-style auto-recording to v2.1e or later).

## RBAC Requirements

Mirror the existing form/jwt/cookie credential routes — no new permission strings:
- `PUT|DELETE /credentials`, `POST /credentials/test`: same permission that gates today's credential mutation route.
- `GET /credentials` (summary): same as today.
- `GET /credentials` (full payload, decrypted): admin-only path stays admin-only.

## Dependencies

- **v2.1a** (PR #27) — credential storage, encryption, target model. Shipped.
- **v2.1c** (PR #43) — multi-engine dispatch, Nuclei `recorded` abort path. Shipped.
- **ZAP image:** must include the `authentication-helper` addon. **Spike required (item 1 in feasibility verdict)** — confirm the addon installs cleanly via the AF `addOns` job in the headless image; if not, bake it into the Dockerfile.
- **No new env vars.** Reuses `DAST_CREDENTIAL_KEY`.

## Success Criteria

Concrete and measurable — all must be true to declare v1 done:

1. **Step editor:** the inline editor in `DastAuthPanel` can author a 5+-step login including a TOTP step, persists across reload, and respects the existing dirty-check + Save pattern.
2. **Test login:** clicking Test against a deployed Juice Shop (or equivalent SPA with login) returns `success` within 60 s. Editing one selector to a known-bad value flips it to `failed_at_step={n, selector, reason}` with the right step number.
3. **End-to-end scan against a real SPA-with-login** (Juice Shop or internal Deptex target) discovers authenticated routes that the same scan without recorded auth does not discover. Findings carry `engine='zap'` and at least one finding's URL is on a route that requires login.
4. **TOTP:** scan against a 2FA-protected fixture (e.g. a small test app wrapping `oathtool`) completes the login step using only the stored TOTP secret.
5. **SSO:** scan against a target that redirects to an external IdP (mock-OIDC or Google OAuth sandbox) completes the login and returns to the target origin.
6. **Session-loss recovery:** intentionally shorten the session cookie TTL on a fixture; scan_job completes after at least one re-login event.
7. **Pre-scan failure:** a known-bad selector causes the scan_job to fail with `auth_failed` BEFORE any spider/active-scan work. `error_details` includes step number, selector, and reason.
8. **Nuclei abort:** running a `dast_nuclei` job on a `recorded`-credential target fails immediately with the actionable error message.
9. **No regression:** all existing v2.1c tests (the 88-CVE corpus, the PGLite migration test, `dast-routes.test.ts`, `finalize-extraction.test.ts`) pass unchanged.
10. **CI gate:** at least one fixture-app e2e test (`npm run e2e:dast-recorded`) runs in CI, asserting (1)–(3) on a deterministic target.

## Open Questions

- **[blocks /plan-feature]** Does the ZAP `authentication-helper` addon install cleanly via the AF `addOns` job in our headless image, or must we bake it into the Dockerfile? Spike (~30 min) before /plan-feature.
- **[blocks /plan-feature]** ZAP browser-context scope behaviour on cross-origin SSO: does the existing `includePaths` regex confine the spider after auth completes? If not, do we need a per-credential `sso_origins[]` allowlist for the auth phase? Spike (~1 hr) before /plan-feature.
- **[can defer to /implement]** Sortable step list — use `@dnd-kit/sortable` (heavier dep if not already pulled in) or up/down buttons (lower polish but zero new deps). Decide in /implement based on existing deps.
- **[can defer to /implement]** Exact cap on step count (currently proposed 50) and selector length (1024) — pick by surveying real login flows during the smoke test.
- **[informational]** Aegis tool integration: should Aegis get a tool to view / propose changes to a recorded login? Likely v2.1e+ — out of scope for v1.

## Recommended Next Step

`/plan-feature` once the two pre-flight spikes are done (addon installability + cross-origin SSO scope). Both are small, ~couple hours combined; they'd let `/plan-feature` write a concrete migration-free Dockerfile + YAML-builder plan without speculative branches.
