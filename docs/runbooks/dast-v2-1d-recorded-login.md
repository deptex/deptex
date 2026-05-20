# DAST recorded-login runbook (v2.1d)

The recorded-login strategy lets DAST scan apps behind a non-trivial sign-in
(multi-step forms, CSRF tokens, SPAs, SSO redirect chains, TOTP). It replays
an authored step list inside ZAP's browser-based Automation Framework auth
method (`authhelper` addon, `firefox-headless` browser).

## When to use which auth strategy

| Strategy | Use when |
|---|---|
| `form` | Single-POST login (legacy server-rendered form, fields known). |
| `jwt` | Token-only API target; no UI login flow. |
| `cookie` | You have a current session cookie jar (rare; short-lived). |
| **`recorded`** | Anything else: CSRF, JS-rendered, multi-step, SSO, TOTP. |

## Authoring a recorded login

Open **Project → DAST → Target → Edit credentials → Recorded login**. The
editor has three blocks:

1. **Header:** optional `Label` (≤80 chars; shows in the credentials list)
   + `Login page URL` (the page the browser navigates to first).
2. **Steps:** ordered list; click **+ Add step** to extend. Each step is
   one of:
   - `Go to URL` — only valid as **step 1**. Sets the entry URL. (For
     mid-flow navigation, use `Click` on a link or button.)
   - `Click` — CSS or XPath selector targeting a clickable element.
   - `Type username` — CSS or XPath targeting the username input.
   - `Type password` — CSS or XPath targeting the password input.
   - `Type TOTP code` — CSS or XPath targeting the 2FA input. Requires
     a base32 `TOTP secret` in the credentials block.
   - `Type custom value` — CSS or XPath + a literal value (REDACTED in
     logs and summaries — treat the value as potentially secret).
   - `Wait` — pause N ms.
   - `Press Enter` / `Press Escape` — keystroke fallbacks.

   Reorder with the up/down chevrons. Remove with the trash icon. Per-step
   `timeout` defaults to 1000 ms; bump for slow-loading pages.

3. **Credentials:** username, password, optional TOTP secret (RFC 6238
   base32, 16–256 chars: `A-Z2-7`). The TOTP secret is encrypted on the
   server alongside the rest of the payload.

### Indicators (Logged-in / Logged-out regex)

Required for the **pre-scan auth probe** to know whether the login worked.
Pick text that:
- Logged-in: appears **only** when authenticated (e.g. `Sign out`,
  `Welcome, <username>`, account dropdown text).
- Logged-out: appears **only** when unauthenticated (e.g. `Sign in`,
  `Log in to continue`).

Both are passed through `safe-regex2` server-side — overly complex regex
gets rejected at save time.

## Test login — iterate without burning a 30-min scan

Hit **Test login** to dry-run only the recorded login (no spider, no
active-scan). The button queues a regular `dast_zap` scan job with
`payload.dry_run: true`; the worker branches into the login-only path,
writes the result to `scan_jobs.error_payload` under
`{kind: 'test_result', test_result: {…}}`, and the editor polls until
the result lands.

Typical latency:
- p50: ≤ 60s (warm Fly worker)
- p95: ≤ 120s
- Worst case: ~5 min if the Fly worker is cold + SSO redirect chain is long.
  The banner shifts to "Still running…" past 90s rather than ending the
  poll.

### Banner outcomes

| Banner | What happened | Fix |
|---|---|---|
| `✓ Logged in (7.4s, 5 steps)` | Success. | — |
| `Step 3 (click): selector "#submit" was not visible in time` | `selector_not_visible_after_timeout`. | Verify the selector in browser devtools; check timing (raise `timeout`) or add a `Wait` before. |
| `Step 4: cross-origin navigation was blocked` | `cross_origin_blocked`. | Add the IdP origin to the credential's `sso_origins[]` (v1: API only; UI field pending). |
| `Step 2: TOTP code generation failed` | `totp_generation_failed`. | Re-paste the base32 secret; check it's exactly the secret your TOTP app uses. |
| `the browser crashed during this step` | `browser_crashed`. | Re-run; if persistent, file an issue (Firefox + ZAP browser-auth flake). |
| `logged-in indicator did not match after login` | `logged_in_indicator_missed`. | Either the login truly failed OR the `Logged-in indicator` regex doesn't match the post-login page. Inspect the page in browser devtools after sign-in. |
| `A scan is running on this target. [Cancel scan] to test.` | The Test-login button is blocked by the 1/project DAST concurrency cap. | Click **Cancel scan** to free the slot, then Test-login retries automatically. |
| `Worker unavailable — try again in 30 seconds.` | Fly machine failed to start. | Retry. If repeated, the depscanner Fly app may need attention. |

## Concurrency model

A Test-login dry-run counts against the 1-scan-per-project DAST cap
(intentional — avoids credential races and Fly machine churn). When a
real scan is already running on the target, the Test-login button
returns 409 and the editor surfaces a **Cancel running scan** affordance
that calls `POST /api/projects/:projectId/dast/jobs/:jobId/cancel` to
free the slot.

## Session-loss recovery

If the app expires the session mid-scan (cookie TTL, idle timeout), ZAP's
`verification.loggedOutRegex` fires and the browser-auth method re-runs.
The `retry_login_on_lost` flag on the credential row gates this (defaults
to false). Recorded logins inherit the same `consecutive_lost_count`
recovery posture form auth uses today; mid-scan re-login failures surface
as `error_payload.kind: 'session_loss'` (separate from pre-flight
failures, which use `kind: 'pre_flight_failed'`).

## TOTP secrets

- Format: RFC 6238 base32 (`A-Z2-7`), 16–256 chars.
- Get the secret when configuring 2FA — most apps offer "show secret" or
  a `otpauth://` URI from which the secret can be extracted.
- The TOTP code is generated **at scan time** by ZAP's `TOTP_FIELD` step
  type using SHA1, 6 digits, 30s period (the RFC defaults).
- Don't share the secret across users — generate a service-account
  credential dedicated to DAST.

## SSO (cross-origin)

A login flow that bounces to `accounts.google.com` / `okta.com` / etc.
mid-step. The recorded login replay follows the redirect; the browser
context's scope is widened during the auth phase and narrowed before the
spider runs. If your IdP origin trips `cross_origin_blocked`, set
`sso_origins: ['https://accounts.google.com']` on the credential payload
(v1: API field is forward-compat; UI is a v2.1e card).

## What's NOT supported in v1

- **Push-notification 2FA** (Duo Push, Okta Verify) — no replay model.
- **WebAuthn / passkeys** — no replay model.
- **SMS / email codes** — no inbox poll in v1.
- **CAPTCHA** — fundamentally browser-only.

For these, configure a service account with TOTP or skip auth on the
target's DAST profile.
