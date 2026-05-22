# DAST HAR Import (replay auth) — Dogfood Runbook

> **HARD PROHIBITIONS — read first.**
>
> - **Dev tenants ONLY.** Do not capture a HAR against a real production
>   tenant — captures hold session cookies + Authorization headers + (if
>   the IdP runs SSO) cross-org bearer tokens. The 2023 Okta breach was
>   exactly this attack class: support-bundle HAR uploads with valid
>   session cookies got exfiltrated and reused.
> - **No real work accounts.** Use a throwaway IdP user with no access
>   to anything sensitive. If you're testing Auth0 / Entra / Okta /
>   Google Workspace, spin up a *dev tenant* — not your engineering
>   account on a prod tenant.
> - **Post-dogfood checklist (every time):**
>   1. Revoke the captured session (sign out of the IdP from another
>      browser; on Auth0, clear the management-API token from your
>      tenant logs).
>   2. Rotate the TOTP secret if one was inlined.
>   3. `shred -u <file.har>` on Linux / `sdelete -p 4 -z <file.har>` on
>      Windows — `rm` alone leaves the bytes on disk.
>   4. Walk the git log for accidental commits:
>      `git log --all --diff-filter=A --name-only | grep -i '\.har$'`
>      Root `.gitignore` blocks `**/*.har`, but a `git add -f` could
>      override it.
> - **Throwaway Supabase only.** If you're testing against a
>   Supabase-backed Deptex dev tenant, make sure DAST_CREDENTIAL_KEY is
>   set to a throwaway hex value (NOT the prod key); otherwise a stale
>   row from this dogfood run lives in prod's encrypted column.

---

## What this runbook is for

End-to-end verification of the Phase 36 replay-auth strategy:

1. Capture a real DevTools HAR against a dev IdP.
2. Drop it into the Replay tab of a DAST target.
3. Confirm the preview + summary + non-replayable detection.
4. Run Test-replay and verify success.
5. Run a real DAST scan against the authenticated route.
6. Validate mid-scan session expiry behavior (Patch D session-loss).

## 4 dogfood targets

Run each at least once per significant pipeline change.

### (a) Form-POST fixture — the dast-auth-app form route

This is the simplest path; uses our own M0 fixture so no third-party tenant
is touched. Verifies the structural happy path.

```bash
# 1. Start the fixture (terminal 1)
cd depscanner
npx tsx test/fixtures/dast-auth-app/server.ts
# → http://localhost:4500

# 2. In a browser w/ DevTools open (Network tab, "Preserve log" on):
#      POST http://localhost:4500/login  with form alice/wonderland
#      GET  http://localhost:4500/dashboard
#      File → "Save all as HAR with content" → form-dogfood.har

# 3. In Deptex Replay tab, drop form-dogfood.har.
#    Expect: 2 requests, 1 origin, 1 Set-Cookie, 0 non-replayable warnings.

# 4. Click Test replay. Expect green "Test replay succeeded".

# 5. Save credential. Run a real DAST scan against the target.
#    Expect: scan completes; findings include passive-scan alerts emitted
#    against the dashboard (which means the cookie was attached).
```

### (b) Auth0 dev tenant

Verifies Universal Login + cross-origin SSO (Auth0 redirects to a separate
`*.auth0.com` hostname).

```text
1. Provision a free Auth0 dev tenant. Add a single SPA application.
2. Create a throwaway user (alice@deptex-dogfood.test).
3. In a browser w/ DevTools open + "Preserve log":
   - POST /usernamepassword/login   (Auth0 password-realm endpoint)
   - GET  /authorize?...            (Auth0 OIDC redirect)
   - GET  https://<app>/callback    (back to your app)
   - GET  https://<app>/profile     (post-auth page)
   - File → Save all as HAR.
4. Drop into Replay tab.
   Expect: ~4-6 requests, 2 origins (Auth0 + app), TOTP detected if
   MFA enabled, has_non_replayable_pattern=false unless MFA is via
   WebAuthn/SMS.
5. If TOTP detected: copy the base32 secret from your Auth0 user's MFA
   enrolment screen, paste into the TOTP secret field.
6. Save + Test-replay. Expect success.
```

### (c) Microsoft Entra dev tenant (TOTP path)

Validates Patch A's freshness guarantee end-to-end against a real IdP that
enforces RFC 6238 TOTP with strict ±1 step window.

```text
1. Provision a free Microsoft Entra dev tenant + an Enterprise App.
2. Throwaway user with TOTP enrolled (NO authenticator-app push; raw
   30s codes only).
3. Capture HAR through the Entra login + TOTP-verify + post-auth page.
4. Drop into Replay tab.
   Expect: TOTP detected on the verify request (body_field='code',
   body_kind='form' typical for Entra).
5. Paste the base32 secret.
6. Test-replay. The first attempt should succeed; wait 31 seconds and
   click Test-replay again — should ALSO succeed (proves Patch A
   re-generates fresh codes per invocation rather than caching the
   one-shot code that was in the original HAR).
```

### (d) HMAC-cookie fixture — dast-auth-app `/hmac-login`

Verifies non-opaque session formats thread correctly. The fixture's HMAC
route signs `{userId, expires}` with HS256 and a per-process key.

```bash
# Same fixture spawn as (a), but capture against:
#   POST http://localhost:4500/hmac-login   (form alice/wonderland)
#   GET  http://localhost:4500/hmac-dashboard
#
# Expect the same flow as (a). The Set-Cookie carries the
# JSON.base64.HMAC envelope; ZAP's cookieBasedSessionManagement
# threads it onto subsequent requests without caring about format.
```

## Mid-scan session expiry validation

Required to confirm Patch D's session-loss machinery extension fires for
replay. This is the only test that needs the `/__test/expire-totp-session`
fixture helper:

```text
1. With dogfood target (c) configured and saved, kick off a real DAST scan
   (POST /dast/scan), NOT Test-replay.
2. While the scan is running, hit:
     POST http://localhost:4500/__test/expire-totp-session?session_id=<sid>
   (Get the sid from the fixture's stdout request log.)
3. The next request the spider issues will fail the logged_out_indicator
   check; ZAP's authentication-helper invokes our script again, which
   POSTs /totp/verify with a FRESH code generated by the inlined RFC 6238
   helper.
4. If the re-auth path works: scan continues, findings count is positive
   at end.
5. If the re-auth path is broken: scan halts with
   error_payload.kind='session_loss' after 4 consecutive misses (engine-
   wide threshold per pipeline.ts:1820+).
```

## Stop conditions

If you see any of these, **stop and file a P0 issue**, do not proceed:

| Symptom | Likely cause |
|---|---|
| Preview response contains a raw cookie value, Authorization header value, or password substring | Privacy scrubber regression; `dast-har-privacy.test.ts` should have caught this — investigate which canary it missed. |
| Save succeeds with no `dast_encryption_not_configured` 503 but the credential row has `encrypted_payload IS NULL` | Encryption path broken end-to-end; check DAST_CREDENTIAL_KEY env. |
| Test-replay returns success but the fixture's `/totp/verify submitted_code=` log shows the SAME code across two runs >30s apart | Patch A freshness regression — the RFC 6238 helper isn't re-evaluating. |
| Real scan exit_code=0 but `error_payload.kind='session_loss'` despite mid-scan expiry being injected | Patch D wiring broken — the session-loss envelope isn't firing. |
| Any `console.error` in the worker log includes literal cookie / bearer / TOTP secret bytes | Logging-redaction regression; check `redactCredentials()` wraps every log site. |

## `[dast-replay-metric]` log line — what to grep

The worker emits a structured log after every replay-auth setup completes.
Symptom-to-cause table:

```
{ strategy: 'replay', request_count, replay_duration_ms,
  login_indicator_hit_ms, totp_regen_count,
  totp_regen_error: 'ok'|'bad_secret'|'algorithm_mismatch'|'no_secret_provided',
  reauth_count }
```

- `totp_regen_error: bad_secret` — base32 didn't decode. Validator regressed
  or the user typed lowercase / has spaces.
- `totp_regen_error: algorithm_mismatch` — IdP uses non-SHA-1 (v2 backlog).
- `reauth_count > 0` — Patch D fired at least once; if `> 4` the scan halted
  with session_loss.
- `replay_duration_ms > 2000` — slow IdP or oversized HAR; investigate.
