# DAST v2.1d — pre-flight spike outcomes

This doc captures empirical findings from M0 spikes against the fixture
login app at `depscanner/test/e2e/fixtures/login-app/`, ZAP 2.17.0 (`authhelper`
v0.39.0). **Three of the five spikes ran; two findings invalidate parts of
the v3 plan and require code rework before this branch is merge-ready.**

## Setup used

- Docker: `ghcr.io/zaproxy/zaproxy:stable` (resolves to `2.17.0` per
  `auth-report.json::@version`).
- Fixture: `node depscanner/test/e2e/fixtures/login-app/server.js` (port
  8080 on host; reached from container via `--add-host=host.docker.internal:host-gateway`).
- YAML mounted at `/zap/wrk/automation.yaml`; `MSYS_NO_PATHCONV=1` set so
  Git Bash doesn't mangle the `/zap/wrk/...` arg.

## Spike-1 — addon installability + 3-step CLICK+TYPE+TYPE replay

**Status:** PARTIALLY RESOLVED. Image launches ZAP cleanly. `authhelper` is
pre-installed (no `addOns` job needed — ZAP warns `The addOns job no longer
does anything and should be removed`). Browser-auth runs and the user reaches
the post-login page in ~17s wall-clock. BUT see Spike-3 — the steps as
authored are **silently dropped** by ZAP at v0.39.0 of the authhelper, and
ZAP falls back to AUTO_DETECT for username/password fields. The 17s wall-clock
includes Firefox cold start (~10s) + AUTO_DETECT login (~7s).

**Decisions:**
- ✅ Drop the `authhelper` entry from `addOns.install[]` in `yaml-builder.ts`
  (deprecated; bake-in is the only path).
- ✅ No Dockerfile change needed — the base image ships Firefox + geckodriver
  + selenium-server already (the `selenium` and `webdriverlinux` add-ons are
  in the v2.17.0 base).

## Spike-3 — Diagnostic format (THIS IS THE BIG ONE)

**Status:** RESOLVED with two breaking findings.

### Finding A — `diagnostics: true` produces NO per-step events

Three runs confirmed: ZAP 2.17.0 with `authhelper` 0.39.0 produces no
per-step BrowserBasedAuth markers in stderr OR `~/.ZAP/zap.log`. The only
auth-related markers in the log are two lines:

```
INFO  User - Authenticating user: deptex-dast-user
INFO  BrowserBasedAuthenticationMethodType - Updating session management method ... with session ...CookieBasedSession
```

These two lines appear **regardless of whether each step succeeded or failed.**
The bad-selector run produces the SAME log markers as the good-selector run,
because the steps go through AUTO_DETECT (see Finding B).

**Code impact:**
- `depscanner/src/dast/runner.ts:parseZapLoginDiagnostics` hunts for
  `BrowserBasedAuth step #N type=X selector=Y SUCCESS|FAILED` markers that
  don't exist. **Always falls through to the unstructured `raw_log` path.**
  In the FE banner this would render "ZAP diagnostic log was unstructured"
  for every Test-login.
- Rework: the parser must be rewritten to consume the **`auth-report-json`**
  file ZAP's authhelper add-on generates when you ask for it.

### Finding B — Our `steps[]` array is silently dropped

Captured `auth-report.json` (committed at
`depscanner/test/fixtures/zap-login-diagnostics/2.17.0/auth-report-empty-steps.json`)
echoes back the YAML ZAP actually loaded:

```yaml
authentication:
  method: browser
  parameters:
    loginPageUrl: http://host.docker.internal:8080/login
    loginPageWait: 5
    browserId: firefox-headless
    stepDelay: 0
    diagnostics: false      ← our true got stripped
    steps: []               ← our 3 steps got dropped
```

Our YAML had `diagnostics: true` and a `steps:` array with three entries.
ZAP's afEnv echo shows BOTH stripped to defaults. Yet auth ran (status:
`stats.auth.browser.passed=1`, `stats.auth.state.loggedin=1`).

How? ZAP's authhelper fell back to **AUTO_DETECT mode** when it couldn't
parse our steps — it found the username/password fields by inference and
ran them without using our CSS selectors.

The docs ([browser-auth](https://www.zaproxy.org/docs/desktop/addons/authentication-helper/browser-auth/))
say the YAML schema is:

```yaml
authentication.parameters.steps:
  - description: "..."
    type: "USERNAME"
    cssSelector: "input#email"
    value: "alice@example.com"
    timeout: 1000
```

The docs example explicitly includes a `value:` field on USERNAME/PASSWORD
steps. Our YAML omitted `value` because we assumed ZAP would pull from
`users[].credentials.{username,password}` via implicit substitution.

**Hypothesis (UNVERIFIED — needs another spike):** authhelper v0.39.0
requires `value` on each USERNAME/PASSWORD/TOTP_FIELD/CUSTOM_FIELD step;
without it, the step is invalid and ZAP silently drops the entire steps
array (probably an aggressive schema-validation guard) and falls back to
AUTO_DETECT.

**Required next experiments (run before merging this branch):**

1. Try `value: "alice@example.com"` literal on USERNAME — does the steps
   array survive? (Confirms the dropped-array hypothesis.)
2. If yes, can `value` use a substitution macro like `{%username%}` that
   reads from `users[].credentials.username`? (Determines whether we
   inject literals into the YAML — security-relevant: the password would
   be written to disk in plaintext alongside the form-strategy's existing
   behaviour. Acceptable: the existing yaml-builder ALREADY writes the
   YAML at mode 0600 + unlinks immediately after spawn.)
3. If macros don't work, the validator + auth-config + yaml-builder all
   need to be revised to thread the decrypted credential values directly
   into each step's `value` field.

### Finding C — Diagnostics come from a REPORT JOB, not stderr

To get structured per-event auth diagnostics, the YAML needs a `report`
job with `template: auth-report-json`:

```yaml
jobs:
  - type: report
    parameters:
      template: auth-report-json
      reportDir: /zap/wrk
      reportFile: auth-report.json
```

The generated `auth-report.json` shape (real captured fixture under
`depscanner/test/fixtures/zap-login-diagnostics/2.17.0/auth-report-empty-steps.json`):

```json
{
  "@programName": "ZAP",
  "@version": "2.17.0",
  "site": "http://host.docker.internal:8080",
  "summaryItems": [
    {"description": "Authentication failed", "passed": false, "key": "auth.summary.auth"},
    {"description": "Username field identified", "passed": true,  "key": "auth.summary.username"},
    {"description": "Password field identified", "passed": true,  "key": "auth.summary.password"},
    {"description": "Session Handling identified", "passed": true, "key": "auth.summary.session"},
    {"description": "Verification URL identified", "passed": true, "key": "auth.summary.verif"}
  ],
  "failureReasons": [
    {"key": "auth.failure.logged_in", "description": "No indication found of being logged in."}
  ],
  "afEnv": "<the loaded YAML as a string>",
  "afPlanErrors": [],
  "statistics": [
    {"key": "stats.auth.browser.foundfields", "value": 1, "scope": "site", "site": "..."},
    {"key": "stats.auth.browser.passed", "value": 1, "scope": "site", "site": "..."},
    {"key": "stats.auth.state.loggedin", "value": 1, "scope": "site", "site": "..."},
    {"key": "stats.auth.success", "value": 1, "scope": "site", "site": "..."},
    ...
  ]
}
```

The parser contract is now:
- **Success:** `summaryItems[?key=auth.summary.auth].passed === true` AND
  `failureReasons[]` is empty.
- **Failure:** `summaryItems[?key=auth.summary.auth].passed === false`
  PLUS one or more entries in `failureReasons[]`. Map the `key` to our
  `reason` enum:
  - `auth.failure.logged_in` → `logged_in_indicator_missed`
  - `auth.failure.username` (TBD — needs failure-case fixture)
  - `auth.failure.password` (TBD)
  - etc.
- **No per-step `step_index`** in the report — ZAP doesn't expose which
  step failed. The `internalIndexToZapIndex[]` mapping I built is dead
  code; `failed_at_step.step_index` should be omitted or always 0 for v1.
- **`afPlanErrors[]`** carries YAML-load errors (e.g. our dropped-steps
  case may surface here once we capture a YAML ZAP rejects outright).

**Code impact:** `parseZapLoginDiagnostics` is rewritten to read
`auth-report.json` (a file on disk after the report job emits it), parse
it as JSON, return `DastLoginTestResult` from the structured summary.
The `internalIndexToZapIndex` plumbing comes out (or is reduced to no-op).
The yaml-builder needs to ALWAYS emit a `report: auth-report-json` job
when `authStrategy='recorded'`.

## Spike-5 — AF `onFail: exit` halts subsequent jobs on auth failure

**Status:** UNTESTED yet (didn't run a verification-failure path with
spider/scan jobs). Recommended next experiment.

## Spike-2 — Cross-origin SSO scope

**Status:** UNTESTED.

## Spike-2B — `loggedOutRegex` re-fires browser-auth mid-scan

**Status:** UNTESTED.

## Spike-4 — `auth_strategy` CHECK accepts `'recorded'`

**Status:** RESOLVED from context. phase24a:137 lists `'recorded'`.

---

## Implications for the branch as currently pushed

The architecture and most layers are correct. **The parser and the
YAML-emit shape for auth steps both need rework before merge.** Concrete
changes required:

### Critical (must do before merge)

1. **Rewrite `parseZapLoginDiagnostics`** (depscanner/src/dast/runner.ts)
   to consume the `auth-report.json` file ZAP emits, NOT stderr/stdout.
   Use the captured fixture as the reference shape. Test cases need to be
   regenerated from real ZAP runs (one success, one failure with the
   correct `auth.failure.*` key).

2. **Modify yaml-builder.ts** to:
   - Always emit a `report` job with `template: auth-report-json` (in
     addition to the existing `traditional-json` report for ZAP findings).
     The report dir/file should be `/zap/wrk/auth-report.json` so the
     pipeline can read it.
   - Remove `authhelper` from `addOns.install[]` (deprecated).
   - Remove `diagnostics: true` (no-op in this ZAP version per Finding A).
   - The `requestor` job needs `parameters.user: deptex-dast-user` so ZAP
     actually exercises the auth method (verified empirically — without
     `user:`, ZAP never replays auth).

3. **Run another spike to verify the `steps` array survives ZAP's
   YAML-load**. If `value: <literal>` is required, the auth-config layer
   must inject the decrypted credential into each step's `value` field at
   YAML emit time (NOT via a substitution macro — the macros are
   form-strategy-specific). The plaintext-on-disk posture is unchanged
   from the existing form-strategy path.

4. **Update `runRecordedLoginProbe`** (depscanner/src/dast/pipeline.ts)
   to read `auth-report.json` after ZAP exits, not parse stderr.

5. **Update the route's request to use `parameters.user: deptex-dast-user`**
   on the requestor job in `yaml-builder.ts`.

### Tightening (do after the critical rework)

6. **Re-run Spike-1 with a working step list** and re-time the wall-clock.
   The 60s p50 / 120s p95 NFR needs to be revisited against real numbers.
7. **Run Spike-5** to determine whether `onFail: exit` on the requestor
   job halts spider/active-scan when verification fails.
8. **Run Spike-2** (cross-origin SSO) + **Spike-2B** (session re-trigger).
9. **Regenerate the unit-test fixtures** in
   `depscanner/test/dast-recorded-pipeline.test.ts` against the new parser.
   The current 32 cases assert against fabricated log shapes that don't
   exist in real ZAP output.

### Optional (post-rework)

10. The captured fixture
    `depscanner/test/fixtures/zap-login-diagnostics/2.17.0/auth-report-empty-steps.json`
    documents the AUTO_DETECT fallback case. Once steps work, capture a
    second fixture (real success with explicit steps) and a third
    fixture (bad selector → real failure).

## Estimated rework effort

- Parser rewrite + test regeneration: ~1h
- yaml-builder + auth-config injection model fix: ~1.5h
- Empirical re-verification (~5 Docker round-trips of 2-3 min each): ~30 min
- Doc updates: ~30 min

Total: **~3-4h** of focused work, fastest done with Docker available and
Henry's hands-on iteration.

## Files captured in this branch from the empirical run

- `depscanner/test/fixtures/zap-login-diagnostics/2.17.0/auth-report-empty-steps.json`
  — real ZAP auth-report from the AUTO_DETECT fallback case (current code path).
