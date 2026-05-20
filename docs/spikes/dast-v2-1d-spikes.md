# DAST v2.1d — pre-flight spike outcomes

This doc captures empirical outcomes from the M0 spikes in
`.cursor/plans/dast-v2-1d-recorded-login.plan.md`. Each spike has a
**status** (resolved / pending) and a **decision** that shapes M2 / M3 code.

The current commits implement reasonable best-evidence defaults; some are
verified post-code-write. Update this doc as spikes resolve to lock the
choices.

---

## Spike-1 — ZAP browser-auth works end-to-end in the depscanner image

**Status: PENDING (best-evidence defaults shipped)**

**Goal:** prove a 3-step CLICK+TYPE+TYPE replay succeeds inside the current
`depscanner` Docker image against the fixture login app at
`test/e2e/fixtures/login-app/`.

**How to run:**

```sh
# Terminal 1 — start the fixture
cd depscanner/test/e2e/fixtures/login-app
npm install && npm start

# Terminal 2 — boot the depscanner image and run a fixture YAML
cd depscanner
npm run docker:build
docker run --rm -v $PWD/test/e2e/fixtures:/fixtures \
  -e DAST_CREDENTIAL_KEY="$(openssl rand -hex 32)" \
  deptex-cli:local \
  /zap/zap.sh -cmd -autorun /fixtures/spike-1.yaml
```

(`spike-1.yaml` is the YAML built by `buildAutomationYaml({..., loginOnly:
true})` against the fixture — capture it from the worker logs, or use
`npm run e2e:dast-recorded` which exercises the builder + parser).

**Success criterion (all three must hold):**
1. ZAP exits with code 0.
2. stderr / diagnostic log contains a literal marker indicating the
   browser-auth method ran successfully. **Action:** capture the exact
   marker string here once observed (e.g. `[BrowserBasedAuth] verification
   succeeded`).
3. `verification.loggedInRegex` set to `Welcome, alice` matches the
   post-login `/dashboard` page.

**Decision matrix:**
- **Green:** AF `addOns` install path works. The current YAML emit (which
  always includes `authhelper` in `addOns.install[]`) is correct. No
  Dockerfile change needed beyond pre-baking the JAR.
- **Yellow (addon installs but CLICK/TYPE fails):** missing `geckodriver`
  or `selenium-server`. Add to `depscanner/Dockerfile`; rerun.
- **Red (addon install itself fails via AF):** bake the JAR into the
  Dockerfile at build time; drop `authhelper` from `addOns.install[]`
  (yaml-builder already supports the omission with a one-line guard —
  add when needed).

---

## Spike-2 — Cross-origin SSO scope behaviour

**Status: PENDING**

**Goal:** confirm that ZAP browser-auth follows cross-origin redirects
during login even when the context's `includePaths` is pinned to the
target origin, AND the spider/active-scan respect `includePaths` after
auth completes.

**How to run:** AF YAML with `includePaths: ['^https://httpbin\\.org/.*$']`
+ a `browser` auth that navigates off-origin mid-flow (use httpbin's
redirect endpoints).

**Outcomes:**
- **Green:** Scope naturally relaxed during auth. No schema change.
- **Yellow:** `sso_origins[]` payload field becomes load-bearing. The
  type is already present as forward-compat (see
  `backend/src/types/dast.ts:RecordedCredentialPayload.sso_origins`); the
  yaml-builder and validator already accept it. If yellow lands, update
  yaml-builder to emit a widened `includePaths` for the auth phase + a
  `pruneSiteTree` job before the spider runs.

---

## Spike-2B — `loggedOutRegex` re-fires browser-auth

**Status: PENDING**

**Goal:** confirm that ZAP's session-management re-fires the **browser**
auth method (not just form) when a response matches `loggedOutRegex`.

**How to run:** AF YAML against a short-TTL-cookie fixture; let scan exceed
TTL; inspect the diagnostic log for a re-login event.

**Outcomes:**
- **Green:** Recorded scans inherit `retry_login_on_lost` behaviour
  unchanged. Success Criterion #6 stands.
- **Yellow:** `retry_login_on_lost` disabled for recorded strategy in v1;
  document the limitation; Success Criterion #6 moves to v2.1e.

---

## Spike-3 — Capture real `diagnostics: true` log fixtures

**Status: PENDING (parser uses best-evidence regex)**

**Goal:** capture two real ZAP browser-auth diagnostic logs (one success,
one failure) and commit them as fixtures so the parser can be tightened
against the actual format.

**How to run:** during Spike-1, ZAP autorun writes diagnostic events to
stderr (the worker buffers them). Copy the raw output to:

- `depscanner/test/fixtures/zap-login-diagnostics/<ZAP-version>/success.log`
- `depscanner/test/fixtures/zap-login-diagnostics/<ZAP-version>/selector_not_visible.log`

The `<ZAP-version>` directory name must match the ZAP version baked into
`depscanner/Dockerfile`. The CI guard (see
`.github/workflows/dast-recorded-e2e.yml` if/when added) fails if the
Dockerfile bumps ZAP without a matching fixture-dir update.

**Decision:** the parser
(`depscanner/src/dast/runner.ts:parseZapLoginDiagnostics`) currently uses
defensive regex matchers (`STEP_LINE_RE`, `STEP_TYPE_RE`,
`STEP_SELECTOR_RE`, `VERIFY_RE`) that tolerate several plausible log shapes.
Once Spike-3 commits real fixtures, tighten the regex to match the
observed format and add per-fixture unit tests in
`depscanner/test/dast-recorded-pipeline.test.ts`.

---

## Spike-4 — `auth_strategy` CHECK already accepts `'recorded'`

**Status: RESOLVED (verified from context)**

**Outcome:** `backend/database/phase24a_dast_v2_engine_additive.sql:136-137`
defines:

```sql
auth_strategy TEXT NOT NULL
  CHECK (auth_strategy IN ('form', 'jwt', 'cookie', 'recorded')),
```

No schema change needed. The validator's `VALID_STRATEGIES` set was
widened to include `'recorded'` in `backend/src/lib/dast-credential-validate.ts`.

---

## Spike-5 — AF `onFail: exit` halts spider/active-scan on verification miss

**Status: PENDING (best-evidence default: yes)**

**Goal:** prove that an AF YAML with `requestor` (verification probe) +
`spider` + `activeScan` jobs aborts the spider/activeScan when the
requestor's `verification.loggedInRegex` misses.

**How to run:** run the Spike-1 fixture YAML with `failOnError: false` (the
current default) but `onFail: exit` on the requestor job. Force a regex
miss (set `loggedInRegex` to a string NOT present on the login response).
Inspect: do spider/activeScan jobs run, or does ZAP stop?

**Outcomes:**
- **Green:** `onFail: exit` is honoured — current YAML emit is correct.
- **Yellow:** subsequent jobs run anyway → fall back to worker-side gating
  (run the login-only YAML first as a SEPARATE ZAP invocation; on success
  spawn the full-scan YAML in the same daemon). Costs one extra cold-start
  on the real-scan path but preserves fail-fast semantics.
- **Red:** no chain mechanism → two separate ZAP processes (login + scan).
  Document the doubled cold-start cost in the runbook NFR.

The yaml-builder supports all three outcomes via the `loginOnly` flag.

---

## How to update this doc

After running a spike:
1. Set the status to `RESOLVED` with a one-line outcome summary.
2. If the outcome is green, the code as-shipped is correct — no change.
3. If yellow/red, file the code patch needed and link the commit.
4. Update `.cursor/plans/dast-v2-1d-recorded-login.plan.md` §Risks if a
   risk rating shifts.
