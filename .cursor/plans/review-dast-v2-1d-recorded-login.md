# Plan Review — dast-v2-1d-recorded-login (v2 — re-review)

**Verdict: REWORK**

- Plan reviewed: `.cursor/plans/dast-v2-1d-recorded-login.plan.md` (rewritten 2026-05-20 after the prior REWORK verdict)
- Brief: `.cursor/plans/feature-brief-dast-v2-1d-recorded-login.md`
- Prior review: archived at top of this file's previous version (REWORK with 5 P0s — 3 resolved by cut, 2 by patches)
- Generated: 2026-05-20
- Mode: lean (no debate); 6 personas
- Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout
- Vote tally (inferred): **READY 0 / REVISE 2 / REWORK 4**
- Findings: **5 verified P0** / **15 P1** / **17 P2** / **14 P3**

## Summary

The cut (`dast_login_test` subtype → `dast_zap + payload.dry_run:true`) resolved 3 of the prior 5 P0s cleanly — no migration, no `queue_scan_job` re-create, no naming collision. **But the patch introduced or missed 5 new P0s, two of which are build-time blockers verified against `origin/main` code:**

1. **Column name doesn't exist** — the plan writes `error_details` ~14 times; the actual column on `scan_jobs` is `error_payload` (added in `phase24a_2_dast_v2_engine_pipeline.sql:44`). Verified by `git show`.
2. **"Cancel running scan" mitigation has no backend route** — `pipeline.ts:isJobCancelled` reads a flag, but no route in `backend/src/routes/dast.ts` writes one. Verified zero grep matches for cancel routes. The P0-4 concurrency mitigation from the prior review is fictional.
3. **GET `/dast/jobs?id=…` SELECT doesn't return the column** the plan polls — so even after fixing the column name, the FE polling banner sees nothing.
4. **AF YAML same-process architecture is unverified** — ZAP's `verification` block is context-attached, not a job; with `failOnError: false` (yaml-builder.ts:222-223), a verification regex miss does NOT halt subsequent spider/active-scan jobs. The plan's "pre-flight fail-fast" claim is structurally false as written. Convergent finding (skeptic + architect, two independent personas).
5. **`runDastPipeline` writes findings unconditionally after `runZapWithControlPlane`** — the dry-run branch must intercept BEFORE `buildAutomationYaml`, not after. Plan glosses this; M3.3's "early exit" wording papers over the control-flow.

The cut was the right strategic call. The plan just needs another patch pass against these specific issues. None requires a fundamental rethink — all are concrete edits to existing milestones. Estimated remediation: **~1.5h of plan revision**.

## Vote Tally (inferred — no Round 3 spawn in lean mode)

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REWORK | skeptic-f1 (AF same-process) + skeptic-f3 (cancel route fictional) | Two independent verified P0s |
| pragmatist | REVISE | pragmatist-f1 (M0 over-formalised) | Plan is fixable; cut option for TOTP/SSO worth surfacing |
| scope-cutter | REVISE | scope-cutter-f1 (cut M7 CI gate) | Plan buildable; cuts available |
| architect | REWORK | architect-f1 (column name) + architect-f2 (jobs GET) + architect-f3 (AF) | Three verified P0s, two of which are independently verifiable build-blockers |
| test-strategy-auditor | REVISE | tsa-r2-f1 (dry-run negative assertions) | Test grid mostly absorbed; gaps are P1/P2 |
| opportunity-scout | READY | — | All P3 opportunities; plan is buildable once P0s patched |

## P0 — Fundamental Concerns

### P0-1 — `error_details` column doesn't exist; real column is `error_payload` `[SOLO architect — verified by reviewer]`

- **Plan section:** Overview / Data Model `error_details.test_result` namespace / M3.3 / M4.1 / M7.2 / Success Criterion #7 / Success Criterion #12 (~14 references)
- **Claim:** The plan writes test results to `scan_jobs.error_details.test_result` and pre-flight failures to `scan_jobs.error_details.failed_at_step`. No such column exists.
- **Evidence (verified by reviewer):** `git show origin/main:backend/database/phase24a_2_dast_v2_engine_pipeline.sql:44` adds `error_payload JSONB`. `git show origin/main:depscanner/src/dast/pipeline.ts:970` writes `error_payload: payload`. Zero `error_details` matches in either file.
- **Suggested patch:** Global rename `error_details` → `error_payload` across the entire plan (Overview, Data Model heading + body, M3.3 dispatch, M4.1 audit-log description, M7.2 e2e assertion, Success Criteria #7 + #11 + #12, edge cases, frontend rendering refs). Also update phase24a_2's `COMMENT ON COLUMN scan_jobs.error_payload` via a docs-only refresh in schema.sql (no migration; comment lives in the schema dump). **Apply unconditionally.**

### P0-2 — GET `/dast/jobs?id=…` SELECT omits the column the FE polls `[SOLO architect — verified by reviewer]`

- **Plan section:** M5.1 useJobResult / API Design / Frontend Design "Live result banner"
- **Claim:** The Test-login UX polls `GET /api/projects/:projectId/dast/jobs?id=…` and reads the result envelope. The existing handler at `dast.ts:836+` SELECTs only `id, status, trigger_source, target_id, target_url, scan_profile, findings_count, duration_seconds, started_at, completed_at, error, error_category, attempts, created_at`. **`error_payload` is not in the column list** and `DastJobDTO` doesn't surface it. Even after fixing P0-1, polling completes with `status='completed'` and an empty result banner.
- **Evidence (verified):** Bash grep above shows the SELECT span begins at line 836 with the column list. `error_payload` does not appear in any of the explicit-column lists for `/dast/jobs` routes in `dast.ts`.
- **Suggested patch:** Add an M4.x sub-task: "Widen `GET /dast/jobs` SELECT to include `error_payload`. Widen `DastJobDTO` to surface `error_payload: DastJobErrorPayload | null` where `DastJobErrorPayload` is a discriminated union (see P0-3 below for the `test_result` / `session_loss` / `pre_flight_failed` variants). Document the dry-run shape." Add a route test asserting the polled response includes `error_payload.test_result` after a dry-run completion. **Apply unconditionally.**

### P0-3 — "Cancel running scan" mitigation has no backend route `[SOLO skeptic — verified by reviewer]`

- **Plan section:** Concurrency behaviour (mitigation paragraph) / M5.2 (`expose cancelDastJob`) / M5.4 ("'[Cancel scan] to test' affordance") / §Edge UI Cases
- **Claim:** The plan's P0-4 (bidirectional concurrency) mitigation relies on a "Cancel running scan" UX affordance. `pipeline.ts:isJobCancelled` reads a flag (verified — used at lines 689 + 1099), but **no route in `backend/src/routes/dast.ts` writes the cancellation flag**, and no `cancel_scan_job` RPC exists. The worker can OBSERVE cancellation but no user-facing endpoint sets it. The mitigation is fictional.
- **Evidence (verified):** `git show origin/main:backend/src/routes/dast.ts | grep -E "router\.(post|delete|patch).*cancel"` returns zero results. No `cancel` keyword in any DAST route. The worker's `isJobCancelled` poll is dead infrastructure from a user-cancellation perspective.
- **Suggested patch:** Either (a) **add an M4.x sub-task: wire `POST /api/projects/:projectId/dast/jobs/:jobId/cancel` route + `cancel_scan_job` RPC** (sets `status='cancelled'` when `status IN ('queued','processing')`; permission `manage_integrations`; +1 audit log; ~1-2h additional scope) — recommended because cancel-running-scan is a P0 UX gap of the existing DAST product anyway, not just for v2.1d; or (b) **drop the "Cancel running scan" affordance from the plan**: M5.2 stops exposing `cancelDastJob`, M5.4 changes the 409 message to "A scan is running on this target. Wait for it to complete." — at the cost of the brief's "iterate quickly" user story being structurally unmet during real scans (per scoring this is at least P1 UX). **Recommend (a)** because the cancel route is needed regardless.

### P0-4 — AF YAML same-process pre-flight architecture is unverified `[CONSENSUS 2/6 — skeptic + architect]`

- **Plan section:** Overview / M2.3 (yaml-builder branch) / M3.3 (runDastPipeline dispatch) / NFR
- **Claim:** The plan asserts one autorun YAML carries `auth-verification AND spider/scan in the same ZAP process` with `pre-flight failure halts subsequent jobs`. ZAP's `verification` block is attached to the **context**, not declared as a job; `loggedInRegex` evaluates passively against responses from subsequent jobs. The added `requestor` job (architect-f10 carry-forward) issues a single GET so the regex fires — but with `env.parameters.failOnError: false` (yaml-builder.ts:222-223), a regex miss does NOT halt the spider/activeScan jobs that follow. So the worker-side branch in M3.3 ("on failure → skip spider/scan") fires AFTER ZAP has already executed spider/scan, not before.
- **Evidence:** `yaml-builder.ts:222-223` sets both `failOnError` and `failOnWarning` to `false`. ZAP AF documentation: verification is context-property, fires lazily. The plan adds a `requestor` job (M2.3 bullet) but doesn't set `onFail: exit` on it.
- **Suggested patch:** Add **Spike-5** to M0: "Prove that an AF YAML with `requestor` (loggedInRegex check) + `spider` + `activeScan` jobs aborts spider/activeScan when the requestor's verification regex fails. If unsupported, either (a) accept two ZAP invocations (login-only YAML, exit, then real-scan YAML — costs ~30-60s extra cold-start, reverses A14), or (b) emit `onFail: exit` on the verification job and verify spider/activeScan don't fire on regex miss, or (c) keep `failOnError: false` and gate spider/scan via runDastPipeline reading the requestor's output between two YAML emits (two YAMLs in one ZAP daemon — also costs more)." Until Spike-5 settles this, M2.3 + M3.3 cannot be authored. **Apply unconditionally.**

### P0-5 — `runDastPipeline` dry-run branch must intercept before YAML emit, not after `[SOLO skeptic]`

- **Plan section:** M3.3 (runDastPipeline dispatch)
- **Claim:** The dispatch reads as "invoke probe → write `error_details.test_result` → exit" but glosses over a control-flow reality. The existing `runDastPipeline` flow is: build YAML → spawn ZAP → wait → parse report → insert findings → finalize. For dry-run, the YAML must be DIFFERENT (login-only — no spider/activeScan/report jobs). The branch must happen at the TOP of the function (before `buildAutomationYaml`), gate the YAML shape, and skip the findings-insert path entirely. Plan's prose makes this look like a post-hoc bail-out.
- **Evidence:** `pipeline.ts:807-820` builds findings inserts unconditionally after `runZapWithControlPlane` returns. The dry-run path also has implications for `findings_count` (CHECK constraint allows NULL for non-DAST types but is silent on values for DAST types) and `duration_seconds`.
- **Suggested patch:** Replace M3.3's prose with an explicit code-shape sketch:
  ```ts
  // at top of runDastPipeline, after job load + credential decrypt:
  if (job.payload?.dry_run === true) {
    const probeResult = await runRecordedLoginProbe(target, credential, controlPlane);
    await supabase.from('scan_jobs').update({
      status: 'completed',
      error_payload: { kind: 'test_result', test_result: probeResult },
      findings_count: 0,
      duration_seconds: Math.round(probeResult.duration_ms / 1000),
      completed_at: new Date().toISOString(),
    }).eq('id', job.id);
    return;
  }
  // ... existing full-scan path unchanged
  ```
  Confirm phase31's CHECK accepts `findings_count=0` on `dast_zap` rows. State explicitly that the dry-run branch does NOT call `populateDependencies`, does NOT insert into `dast_findings`, does NOT flip PDVs. Test grid (M3.4) asserts these negative invariants explicitly (per tsa-r2-f1). **Apply unconditionally.**

## P1 — High-Priority Gaps (consolidated)

### `error_payload` schema overloading — single column, two failure shapes, no discriminator `[CONSENSUS — architect-f8 + tsa-r2-f3 + skeptic-f7]`

phase24a_2's COMMENT pins `error_payload` for `auth_failed` to `{consecutive_lost_count, last_logged_out_url, last_logged_out_at}` (form-strategy session-loss). The plan adds (a) `{test_result: …}` for dry-run completions (success OR failure) and (b) `{failed_at_step: …}` for recorded-strategy pre-flight failures. Three shapes under one column with no discriminator. Existing UI rendering form-strategy auth_failed will likely fall through on the new shapes.

**Patch:** Add a `kind` discriminator to `error_payload`:
```ts
type DastJobErrorPayload =
  | { kind: 'session_loss'; consecutive_lost_count: number; last_logged_out_url?: string; last_logged_out_at?: string }
  | { kind: 'pre_flight_failed'; failed_at_step: FailedAtStep; consecutive_lost_count: 0 }
  | { kind: 'test_result'; test_result: DastLoginTestResult };
```
Frontend renderer switch-cases on `kind`. Update phase24a_2 COMMENT (docs-only, refreshed via `schema:dump`). Add a regression test that the existing form-strategy auth_failed render is unchanged.

### `internalIndexToZapIndex[]` lifecycle unspecified `[CONSENSUS — skeptic-f6 + architect-f4]`

Producer (`buildRecordedAuthForZap` in auth-config.ts) and consumer (`parseZapLoginDiagnostics` in runner.ts) live in different files. Plan doesn't specify the carrier — function arg? Closure? Stored in YAML as comment? Re-derived at parse time (drift risk)?

**Patch:** Spec it explicitly in M3.2: `runRecordedLoginProbe` holds the mapping in-scope (`const {internalIndexToZapIndex} = buildRecordedAuthForZap(payload); …; const result = parseZapLoginDiagnostics(log, internalIndexToZapIndex);`). Add a unit test asserting the mapping function is deterministic over the payload (same input → same output) so retry re-derivation cannot drift.

### `scan_timeout_minutes` reconciliation for recorded strategy `[SOLO architect-f5]`

Plan claims "one autorun, one cold-start, same `scan_timeout_minutes`" but real customer SSO flows (cold Firefox + 3-5 redirects + AJAX login) routinely hit 60-120s for the login alone. The plan never says whether `scan_timeout_minutes` is bumped or the active-scan slice is reduced.

**Patch:** In M2.3, recorded-strategy YAMLs reduce `activeScan.maxScanDurationInMins` to `scan_timeout_minutes - 3` (auth budget); `ZAP_DEFAULT_TIMEOUT_MS` worker wrapper unchanged. Document in runbook.

### `startDastMachine` errors silently swallowed on `/credentials/test` `[SOLO architect-f9]`

The `/scan` route catches `startDastMachine` failures and warns but keeps the job queued. For Test-login the 60s budget is unreachable if the machine doesn't start — user sees a 5-min poll timeout, not a real failure.

**Patch:** On `POST /credentials/test`, if `startDastMachine` throws, return `503 fly_machine_unavailable` synchronously and delete the just-queued row (or mark `status='failed', error_category='engine_crash'`). UI renders "Worker unavailable — try again in 30s."

### Spike-1 success criterion too loose `[SOLO skeptic-f5]`

"ZAP reports logged in" is not the same as "exit 0 + log-line marker + verification.loggedInRegex hits a user-specific string." A ZAP-AF run can exit 0 with individual steps silently failed (default `onFail: info`).

**Patch:** Tighten Spike-1 success criterion to (a) ZAP exits with code 0, (b) stderr/diagnostic log contains a literal marker indicating browser-auth ran successfully (capture exact marker in spike doc), (c) `verification.loggedInRegex` set to a user-specific string only present post-login (e.g. "Welcome, alice"). All three must hold.

### `payload.dry_run` + `payload.source` unstructured — typo risk `[SOLO architect-f6]`

A typo (`dryRun`, `dry-run`) silently takes the wrong branch. False→full-scan is far worse than true→no-scan. No payload schema validator exists.

**Patch:** Add `DastJobPayloadSchema` (Zod or hand-rolled) in `backend/src/types/dast.ts`. Route validates at queue time; worker re-validates after load (defense-in-depth). Branch in pipeline.ts asserts the validated shape.

### M0 over-formalised; collapse 4 spikes → 1 ~45min spike `[SOLO pragmatist-f1]`

Spike-1 (image replay) and Spike-3 (capture diagnostic logs) and Spike-1 success-criterion verification all run the same fixture YAML. The natural artefact is one ~45min focused session that produces all three outputs (Dockerfile delta, parser shape, real diagnostic logs as test fixtures) and a single commit message recording the outcomes.

**Patch:** Collapse Spike-1 + Spike-3 (and the now-added Spike-5) into a single "M0 ZAP browser-auth empirical session" that runs one fixture YAML, captures all required artefacts, and commits them. Spike-2 (SSO scope + session-loss) stays a separate session because it needs a different fixture target. Spike-4 (grep-verify) folds into M1.1 as a 5-line bullet. Net: 2 spikes instead of 4; ~2-3h instead of 4-5h.

### Hidden-migration claim in v2.1e roadmap `[SOLO skeptic-f4]`

Plan §Concurrency reserves "v2.1e adds a dry_run-aware cap split inside queue_scan_job (still no migration; just a body change to the existing RPC and a re-CREATE OR REPLACE)". A re-CREATE OR REPLACE of a stored procedure IS a migration — exactly what drove the prior review's P0-3.

**Patch:** Rephrase to: "v2.1e MAY add a dry_run-aware cap split — this would require a real migration (CREATE OR REPLACE of the RPC body, with `schema:dump` refresh and two-phase rollout per `feedback_two_phase_migration_pattern`). Tracked separately, not in v2.1d."

### Downstream JSONB shape coupling — audit existing readers of `error_payload` `[SOLO skeptic-f7]`

If any SLA / recovery cron / retry-counter SQL filters `WHERE error_payload IS NOT NULL` as a "has-failure-metadata" proxy, successful dry-run completions (which write `error_payload.test_result` on success) trip those code paths.

**Patch:** Add an M3.4 audit task: grep all SQL helpers + cron functions for `error_payload` reads; confirm none treat non-NULL as a failure proxy. If any do, gate them on `error_category IS NOT NULL` instead. Document the audit outcome in the spike doc.

### `useJobResult` extraction lacks regression-test budget for DastScanningTab `[SOLO architect-f7]`

M5.1 refactors `DastScanningTab.tsx` to consume the new hook "no behaviour change" — but the existing test surface for that component may be thin or non-existent. Realtime + setInterval fallback + AbortController teardown is exactly the surface that breaks silently in a refactor.

**Patch:** Add to M5.1: if `DastScanningTab.test.tsx` exists, list it as required-pass before commit. If it doesn't exist (likely), add a small smoke test of the existing polling pattern BEFORE the refactor (capture current behaviour: idle → polling → completed, observed backoff intervals).

### Same auth replay runs TWICE on real scans `[SOLO architect-f10]`

In the same-process design, the auth-replay is part of the autorun YAML (executes once at startup). When `loggedOutRegex` fires mid-scan, ZAP re-executes the SAME browser-auth block. The diagnostic log interleaves the initial replay AND every re-login. `parseZapLoginDiagnostics` is specced without a "which invocation" selector.

**Patch:** Spike-3 fixture corpus must include a multi-replay log (1 success + 2 mid-scan re-logins, one failing). Parser contract: for dry-run, returns the FIRST replay's verdict; for real-scan, ignores re-login events (those go via the `session_loss` envelope per P1 discriminator above).

### Concurrency block still bites iteration `[SOLO skeptic-f8]`

Plan's mitigation (UI "Cancel scan" affordance + v2.1e cap split) leaves the 30-minute-real-scan-blocks-iteration footgun in place for v1. Given P0-3 above confirms the cancel route doesn't exist, the mitigation is currently fictional. The brief's User Story #2 ("iterate quickly") is structurally unmet.

**Patch:** Either lift dry-run jobs out of the per-project cap COUNT NOW (one body-only `queue_scan_job` re-CREATE — same risk as v2.1e but with concrete value); OR increase per-project cap from 1 to 2 specifically for `dast_zap` (simpler one-line diff). Pair with P0-3's cancel-route fix. Decide explicitly.

### Step editor surface too wide for v1 `[SOLO pragmatist-f3]`

9 step actions + CSS/XPath toggle + per-step `timeout_ms` + sort buttons + 'currently testing' amber + failed-step border + stale-result hint + never-tested-save warning. Real-app logins reduce to click/type/click/type/click-submit. XPath escape hatch + per-step timeout + sort are post-v1 niceties.

**Patch (optional, Henry-level scoping call):** v1 ships 4 actions (`click`, `type_username`, `type_password`, `wait`). CSS-only selectors (`selector_kind` stays in schema for forward-compat; validator rejects xpath). Single global `step_timeout_ms` on payload (no per-step). No sort buttons. `type_totp`, `type_custom`, `return`, `escape`, `goto` defer to v2.1e — but this contradicts the locked TOTP scope. Recommend NOT cutting TOTP per Henry's prior "match competitors" steer; instead cut `type_custom` + `return` + `escape` + per-step timeout + sort. Saves ~2-3h.

## P2 — Quality Gaps (compressed)

- **scope-cutter-f1** — M7 CI e2e gate optional (commit harness, run locally; CI integration v2.1e).
- **scope-cutter-f2** — M6.3 SSO smoke deferred to dogfood; formal smoke in v2.1e.
- **scope-cutter-f3** — Replace M6.2 2FA fixture with `otplib` unit test + Juice Shop's built-in 2FA toggle.
- **scope-cutter-f4** — Up/down sort buttons cut.
- **scope-cutter-f5** — `meta?: Record<string,unknown>` is YAGNI; drop.
- **scope-cutter-f6** — `label?: string` defer to v2.1e.
- **scope-cutter-f7** — `sso_origins?: string[]` decide post-Spike-2 (reorder M1 after spike).
- **scope-cutter-f8** — POST /test audit-log row cut (PUT keeps it).
- **scope-cutter-f9** — `runtime_confirmed_via_auth` marker — defer explicitly to v2.1e (NOT just Open Question).
- **scope-cutter-f10** — M6.4 session-loss smoke replaced by telemetry observation post-merge.
- **pragmatist-f4** — Spike-4 folds into M1.1 (not a separate bullet).
- **pragmatist-f5** — Don't refactor `DastScanningTab.tsx`; let RecordedStrategyEditor copy the pattern.
- **pragmatist-f6** — `meta?: Record<string,unknown>` YAGNI (same as scope-cutter-f5).
- **tsa-r2-f4** — Add YAML-level test asserting `failOnError`/job-ordering semantics for pre-flight failure (depends on P0-4 spike outcome).
- **tsa-r2-f5** — Re-run existing `DastScanningTab.tsx` tests post-refactor (or add smoke first if no tests exist).
- **tsa-r2-f6** — Worker-unit test for missing `DAST_CREDENTIAL_KEY` rejection on dry-run.
- **tsa-r2-f7** — Promote session-loss bounded-retry to automated test (or `e2e:dast-recorded-session-loss`).
- **tsa-r2-f8** — Expand YAML snapshot matrix to per-action minimal-emit (9 snapshots) + `requestor`-job assertion.

## P3 — Nits & Opportunities

- **opportunity-scout-r2-f1** — "Last test result" panel using queryable `error_payload.test_result` history (cheap).
- **opportunity-scout-r2-f2** — Cache authenticated ZAP session by `credential_payload_hash` for rapid re-scan iteration (P2 win; reserve parser metadata in v2.1d).
- **opportunity-scout-r2-f3** — `dry_run:true` is now a generic primitive — reserve dispatch shape for form/jwt/cookie Test-login in v2.1e.
- **opportunity-scout-r2-f4** — Spike-3 diagnostic-log corpus as a public artefact post-launch.
- **opportunity-scout-r2-f5** — Audit existing polling sites for `useJobResult` adoption post-merge.
- **opportunity-scout-r2-f6** — `runtime_confirmed_via_auth` marker — move from Open Questions to M3.3 finalize path (one-liner) IF column exists per v2.1c.
- **opportunity-scout-r2-f7** — Emit `dast_login_test.completed` event to `organization_activities` for Aegis context.
- **opportunity-scout-r2-f8** — Reserve `failed_at_step.dom_excerpt?: string` (≤1KB redacted) in M3.1 parser for future Aegis selector-suggest assistant.

## Suggested Plan Amendments (numbered, selective)

**B1 — Global rename `error_details` → `error_payload`** (P0-1). 14 occurrences. **Apply unconditionally.**

**B2 — Add an explicit `kind` discriminator to `error_payload`** (P1 + P0-1 follow-on). Three-variant discriminated union. **Apply unconditionally.**

**B3 — Widen GET `/dast/jobs` SELECT to include `error_payload`** (P0-2). Plus widen `DastJobDTO`. Add route test. **Apply unconditionally.**

**B4 — Either wire `POST /api/projects/:projectId/dast/jobs/:jobId/cancel` + `cancel_scan_job` RPC, OR drop the "Cancel running scan" affordance** (P0-3). Recommend (a) — the cancel endpoint is a pre-existing UX gap of DAST as a whole, not just v2.1d-specific. **Apply unconditionally — decide which option.**

**B5 — Add Spike-5: prove AF YAML pre-flight fail-fast actually works** (P0-4). Before M2.3/M3.3 are authored. **Apply unconditionally.**

**B6 — Rewrite M3.3 with explicit code-shape sketch for the dry-run early-exit** (P0-5). Include `findings_count: 0`, `populateDependencies` NOT called, PDV-mutation NOT called. **Apply unconditionally.**

**B7 — Apply the consolidated P1 patches:** `internalIndexToZapIndex[]` carrier, `scan_timeout_minutes` reconciliation, `startDastMachine` 503 fast-fail, Spike-1 tightened criteria, `DastJobPayloadSchema`, downstream `error_payload`-reader audit, M5.1 `DastScanningTab` regression-test plan, multi-replay parser contract. **Apply unconditionally.**

**B8 — Collapse M0 4 spikes → 2 spikes (~2-3h instead of 4-5h)** (pragmatist-f1). Spike-1+3+5 into one ZAP empirical session; Spike-2 stays separate; Spike-4 folds into M1.1. **Apply unconditionally.**

**B9 — Rephrase v2.1e roadmap to acknowledge `queue_scan_job` body change IS a migration** (skeptic-f4). One-paragraph edit. **Apply unconditionally.**

**B10 — Selective scope cuts** (Henry-level): drop `meta` (YAGNI), drop `label` (defer), drop up/down sort, drop M7 CI gate (keep harness only), defer M6.3 SSO smoke + M6.4 session-loss smoke to dogfood telemetry. Cuts ~3-5h. **Henry decides** — these contradict the "match competitors" steer for SSO; recommend at least taking the `meta` + sort + M7-CI cuts.

**B11 — Cancel-route as a pre-v2.1d chore** (B4 alternative framing): write the cancel route + RPC as a separate `chore/dast-cancel-route` PR that merges BEFORE v2.1d. Removes ~1-2h from v2.1d scope; lets v2.1d depend on the existing surface. **Recommend if you want v2.1d to ship faster.**

**B12 — Selectively absorb opportunities** (`runtime_confirmed_via_auth` one-liner; `useJobResult` global hook; `failed_at_step.dom_excerpt` parser reservation). None blocks /implement.

## Findings by Axis

| Axis | Count | Highest | Personas |
|---|---|---|---|
| column-name / schema mismatch | 2 | P0 | architect (verified) |
| backend-route fiction (cancel) | 1 | P0 | skeptic (verified) |
| AF YAML same-process architecture | 2 | P0 | skeptic, architect (convergent) |
| pipeline control-flow / dry-run | 1 | P0 | skeptic |
| `error_payload` overload / discriminator | 3 | P1 | architect, tsa, skeptic |
| spike scoping / loose criteria | 3 | P1 | skeptic, pragmatist |
| concurrency mitigation | 2 | P1 | skeptic, architect |
| schema / migration honesty | 1 | P1 | skeptic |
| state-passing (internalIndex…) | 2 | P1 | skeptic, architect |
| step editor scope | 1 | P1 | pragmatist |
| timing/timeout reconciliation | 1 | P1 | architect |
| route hardening (startDastMachine) | 1 | P1 | architect |
| test grid gaps (dry-run negative, schema, session-loss, key-missing, snapshots) | 8 | P1-P2 | tsa |
| scope cuts (TOTP/SSO/CI/runbook/sort/meta/label/audit) | 10 | P1-P3 | scope-cutter, pragmatist |
| opportunities (panel, cache, generic primitive, etc.) | 8 | P2-P3 | opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | Vote |
|---|---|---|
| skeptic | 8 | REWORK |
| pragmatist | 6 | REVISE |
| scope-cutter | 10 | REVISE |
| architect | 10 | REWORK |
| test-strategy-auditor | 8 | REVISE |
| opportunity-scout | 8 | READY |
| **Total** | **50 raw, ~42 unique themes** | |

R2 columns omitted (lean mode). Disputed findings: none.

## Recommended Next Step

**Apply B1–B9 unconditionally** (the P0 + P1 patches), **then re-run `/review-plan` once more** to confirm the schema-correctness + same-process verification + cancel-route patches landed cleanly. **B10 + B11 + B12 are Henry-level choices** — talk through them, then apply selectively.

Estimated patch effort: **~1.5h of plan revision**. The cut from v1 → v2 was right; the v2 just needs another tighter pass against the codebase reality (column name, route inventory, AF semantics).

Once verified READY, proceed to `/explain-plan` (optional) then `/implement`.
