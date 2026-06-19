# Plan Review — findings-status (v2, round 2)
Verdict: **REVISE** (round 2 — prior fundamental P0s CLOSED; new SQL-precision/premise cluster, mostly *simplifying*)
Plan reviewed: `.cursor/plans/findings-status.plan.md` (v2)
Mode: lean (8 personas), debate off. Vote synthesized from findings.
Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, migration-safety-auditor

## Summary
The v2 SQL-compute re-architecture **closed the prior fundamental P0 clusters** (rollout regression, container GENERATED-key instability, mutation fan-out, FK cascades — all confirmed resolved by their original raisers). The **architecture is validated** — nobody challenged SQL-compute / self-backfill / per-run status / stored `auto_ignored`. But the v2 plan's Data Model + RPC *prose* over-generalized ("switch ALL types to finding_key", "uniform active-run filter", "override in every reader") and rests on a **wrong factual premise**, producing a new P0 cluster. The good news: **most corrections make the work smaller** (don't touch already-working carry-forward; `finding_key` is a handle; the override is PDV-only). **Recommendation: apply the focused v3 corrections below, then build test-first — we're at diminishing returns on further review rounds; the remaining precision is what the test plan + writing the real SQL will catch.**

## Prior P0 clusters — CLOSED (confirmed)
- **Rollout/backfill regression** → closed by the self-backfill (migration-safety: "genuinely closes the prior worker/rescan P0… carry-forward no-op fixed… reversibility handled").
- **Container GENERATED-key instability** → closed (sources stable columns now).
- **Mutation fan-out / per-run double-count** → closed by "status on active-run row, reads filter active run" (modulo the project-scoping bug below).
- **New-table FK cascades** → closed (matches existing convention).
- **"New" badge cut** → safe (pure render label, no stored source).

## New P0 cluster — v2 over-generalized the SQL (most fixes SIMPLIFY)

### 1. The SQL is a *lossy mirror* of `autoTriageRow`, not a faithful source `[skeptic-f1]`
phase54 **admits in its own comments** it doesn't port `iacRuleInfo`'s per-rule score (L117) or the DAST injected-param axis (L182-3). So a HIGH Terraform finding is **Open in the TS table but auto-hidden in SQL today** — they already diverge. "Relocate the SQL = parity" is false; relocating freezes the divergence into the stored column. **DECISION FORK (the crux of "one source"):** (a) port `K8S_RULES` + `dastInjectionParam` into the SQL helper for true parity, (b) compute open-state at *scan time in the worker* (what the migration headers themselves recommend), or (c) accept SQL-canonical and change what the table shows. The golden-master **must** include the IaC-generic-severity-fallback + DAST-two-params-one-handler cases so the divergence is caught *before* `autoTriageRow` is deleted.

### 2. WRONG PREMISE: iac/container are ALREADY carried forward `[skeptic-f2, contradicts the plan + an earlier scout]`
`schema.sql:4086-4123` already carries `project_iac_findings` (by `scanner, iac_fingerprint`) and `project_container_findings` (by `container_fingerprint`) status/suppressed/risk_accepted across rescans. **Only `project_malicious_findings` genuinely lacks carry-forward.** So the plan's "extend carry-forward to iac/container/malicious + switch ALL types' JOIN to finding_key" is wrong — it would **replace working fingerprint joins with a different identity** (regression). **Fix (shrinks scope): `finding_key` is a denormalized HANDLE only; keep ALL existing per-type carry-forward joins untouched; ADD carry-forward for malicious ONLY.**

### 3. PDV carry-forward can't use a flat `finding_key` join `[architect-f1, skeptic-f3, data-model]`
PDV uses a ranked `DISTINCT ON (npd.id, opdv.osv_id)` with a version-aware tiebreak (the documented **Bug-002 fix**) precisely because `(dep_name, osv_id)` is non-unique in a monorepo. A flat key-equality join resurrects Bug-002 / fans out. **Fix: keep the existing PDV join; `finding_key` is denormalized-only** (folds into #2).

### 4. `runtime_confirmed_at` override is PDV-ONLY `[architect-f3]`
The column exists only on `project_dependency_vulnerabilities`; a generic `AND runtime_confirmed_at IS NULL` over the other 6 tables is a **column-does-not-exist error**. **Fix: scope the override to the SCA branch.** Consider one shared `is_effectively_auto_ignored` SQL expression so it isn't re-duplicated across the count RPC + frontend + Aegis `[skeptic-f5]`.

### 5. The "active-run filter" is TWO mechanisms `[architect-f4, data-model-f1]`
Extraction types filter `extraction_run_id = ANY(p_active_run_ids)`; **DAST** filters `dast_run_id` (per-target, via a `created_at DESC` subquery today — ideally the target's `active_dast_run_id`). A uniform `extraction_run_id = active_run` is wrong for DAST. **Fix: keep per-type run-scoping; state DAST is per-target, not org-active-run.**

### 6. `finding_key` is NOT project-unique on an ORG-scoped route `[skeptic-f4]` — correctness/security
`PATCH /organizations/:id/findings/:type/:findingKey/status` has no `:projectId`, but `sha256(dep_name+osv_id)` for e.g. lodash CVE-2021-23337 is **identical across every project**. Resolving by `finding_key` alone mutates the wrong project's row (or many). **Fix: add `:projectId` to the route so `(project_id, finding_key)` resolves uniquely; close the inherited cross-org IDOR on the existing endpoint.**

### 7. `project_malicious_findings` is NEVER reaped `[data-model-f2]`
The "finalize keeps 2 runs → 2 rows per finding_key" invariant is false for malicious — it accumulates a row per run forever (no `DELETE FROM project_malicious_findings` in any reap function). **Fix: add malicious to `reap_old_extractions` in phase55 before adding its carry-forward.**

### 8. container/DAST counts are GROUP-level, can't source a per-row `auto_ignored` `[skeptic-f6, architect-f8]`
phase54 collapses non-KEV container to one synthetic row per image (`GROUP BY image_reference`) and DAST via `DISTINCT ON (handler, fam)`. A per-row stored boolean has no "group representative" notion. **Fix: `compute_auto_ignored` produces a per-row verdict ONLY for row-level predicates (SCA reachability, IaC critical-rule, DAST passive, container non-KEV); the grouping stays a count/presentation concern (already the plan's v2 group_key deferral) — make the Success Criteria say the stored column is the source for row-level types, not all types.**

## P1/P2 — also fix
- **malicious × allowlist desync** `[architect-f7, data-model-f8, skeptic-f9]` (blocking, not a deferred risk): a manual `status='ignored'` won't re-run `recompute_dependency_is_malicious`, so `dependencies.is_malicious` stays true; the count branch filters `suppressed`/`risk_accepted` not `status`; the legacy→status backfill would wrongly sweep auto, run-scoped `allowlist:%` suppressions into sticky manual ignore. **Decide: manual ignore writes the `suppressed` path (re-runs recompute) vs status-only + exclude `allowlist:%` from the backfill + count branch reads status.**
- **Migration file structure** `[migration-safety-f1, f3]`: split into `phase55` (txn: columns + helpers + backfill + legacy→status + the simplified `security_summary_counts` `CREATE OR REPLACE` as the LAST statement) and **`phase55b`** (CONCURRENTLY indexes ONLY, own file, `DROP INDEX IF EXISTS` first per the invalid-index trap). The RPC cutover is migration-channel, not "backend deploy."
- **Testing** `[test-strategy-f1, f2, f4, f5]`: golden-master is itself TS→SQL — split by provenance + include the IaC/DAST divergence cases; the **self-backfill needs a dedicated harness** that execs the raw `phase55.sql` against a seeded *pre-phase55* PGLite DB (the `finalize-extraction.test.ts` harness boots `schema.sql` = DDL-only, so it can't test the backfill); test the `runtime_confirmed_at` override across all 4 readers; gate the Aegis `issues.ts` cutover with an equivalence test.
- **IaC triage vs grouping not separable** `[architect-f5]`: the frontend `iacRuleInfo` predicate still drives grouping, so it can't be fully deleted unless a stored `is_hardening` flag feeds the grouping.
- **Writer enumeration incomplete** `[architect-f6]`: `scanner-findings.ts` iac/container ignore endpoints already write `status` gated on **project-level** `checkProjectManagePermission` (not org `manage_findings`), and IaC has a separate `risk_accepted` vocabulary — enumerate ALL writers + pick one permission model.
- **Backend-before-migration window** `[migration-safety-f6]`: make phase55 a hard prereq gate before the backend deploy (new writers reference new columns).

## Scope refinements (consensus) `[pragmatist, scope-cutter]`
- **Defer DAST + malicious carry-forward to PR-B** — they carry the open-question risk (allowlist desync, per-target DAST run); count-drift stays global (read-side). PR-A carry-forward = PDV/secret/semgrep + the already-working iac/container.
- Fix the **events-table create-location contradiction** (line 60 vs 121); **drop "events logged" from PR-A success criteria** + the event-row assertions (no v1 reader); keep the cheap INSERT best-effort.
- Drop **`ignore_expires_at`** and the **"reserve Fix-with-Aegis slot"** from PR-A (no v1 consumer / no menu yet).
- Split task 5 (endpoint generalization vs legacy-writer repoint) — but keep the **legacy-writer repoint load-bearing in PR-A** (or "ignore survives rescan" breaks day 1).

## Opportunities (P3) `[opportunity-scout]`
- **Persist `status='resolved'`** — `finalize` already diffs runs to detect "gone"; writing it gives the events table a v1 reader + a Resolved filter chip + MTTR data nearly free. (The plan currently describes `resolved` but never writes it.)
- **`first_seen` is now cheap** (the carry-forward JOIN exists) → restore "New" + finding-age.
- Surface `auto_ignore_reason` in `heroDemo` ("auto-hidden: unreachable") as a reachability-moat trust signal.

## Verdict & Recommended Next Step
**REVISE (round 2).** The architecture is sound and the fundamental P0s are closed; this round is **SQL precision + one wrong premise**, and the corrections mostly *shrink* the work (don't touch working iac/container carry-forward; `finding_key` = handle; override = PDV-only; carry-forward = malicious-only in PR-A). **Apply the v3 corrections, then go to `/implement` — test-first.** A third full review round would surface a fourth layer of finer detail at diminishing returns; the remaining precision is exactly what the golden-master + parity + dedicated-backfill tests are designed to catch as the SQL gets written. The two items that genuinely need a *decision* before coding: **(#1) the IaC/DAST parity approach** (port to SQL vs worker-compute vs SQL-canonical) and **(#6) adding `:projectId` to the status route.**
