# Findings Status Model & Lifecycle — Implementation Plan (v3)

_From `feature-brief-findings-status.md`. **v3 = v2 + both `/review-plan` rounds applied** (`review-findings-status.md`, `review-findings-status-v2.md`). Branch `worktree-findings-experience`. File:line refs from the codebase sweeps._

## Overview
One persisted status model for findings, keyed to a stable `finding_key`, replacing the 3-place auto-triage duplication. **Architecture (validated across two reviews):** the per-finding triage verdict + `finding_key` are computed in **SQL, set-based, at `finalize`** and **backfilled by the migration itself** (so existing rows are correct the instant it applies — no rollout window). SQL is the **single source**; the frontend `autoTriageRow` triage branches and `finding-triage.ts` are deleted in favor of reading the stored column. Trackers are a separate **PR-B**.

## Two decisions locked (from review round 2)
- **D1 — IaC/DAST parity = port predicates into SQL.** The current phase54 SQL is a *lossy mirror* of `autoTriageRow` (it drops `iacRuleInfo`'s per-rule critical logic and the `dastInjectionParam` axis — so a HIGH Terraform finding is Open in the table but hidden in the count today). `compute_auto_ignored()` must **faithfully port `autoTriageRow`'s per-row logic** (incl. `iacRuleInfo` critical-determination + the DAST injected-param axis) so the stored verdict == what the table shows. Worker-compute was rejected: it would break the migration self-backfill and re-open the rollout regression.
- **D2 — `finding_key` is a denormalized HANDLE, not a join/route key.** `sha256(dep_name+osv_id)` is identical across projects, so the status route is **project-scoped** (`:projectId` in the path) and resolves `(project_id, finding_key)` → the active-run row. Carry-forward keeps the **existing per-type JOINs untouched**.

## Codebase Analysis (corrected by review)
**8 finding stores.** Status columns: `status` on PDV/secret/semgrep/dast/iac/container; **`project_malicious_findings` has none** (v3 adds it); `project_reachable_flows` (taint_flow) stays on its existing `flow_signature_hash` suppression (out of v1 unified model).

**Carry-forward TODAY (corrected — the v2 premise was wrong):** the *current* `finalize_extraction` (per `schema.sql`, not just phase19_3) carries forward:
- PDV — ranked `DISTINCT ON (npd.id, opdv.osv_id)` with a version-aware tiebreak (the **Bug-002 fix** — do NOT replace with a flat key-join). `schema.sql:3933-3955`.
- semgrep — `semgrep_fingerprint` → tuple fallback.
- secret — `(detector_type, file_path, redacted_value)`.
- **iac — already carried** by `(scanner, iac_fingerprint)`. `schema.sql:4086-4104`.
- **container — already carried** by `container_fingerprint`. `schema.sql:4106-4123`.
- **DAST — already carried** by `commit_dast_target_run` (phase24a) on its natural key, `status <> 'open'` guard, per-target `dast_run_id` lifecycle.
- **malicious — the ONLY type with no carry-forward**, and `project_malicious_findings` is **never reaped** (no `DELETE` in `reap_old_extractions`).

So the unified status only needs to: **(a) add the new ignore_* columns to the EXISTING carry-forward SET lists** (5 types) — keep their JOINs as-is — and **(b) add net-new carry-forward + reap for malicious** (deferred to PR-B).

**Triage TODAY = a 3-way *divergent* mirror** (the drift to kill): frontend `autoTriageRow()` (uses `iacRuleInfo` from `infra-format.ts`, `dastInjectionParam`), backend `vulnAutoIgnoreReason` (`finding-triage.ts`), and `security_summary_counts` (phase54 — a *lossy* SQL re-impl that drops the IaC per-rule + DAST param axes). `runtime_confirmed_at` (PDV-only column) overrides the verdict. Count-RPC run-scoping is **two mechanisms**: extraction types `extraction_run_id = ANY(p_active_run_ids)`; DAST `dast_run_id` (per-target).

**Other:** existing finding-status writers to reconcile — `teams.ts:2592` (3-type, membership-only), `scanner-findings.ts:125-335` (iac/container ignore + risk-accept, gated **project-level** `checkProjectManagePermission`), `projects.ts:10340` (PDV suppress). `manage_findings` doesn't exist yet. `external.ts` Jira/Linear ticket creation reads `organization_integrations`. Next migration number: **phase55** (`phase54` taken). `schema:dump` = `cd depscanner && npm run schema:dump`.

---

## PR-A — Status Foundation

### Data Model
**Per-run rule:** `finalize` retains 2 runs (active+previous via `reap_old_extractions`). Manual `status` lives on the **active-run row**, carried forward; **all reads/counts/mutations target the active run** (extraction types: `extraction_run_id = active`; DAST: the target's `active_dast_run_id` — NOT a uniform filter).

**`finding_key` (denormalized handle)** = `encode(sha256(normalized natural tuple),'hex')`, computed in SQL by `compute_finding_key()`, set set-based at `finalize`/`commit_dast_target_run` + backfilled in phase55. **It is NOT a carry-forward join key** — it's for tracker/event references + status-endpoint resolution. Inputs (lowercased, null→`''`): PDV `dep_name‖osv_id` · secret `detector_type‖file_path‖redacted_value` · semgrep `COALESCE(fingerprint, rule_id‖file_path‖start_line)` · iac `COALESCE(iac_fingerprint, rule_id‖file_path‖start_line_key)` · container `image_reference`(repo, digest/tag-stripped, 3 ref-shapes handled)`‖COALESCE(osv_id,cve_id, os_package_name‖os_package_ecosystem)` · dast `rule_id‖vulnerability_type‖COALESCE(handler_file_path‖handler_function_name, endpoint_url‖http_method)` · malicious `dep_name‖rule_id‖scanner`.

**`auto_ignored` (+ reason)** = per-row verdict computed in SQL by `compute_auto_ignored()`, which **faithfully ports `autoTriageRow`'s per-row branches** (D1): SCA reachability, IaC `iacRuleInfo` critical-determination (NOT just phase54's 10-rule allowlist), DAST passive-hygiene incl. the injected-param axis, container non-KEV base-image. **Row-level types only** — the container/DAST *grouping* (one row per image / family dedup) stays a count/presentation concern, NOT in the stored column. `runtime_confirmed_at` is **PDV-only** and applied as a **read-time override** (`auto_ignored AND runtime_confirmed_at IS NULL`) in the SCA branch of each reader — surfaced as one shared SQL expression to avoid re-duplication.

### Migrations (split — `CONCURRENTLY` can't share a txn file)
**`phase55_findings_status_foundation.sql`** (one transaction, statements in order):
1. `ADD COLUMN IF NOT EXISTS status` on malicious; `finding_key`, `ignore_reason`/`ignore_note`/`ignored_by`/`ignored_at`, `auto_ignored BOOLEAN NOT NULL DEFAULT false`/`auto_ignore_reason`, and `resolved_at` on all 7 tables. (`first_seen_at`/`first_seen_run_id` optional — restores the "New" badge cheaply now the carry-forward JOIN exists.)
2. `CREATE FUNCTION compute_finding_key()` + `compute_auto_ignored()` (the ported predicates).
3. **Backfill** `finding_key` + `auto_ignored`/`auto_ignore_reason` for ALL existing rows (active+previous) via the helpers (set-based; PDV joins `project_dependencies` for `dep_name`).
4. Legacy → status: `(suppressed OR risk_accepted) → status='ignored'`, **excluding malicious `suppressed_reason LIKE 'allowlist:%'`** (those are auto, run-scoped — not sticky manual ignores); DAST `'closed'→'ignored'`.
5. The simplified `security_summary_counts` `CREATE OR REPLACE` — **LAST statement** (after the backfill, same txn, so the column is populated before the new body is visible).

**`phase55b_findings_status_indexes.sql`** (own file, non-transactional): `DROP INDEX IF EXISTS` then `CREATE INDEX CONCURRENTLY` for `(project_id, finding_key)` + `(project_id, status)` per table.

`backend/database/add_manage_findings_permission.sql` (copy `add_manage_statuses_permission.sql`: owner→true else false) + seed in the new-org default-role creation. Then `schema:dump` + verify columns landed.

### RPC changes
- **`finalize_extraction`:** set `finding_key` + `auto_ignored` set-based for the new run (helpers). **Do NOT touch the existing carry-forward JOINs** (PDV ranked / semgrep / secret / iac / container) — only **add the new `ignore_reason/ignore_note/ignored_by/ignored_at` columns to their existing SET lists**. (Malicious carry-forward + its reap → PR-B.)
- **`commit_dast_target_run`:** set `finding_key`/`auto_ignored`; add `ignore_*` to its existing `status` carry-forward SET (keep `status <> 'open'` guard).
- **`security_summary_counts`:** **delete** the inline PDV reachability predicates (lines 90-113) and read the stored `auto_ignored` + the PDV-scoped runtime override; **keep per-type run-scoping** (extraction vs DAST per-target) and the container/DAST **grouping** (residual — out of the v1 zero-drift guarantee).

### API
| Method | Route | Auth | Permission | Notes |
|---|---|---|---|---|
| PATCH | `/api/organizations/:id/projects/:projectId/findings/:type/:findingKey/status` | JWT | `manage_findings` | **`:projectId` added (D2)** → resolve `(project_id, finding_key)` to the **active-run row**; 404 if no active row (resolved/gone) — never write the previous-run row. Writes a `finding_status_events` row. |
| GET (extended) | org/team/project findings reads | JWT | view | add `status`/`auto_ignored`/`auto_ignore_reason`; apply the PDV runtime override consistently |

New `checkOrgManageFindingsPermission()` in `project-access.ts`. **Enumerate + reconcile ALL existing status writers** in this PR (`teams.ts:2592`, `scanner-findings.ts` iac/container ignore+risk-accept, `projects.ts:10340`) onto the unified `status` + `manage_findings` — note this moves iac/container ignore from a **project-level** permission to an org one; confirm intended. Close the inherited cross-org IDOR.

### Frontend
- `FindingStatusCell` reads stored `status`/`auto_ignored`/`auto_ignore_reason` (+ PDV runtime override). **Persist + show `resolved`** (finalize already diffs runs to detect "gone" — write `status='resolved'`+`resolved_at`; add a **Resolved** chip to Open/Ignored/All). "New" badge: optional via `first_seen_*`, else all-open reads "Open".
- Inline **Ignore/Un-ignore** (single action; overflow menu + tracker chip → PR-B) → `IgnoreReasonDialog` (shadcn, reason+note, green confirm). Gated on `manage_findings`. Optimistic + refetch.
- **Cleanup:** delete `autoTriageRow`'s per-row triage branches + `finding-triage.ts`; Aegis `issues.ts` reads the stored column. **IaC caveat:** `iacRuleInfo` stays in the frontend to drive *grouping* (`iac_group` collapse) unless a stored `is_hardening` flag is added — the grouping consumes the verdict, so it's not fully deletable.
- **Landing:** update `heroDemo.ts` mock findings to carry the new fields (else the hero pills blank); optionally surface `auto_ignore_reason` as "auto-hidden: unreachable". `/verify` checks the pills render. (Don't edit other `components/landing/*`.)

### Implementation Tasks (PR-A)
1. **(M) phase55 + phase55b + `add_manage_findings_permission` + new-org seed + `schema:dump`.**
2. **(S→M) Golden-master freeze FIRST** — checked-in fixture from CURRENT `autoTriageRow`+`vulnAutoIgnoreReason`, **split by provenance** (TS-frozen for SCA/container; for IaC/DAST capture the cases where TS and phase54 SQL *disagree* and pin the TS behavior as canonical). Gates task 1's helper bodies + task 4.
3. **(S) finalize/commit_dast:** add `ignore_*` to existing carry-forward SET lists; set finding_key/auto_ignored. (No JOIN changes.)
4. **(M) Simplify `security_summary_counts`** — read stored columns; PDV override; per-type run-scoping; keep grouping.
5a. **(M) Status endpoint** (`:projectId`, 8 types, finding_key resolution, `manage_findings`, events) + helper + migrate frontend caller. 5b. **(S) Repoint legacy writers** (`projects.ts`, `scanner-findings.ts`) — load-bearing (or backfill goes stale).
6. **(M) Frontend** status cell (incl. Resolved) + Open/Ignored/All + inline Ignore + dialog.
7. **(S) Cleanup + heroDemo.**
8. **(M) Tests + `/criticalreview` + merge.**

### Testing
- **Golden-master** (task 2): SQL `compute_auto_ignored` byte-equal to the frozen fixture; **must include the IaC generic-severity + DAST two-param cases** so the lossy-mirror divergence is caught before deletion.
- **Backfill correctness — dedicated harness** (NOT `finalize-extraction.test.ts`, which boots DDL-only `schema.sql`): exec the raw `phase55.sql` against a **seeded pre-phase55 PGLite** DB (strip `CONCURRENTLY`); assert per-row `(status, ignore_*, finding_key, auto_ignored)` incl. the `allowlist:%` exclusion + idempotency.
- **Parity:** RPC output set == the stored-column Open set over active-run fixtures **including grouped container/DAST** + a `auto_ignored=true, runtime_confirmed_at set` row (override exercised) + a previous-run duplicate (no double-count).
- **Override parity** across all readers (count RPC, frontend filter, Aegis `issues.ts`, org/team reads). **Aegis cutover** equivalence test before deleting `finding-triage.ts`.
- **Carry-forward:** the 5 already-carrying types keep `ignore_*` across a simulated rescan; `auto_ignored` recomputed-not-carried (auto-reopen).
- **Endpoint:** `(project_id, finding_key)` resolves to the active-run row only (404 if gone); cross-org IDOR; member-without-`manage_findings` → 403; out-of-enum → 400.
- **Perf:** structural index presence (drop PGLite timing).

### Rollout Order
1. Apply **phase55** (self-backfills existing rows; RPC cutover is the last txn statement) **then phase55b** (CONCURRENTLY). `schema:dump`. 2. **Hard gate: phase55 applied before the backend deploy** (new writers reference new columns). 3. Backend deploy (endpoint + repointed writers). 4. Worker: no new triage code (finalize SQL); refresh `FLY_DEPSCANNER_IMAGE` pin if the image changed. No fleet rescan needed (backfill ran). Legacy columns retained (forward-only; backend rollback safe — legacy→status didn't clear them).

### Success Criteria
- Triage has **one source** (`compute_auto_ignored`, ported faithfully); `autoTriageRow` per-row branches + `finding-triage.ts` deleted; the RPC reads the column.
- **Count == table Open, zero drift — for row-level types** (SCA/secret/semgrep/IaC/DAST-passive/container-non-KEV), proven by the parity test. Container/DAST **grouping** is explicitly out of the v1 guarantee.
- Ignore (with reason) survives rescans for the 5 already-carrying types; un-ignore restores. `resolved` persisted + visible.
- Auto-ignored → reachable (or DAST-confirmed) reappears in Open with no manual action.
- No count spike / dropped ignores on deploy.

---

## PR-B — Trackers + the deferred carry-forward
- **Malicious:** add `status` carry-forward + **add `DELETE FROM project_malicious_findings` to `reap_old_extractions`** (so the 2-run invariant holds); **resolve the allowlist desync** (decide: manual ignore writes the `suppressed` path so `recompute_dependency_is_malicious` fires, OR status-only + the count branch reads `status` + a recompute on status change). Blocking for malicious manual-ignore.
- **Trackers:** prereq — verify `integrations.ts` Jira/Linear cred scope (`external.ts` reads `organization_integrations`). `finding_tracker_links` + reader-facing `finding_status_events` indexes; both `REFERENCES organizations/projects ON DELETE CASCADE`. Extract Jira/Linear REST bodies from the `external.ts` tool closures into plain helpers; add `github.createIssue`. Overflow actions menu + `TrackerProviderPicker` + `TrackerChip` + the **"Fix with Aegis"** item (gated `trigger_fix`). Tracker failure-mode tests.
- **Deferred to v1.1:** finding→ticket auto-close; fold taint_flow into the unified model; `finding_status_events` metrics endpoint (MTTR) + an Aegis `setFindingStatus` tool.

## Risks & Open Questions
- **IaC triage vs grouping coupling** — `iacRuleInfo` stays frontend-side for grouping unless a stored `is_hardening` flag is added.
- **`finding_status_events` create-location** — created in PR-A (write-only); ensure the migration creates it before the endpoint writes it. **Drop "events logged" from PR-A success criteria** (no v1 reader) — assert `ignored_by/ignored_at` instead.
- **PDV version-blindness + container image-logical grain** — ignores are dep/image-logical, not version/digest-specific (correct for `accepted_risk`; stated).
- Keep legacy `suppressed`/`risk_accepted` until a retirement PR (enumerate readers/writers first).

## Recommended Next Step
`/implement` PR-A, **test-first**, starting task 1 (migration) + task 2 (golden-master freeze, incl. the IaC/DAST divergence cases). The remaining precision is what the golden-master + parity + dedicated-backfill tests catch as the SQL is written.
