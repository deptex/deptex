# Plan Review — findings-status
Verdict: **REVISE** (heavy)
Plan reviewed: `.cursor/plans/findings-status.plan.md`
Brief: `.cursor/plans/feature-brief-findings-status.md`
Mode: lean (8 personas), debate off. Phase-4 vote synthesized from Round-1 findings (not re-spawned) — the verdict is overdetermined by the P0 set.
Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, data-model-auditor, migration-safety-auditor
Findings: **9 P0** / 18 P1 / 11 P2 / 8 P3 (author-rated; P0s are all patchable-in-place — see verdict note)

## Summary
The **brief's product design is validated** — no persona challenged status={open,ignored,resolved} + stored `auto_ignored` + `finding_key` + tracker links + `manage_findings` + auto-reopen + finding→ticket auto-close. Every P0 is an **implementation-mechanics gap in the plan**, not a design flaw, so this is a *heavy REVISE* (apply the patch set + re-scope), **not** a REWORK (the brief stands). But the plan is **not buildable as written**: it would cause a production regression (count pills spike + manual ignores dropped on deploy), it under-reckons with the per-run row cardinality, it has two divergent `finding_key` definitions (TS hash vs SQL joins), and the headline "zero drift" + "delete the dup" claims are partly unachievable as specified. Do **not** proceed to `/implement` until the amendments below are folded in.

## Vote Tally (synthesized from findings)
| Persona | Vote | Top concern |
|---|---|---|
| skeptic | REVISE | `auto_ignored` depends on cross-pipeline `runtime_confirmed_at` (P0) |
| migration-safety-auditor | REVISE | RPC reads un-backfilled `auto_ignored`/`finding_key` → prod regression (P0×3) |
| data-model-auditor | REVISE | `(project_id, finding_key)` non-unique → double-count + mutation fan-out (P0×2) |
| architect | REVISE | TS-hash `finding_key` vs SQL raw-column joins diverge (P0) |
| test-strategy-auditor | REVISE | parity test is cross-language; no golden-master before deleting `autoTriageRow` (P0×2) |
| pragmatist | REVISE | split trackers into own PR; the tracker arc has an unresolved cred blocker |
| scope-cutter | REVISE | tracker arc + events table + taint_flow are riders on the must-have core |
| opportunity-scout | READY+ | non-blocking; add "Fix with Aegis" + metrics endpoint |

## P0 — Fundamental Concerns (all patchable; they block /implement, not the design)

### Cluster A — Per-run row cardinality & finding_key identity `[CONVERGENT: data-model, architect, skeptic]`
The plan never reckons with the fact that `finalize` retains **two runs** (active + previous, via `reap_old_extractions`), so a recurring finding has **2 rows** sharing one `finding_key`.
- **data-model-f1 (P0, double-count):** the simplified count RPC dropped the active-run filter; counting `status='open' AND auto_ignored=false` over both retained runs double-counts every recurring finding. **Patch:** every read/count MUST filter `extraction_run_id = projects.active_extraction_run_id` (DAST: active `dast_run_id`); the parity test must seed a previous-run duplicate.
- **data-model-f2 (P0, mutation fan-out):** a status mutation keyed by `finding_key` (no run) must pick ONE rule — write the active-run row only (carried forward) vs fan out to all retained rows — and the endpoint + backfill + carry-forward must all obey it. **Patch:** decide "status lives on the active-run row; finalize carries it forward; reads filter active run," and state it once.
- **architect-f4 (P0, identity divergence):** `finding_key` is a **TS hash in the worker**, but `finalize`'s carry-forward JOINs match on **raw natural columns** (PDV `name`+`osv_id`, semgrep fingerprint, secret `redacted_value`). Two identity definitions that silently diverge if TS normalization ≠ SQL. **Patch:** compute `finding_key` in **one** place — prefer a SQL expression/generated column so finalize's JOINs and the stored key are identical; if TS stays, rewrite finalize JOINs to use `finding_key` for all types AND add a PGLite test asserting TS-hash == SQL-recomputed-key over the dogfood corpus.
- **architect-f7 (P2→ folded here): `finding_key` must be a hash digest** — the Data Model "source" column lists raw concatenations of values containing `/` and `:` (`image_reference`, `endpoint_url`), which can't be a URL path segment. State it's a sha256 hex of the normalized tuple + the normalization spec.
- **data-model-f3 (P1, container instability):** container `finding_key` pulls in `vulnerability_id`, a **GENERATED** column that falls back to `md5(image_digest||…)` when there's no CVE → rehashes on every base-image digest bump → ignore orphaned. **Patch:** build container key from stable columns directly (`image_reference` repo + `COALESCE(osv_id,cve_id)` else `os_package_name`+ecosystem), never `vulnerability_id`.

### Cluster B — Rollout / backfill safety `[CONVERGENT: migration-safety, skeptic]`
- **migration-safety-f1 (P0):** the simplified RPC reads `auto_ignored` (DEFAULT false) on existing rows until a rescan, so previously auto-hidden findings (unreachable SCA, base-image, passive DAST, IaC hardening) **all un-hide → count pills spike on every project** between migration-apply and per-project rescan (different deploy channels). **Patch:** keep the phase54 SQL triage as a **fallback** when the row has no stored verdict (`finding_key IS NULL` / not-yet-triaged), OR backfill `auto_ignored` in phase55 by porting the existing logic, OR gate the RPC cutover behind the worker deploy. (= skeptic-f9.)
- **migration-safety-f2 (P0):** finalize carry-forward by `finding_key` **no-ops on the first post-deploy scan** because prior-run rows have `finding_key=NULL` → every manual ignore set before the deploy is dropped. **Patch:** backfill `finding_key` for current active-run rows, OR keep the existing natural-key JOIN as the first-scan fallback; document carry-forward is correct from the *second* scan on.
- **migration-safety-f3 (P0):** there is **no written rollout runbook** for the migration↔worker↔backend (three independent release channels); wrong order produces f1/f2. **Patch:** add a "Rollout Order" section: (1) worker first (or ship the RPC change in fallback form), (2) phase55 + perm migration + schema:dump, (3) trigger a fleet rescan or accept+state a transition window, (4) backend reading the simplified RPC last. Name who triggers the rescan.

### Cluster C — `auto_ignored` depends on a cross-pipeline field `[CONVERGENT: skeptic-f1, architect-f2]`
PDV `auto_ignored` short-circuits on `runtime_confirmed_at`, which is written by the **DAST pipeline** (`commit_dast_target_run`, async, after extraction), NOT the extraction reachability step the plan pins it to. Freezing `auto_ignored` at `reachability.ts` time will **wrongly re-auto-ignore a DAST-confirmed CVE** until a full re-extraction — and contradicts Locked Scope #2 ("recomputed every scan"). **Patch:** either (a) the DAST confirm RPC also clears `auto_ignored` on the matching PDV, or (b) keep `runtime_confirmed_at` as a read-time override in the count RPC/reads (`auto_ignored AND runtime_confirmed_at IS NULL`) rather than a pure frozen boolean. State which; "recomputed every scan" is false for the DAST input.

### Cluster F — Testing the headline claims `[test-strategy]`
- **test-strategy-f1 (P0):** "count pills == table Open count" is a **cross-language** equivalence — the table's Open set is filtered in TypeScript (`autoTriageRow` + `depscore-bands.ts`), the count is the SQL RPC. A PGLite-only test exercises only the SQL half and **can't prove the parity that is the whole point**. **Patch:** make the TS Open-filter a single shared function the table AND the test import; assert equal `finding_key` **sets**, not just totals, over shared fixtures including grouped container/DAST rows.
- **test-strategy-f2 (P0):** task 12 deletes `autoTriageRow` with **no captured golden-master first**; the one existing golden test covers only 3/8 types and no `auto_ignore_reason`. **Patch:** add a task BEFORE the worker port — freeze a checked-in fixture `{inputs → (auto_ignored, auto_ignore_reason)}` from the CURRENT `autoTriageRow`+`vulnAutoIgnoreReason` across all 8 types + every reason; assert `computeAutoIgnored` byte-equal; only then is deletion safe.

## P1 — High-Priority Gaps

- **"Delete the 3-place dup" needs a shared module (architect-f1):** `computeAutoIgnored` must replicate `iacRuleInfo()` (`frontend/.../infra-format.ts`), DAST payload checks, container `is_kev` — the worker can't import frontend modules, so porting creates a **4th copy**. **Patch:** extract the per-type triage predicates into one dependency-free shared module consumed by frontend + backend `finding-triage.ts` + depscanner; make it task 1.5.
- **"Zero drift" overstated — grouping stays dual-implemented `[CONVERGENT: skeptic-f7, pragmatist-f6, data-model-f8, architect-f5]`:** container (`GROUP BY image_reference`) + DAST (`DISTINCT ON (handler,fam)`) collapse rows in BOTH the RPC and the frontend row model — the same drift class the feature exists to kill, surviving in the two noisiest types. **Patch:** either materialize a stored `group_key` + `is_group_representative` at scan time so both sides count the same set, OR explicitly scope the "zero drift" Success Criterion to ungrouped types in v1 and flag container/DAST grouping as known-residual. Don't claim global zero-drift.
- **Endpoint generalization breaks callers (architect-f6):** the existing `teams.ts:2592` status endpoint takes `:findingId` (row UUID), 3 types, **membership-only**; the plan reinterprets the 4th segment as `:findingKey` AND tightens to `manage_findings`. Path-identical routes shadow; in-place edit breaks every current caller. **Patch:** grep + migrate the frontend call sites in the same task; decide `:findingId`→server-side-key-lookup vs `:findingKey`+update-all-callers; call out the membership→`manage_findings` tightening for read-only members mid-deploy.
- **Reconcile with existing mechanisms (don't reinvent):**
  - **DAST carry-forward already exists** (architect-f3): `commit_dast_target_run` (phase24a) already carries `status` forward on the exact natural key the plan proposes — extend that UPDATE to also carry `ignore_*` (keep its `status <> 'open'` guard); use `finding_key` for DAST only as a denormalized join column, not the carry-forward key.
  - **iac/container** (data-model-f6): `phase30_iac_container_carryforward_fix.sql` + `phase45` already touch these tables + have fingerprint indexes — audit them before the finalize rewrite so the new `(project_id, finding_key)` index doesn't duplicate `idx_piacf_fingerprint`/`idx_pcf_fingerprint`, and confirm exactly which columns carry today.
  - **malicious** (architect-f8): inserted by `insert_malicious_findings_with_recompute` with its own `apply_malicious_allowlist`/`recompute_dependency_is_malicious` denorm + a `suppressed`/`'allowlist:…'` vocabulary. Define how `status='ignored'` maps to allowlist-suppression and whether a manual ignore must re-run the `is_malicious` recompute.
  - **Jira/Linear creds `[CONVERGENT: pragmatist-f2, skeptic-f3, scope-cutter-f2, architect-f10]`:** `external.ts` create*Ticket are Aegis **tool closures** (return JSON strings, gated on `manage_integrations`) reading **`organization_integrations`** — but the plan says Jira/Linear OAuth is **`user_integrations`**-scoped. So the "reuse" reads the wrong table, the v1 *primary* providers may have no org creds, and the internal auto-close hook has **no user context** to fall back on. **Patch:** resolve the cred-scope BEFORE tasks 7-8 (it's a blocker, not a deferred risk); extract plain async helpers taking an explicit creds object; verify where `integrations.ts` actually writes Jira/Linear tokens.
- **Phasing — split into two PRs `[CONVERGENT: pragmatist-f1, scope-cutter-f1]`:** the tracker arc (create/list/delete + `github.createIssue` + auto-close + picker/chip + `finding_tracker_links`) is orthogonal to the core drift-kill and carries the unresolved cred blocker. **Patch:** PR-A = status foundation (tasks 1-6, 9, 10, 12, 13); PR-B = trackers (7, 8, 11). Ship PR-A first; it delivers every Success Criterion except the tracker line.
- **Cut finding→ticket auto-close from v1 `[CONVERGENT: pragmatist-f5, scope-cutter-f3]`:** it's 3 distinct provider APIs (Jira transition-id, Linear workflow-state, GitHub close) + a resolve-time hook; the value (create+chip) ships without it. **Patch:** defer auto-close to the tracker fast-follow.
- **Test coverage the strategy is silent on (test-strategy-f3–f7):** name `depscanner/test/finalize-extraction.test.ts` as the carry-forward harness + one scenario per newly-carried type (iac/container/malicious) + a separate DAST `commit_dast_target_run` scenario; add the auto-reopen **matrix** (manual-sticky vs auto-recompute collision on one `finding_key`); add a **backfill-correctness** PGLite test (each pre-state vocabulary + idempotency); add **cross-org IDOR + malformed-input** tests on the new endpoints (the repo has a history of finding-endpoint IDORs).

## P2 — Quality Gaps
- **Permanent ignore = stale-suppression accumulation (skeptic-f4):** every cited incumbent time-boxes; cheap hedge = add a nullable `ignore_expires_at` column now (unused in v1 UI) so v2 snooze is UI-only, not a migration.
- **`finding_key` version-blindness for PDV (skeptic-f5):** `dep_name+osv_id` (matches finalize) means an ignore sticks across version bumps — correct for `accepted_risk`, wrong for a version-specific `false_positive`. State the tradeoff; no code change.
- **"New" badge has no stored source (skeptic-f6):** no `first_seen` column exists or is added → the badge is unimplementable from the schema once render-time logic is removed. Add `first_seen_run_id`/`first_seen_at` (carried forward) or cut the badge from v1.
- **taint_flow dual suppression model `[CONVERGENT: skeptic-f8, scope-cutter-f4, data-model-f7, architect-f9]`:** `project_reachable_flows` has no `organization_id`, a nullable `flow_signature_hash`, and a *working* `project_reachable_flow_suppressions` table the count RPC already consults. Make the "pick one source of truth" a **blocking decision**, not a risk — recommended: leave taint_flow on its existing per-project hash suppression for v1 (cut it from the unified model), enumerate the migration as a task if folding it in.
- **events table has no v1 reader `[CONVERGENT: pragmatist-f4, scope-cutter-f5]`:** keep the cheap INSERT but don't gate the endpoint's test matrix on it; the per-row `ignored_by/ignored_at` already record "who set the current state." Don't list "events logged" as a v1 Success Criterion with no surface.
- **`auto_ignore_reason` vocabulary drift (data-model-f4):** add a CHECK/enum or document it's presentation-only; the parity test must assert reason strings, not just the boolean.
- **New tables need FK cascades (data-model-f5):** `finding_tracker_links`/`finding_status_events` should `REFERENCES projects(id) ON DELETE CASCADE` (can't FK the finding row — `finding_key` isn't unique) or a project delete orphans them.
- **malicious backfill correctness (migration-safety-f6) + schema:dump on DO-block DDL (migration-safety-f8):** verify the dynamic `DO/format()` migration round-trips through PGLite's `dump-schema.ts` (fall back to explicit per-table ALTERs if not); confirm malicious has no disposition signal beyond `suppressed`/`risk_accepted`.
- **Index lock time (migration-safety-f4):** use `CREATE INDEX CONCURRENTLY` (outside a txn) + `lock_timeout`; confirm backfill UPDATE row counts are small.
- **Legacy-column retirement (migration-safety-f5, pragmatist-f8):** repoint ALL existing suppress/risk-accept/closed writers (`projects.ts:10340`, `scanner-findings.ts:125-335`) to the unified status in the SAME PR, or the backfill goes stale day 1; enumerate readers before the follow-up drop.
- **Tracker failure modes untested (test-strategy-f9):** add tests for create-5xx (no link row, finding unchanged), auto-close against a deleted/closed ticket (best-effort, doesn't abort finalize), and not-connected provider (clean 4xx).

## P3 — Nits & Opportunities
- **`manage_findings` default grant undecided (skeptic-f10):** the copied pattern silently resolves to owner-only; confirm members can't triage by default is intended.
- **Reuse `manage_statuses`? (scope-cutter-f6):** surface why the existing status permission is insufficient before minting a new key.
- **Confirm no Resolved/history UI in v1 (scope-cutter-f7).** DAST carry-forward divergence — flag not cut (scope-cutter-f8). Perf assertion → structural index check, not PGLite timing (test-strategy-f10).
- **Opportunities (opportunity-scout):**
  - **"Fix with Aegis" in `FindingActionsMenu`** (above "Create issue") — the moat; putting "send to Jira" there but not "send to Aegis" inverts the value prop. Reserve the slot at minimum.
  - **Metrics endpoint off `finding_status_events`** (weekly opened/resolved/median-time-to-resolve) — gives the events table a v1 reader + an exec artifact every incumbent ships.
  - **Update `frontend/src/components/landing/heroDemo.ts`** mock findings to carry the new `status/auto_ignored/finding_key` fields — deleting `autoTriageRow` could blank the landing hero's pills; turns a regression risk into "the marketing page is backed by the real status model." Add to the /verify checklist.
  - **Aegis write path:** once the status endpoint exists, a `setFindingStatus` Aegis tool (gated `manage_findings` + the existing approval flow) lets Aegis triage noise itself — the highest-leverage use of the foundation. Keep the endpoint contract `finding_key`+`type`-based so it's Aegis-friendly.

## Suggested Plan Amendments (apply before /implement)
1. **Rewrite the Data Model section** around the per-run model: `finding_key` is a sha256 hex of a normalized natural tuple computed in **SQL** (or with a TS↔SQL parity test); status lives on the **active-run row**, carried forward, reads filter the active run; container key avoids `vulnerability_id`; add `first_seen_*` (if keeping the New badge) and a nullable `ignore_expires_at` hedge.
2. **Add a "Rollout Order" section** + backfill of `auto_ignored`/`finding_key` for existing active-run rows (port phase54 logic; don't delete it until rescans land) OR a fallback path in the RPC; sequence worker→migration→rescan→backend.
3. **Fix the `auto_ignored` cross-pipeline input** (DAST clears it on confirm, or read-time `runtime_confirmed_at` override).
4. **Add task 1.5: shared dependency-free triage module** consumed by frontend + backend + worker; only then is the "delete the dup" criterion achievable.
5. **Re-scope honestly:** split trackers into PR-B; cut auto-close + taint_flow-into-unified-model from v1; scope "zero drift" to ungrouped types (or add a stored `group_key`); state the events table has no v1 reader.
6. **Reconcile with existing mechanisms** (DAST `commit_dast_target_run`, phase30/45 iac/container, malicious recompute RPC, Jira/Linear cred scope) — audit each before writing the corresponding change.
7. **Rewrite the Testing section:** freeze the autoTriageRow golden-master before deletion; make parity a shared-TS-function + finding_key-set assertion incl. grouped types; per-type carry-forward scenarios in the named harness; the auto-reopen collision matrix; backfill correctness + idempotency; cross-org IDOR + malformed input; tracker failure modes.

## Findings by Axis
| Axis | Count | Highest |
|---|---|---|
| rollout-order / backfill | 4 | P0 |
| per-run cardinality / finding_key identity | 5 | P0 |
| cross-pipeline / cross-lifecycle dependency | 2 | P0 |
| count==table parity / grouping drift | 5 | P0/P1 |
| test coverage gaps | 7 | P0/P1 |
| scope / phasing | 6 | P1 |
| reconcile existing mechanism | 4 | P1/P2 |
| integration creds | 4 | P1/P2 |
| opportunity | 5 | P3 |

## Persona Coverage Map
| Persona | R1 findings | Vote |
|---|---|---|
| skeptic | 10 | REVISE |
| pragmatist | 8 | REVISE |
| scope-cutter | 8 | REVISE |
| architect | 10 | REVISE |
| test-strategy-auditor | 10 | REVISE |
| opportunity-scout | 5 | READY+ |
| data-model-auditor | 8 | REVISE |
| migration-safety-auditor | 8 | REVISE |

## Recommended Next Step
**REVISE.** Apply amendments 1-7 to `.cursor/plans/findings-status.plan.md` (the brief stands — no /brainstorm needed). The biggest single move is re-architecting the **finding_key / per-run / rollout** story; once that's coherent, the rest is scoping + test specification. Recommend re-running `/review-plan findings-status` (lean) after the rewrite to confirm the P0 cluster is closed, then `/implement` starting with the migration + the shared triage module + the golden-master freeze.
