# Plan Review — iac-container-v2-phase2-closeout

Verdict: **REVISE**
Plan reviewed: `.cursor/plans/iac-container-v2-phase2-closeout.plan.md`
Generated: 2026-05-19
Mode: lean (6 personas); debate: off
Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout
Findings: 0 critical / 5 high / 5 medium / 8 low

## Summary

The plan's direction is sound — every item is verified against merged code and the close-out genuinely finishes Phase 2. No P0s. But five P1 gaps will cause rework if built as-written: (1) the depscore backfill is deferred as "optional" yet Success Criterion 1 is *false* without it; (2) the new reaper route is heavier than needed and is itself dead code until a manual QStash step — folding it into the existing `scanner-cache-reap` cron is simpler and actually complete; (3) wrapping `generateRecommendation` per-Dockerfile is the wrong granularity — a bad catalog throws once-per-run, not per-file; (4) the ×0.4 multiplier silently contradicts Deptex's own `depscore.ts` reachability weights and needs an explicit justification; (5) the orchestrator — the most behavior-changing file — has no named tests. All five are fixable patches; core direction holds → REVISE.

## Vote Tally

Lean mode, no debate — verdict synthesized from findings (the verdict rule is mechanical: P1 findings present, zero P0 → REVISE). No separate vote round was run. Persona-level disposition inferred from findings:

| Persona | Disposition | Top concern |
|---|---|---|
| skeptic | REVISE | Backfill deferral makes Success Criterion 1 false |
| pragmatist | REVISE | New reaper route over-built vs folding into existing cron |
| scope-cutter | REVISE | Standalone reaper route contradicts brief's "existing cron" |
| architect | REVISE | ×0.4 multiplier diverges from `depscore.ts` constants |
| test-strategy-auditor | REVISE | Orchestrator-layer changes have no named tests |
| opportunity-scout | READY (non-blocking) | Opportunities only |

## P0 — Fundamental Concerns

No P0 findings.

## P1 — High-Priority Gaps

### depscore-staleness: The backfill is deferred as "optional" but Success Criterion 1 is false without it `[CONSENSUS 4/6]`
- **Plan section:** Data Model / Risks & Open Questions — "Optional depscore backfill"
- **Claim:** `scanner-findings.ts` sorts container findings purely by the `depscore` column. With no backfill, only freshly-re-scanned projects get reachability-adjusted scores — an un-rescanned project's `unreachable` HIGH (70) still sorts *above* a fresh project's `unreachable` HIGH (28). Success Criterion 1 ("an `unreachable` finding sorts below a `module` finding of equal severity") holds only within a single post-PR run.
- **Evidence:** `scanner-findings.ts` `.order('depscore', …)` / `.gte('depscore', …)`; container re-scans are days/weeks apart depending on `sync_frequency`; carryforward keeps stale rows across no-change runs. `reachability_level` is already populated on existing rows, so the backfill is one idempotent `UPDATE`.
- **Suggested patch:** Promote the backfill from an Open Question to a **required** step of Task 1: run `UPDATE project_container_findings SET depscore = ROUND(depscore * 0.4) WHERE reachability_level = 'unreachable' AND depscore IS NOT NULL;` via Supabase MCP. Reword Success Criterion 1 so it does not depend on a re-scan. (scope-cutter dissented — preferred dropping it to avoid an ad-hoc prod mutation; mitigated by it being a single reviewed idempotent statement run via MCP, which is standard Deptex practice.)
- **Flagged by:** skeptic-f5, architect-f4, pragmatist-f2, opportunity-scout-f2

### reaper-overbuild: Fold the reaper into the existing `scanner-cache-reap` cron instead of a new route `[CONSENSUS 3/6]`
- **Plan section:** Implementation Tasks — "5. (F1) Base-image recommendations reaper"
- **Claim:** A new route + new test file + a **manually-created QStash schedule** is the heaviest task in a plan billed as "no new routes," and it leaves the route dead until Henry manually wires the cron — Success Criterion 4 ("a cron deletes dismissed recommendations") is not satisfied by the PR. It also contradicts brief item F ("wire into an existing maintenance cron").
- **Evidence:** `scanner-cache-reaper.ts` is a daily 03:00 QStash cron that already has a schedule. Both reapers are container-scan maintenance on the same cadence.
- **Suggested patch:** Replace Task 5 — add a second `supabase.rpc('cleanup_dismissed_base_image_recommendations', { retention_days: 90 })` call inside the existing `scanner-cache-reap` handler; extend its response to `{ ok, cache_rows_deleted, recommendation_rows_deleted }`. No new route, no new file, no new QStash schedule. Add one assertion to the existing reaper test. (Note: phase28c's RPC `RETURNS INTEGER` — verified — so `rows_deleted` is a real count; architect-f5's return-type concern is already satisfied.)
- **Flagged by:** pragmatist-f1, scope-cutter-f1, skeptic-f6

### catalog-load-granularity: Wrapping `generateRecommendation` per-Dockerfile is the wrong granularity `[CONSENSUS 2/6]`
- **Plan section:** Implementation Tasks — "2. (C+D) Orchestrator hardening" (item C)
- **Claim:** `generateRecommendation` is synchronous and calls `loadCatalog()`; a bad/missing catalog is a deterministic whole-run failure. A per-Dockerfile try/catch produces N identical `base_image_advisor_failed:<path>` warnings — noise, not resilience.
- **Evidence:** `git show origin/main:orchestrator.ts` — `runBaseImageAdvisor` builds `rows` from synchronous `generateRecommendation(...)` calls; only `upsertBaseImageRecommendations` is currently wrapped.
- **Suggested patch:** Split item C's robustness fix: (a) load + validate the catalog **once** before the loop in a single try/catch — on failure push one `base_image_advisor_catalog_unavailable` warning and skip the advisor; (b) keep a per-Dockerfile try/catch only for per-file (`parseDockerfileFinalStage` / read) failures. Verify `loadCatalog`'s memoization in `base-image-catalog.ts` at implement time.
- **Flagged by:** skeptic-f2, architect-f3

### depscore-convention: The ×0.4 multiplier silently contradicts `depscore.ts`'s own reachability weights `[SOLO]`
- **Plan section:** Competitive Research & Design Rationale / Task 1
- **Claim:** `depscore.ts` defines `REACHABILITY_WEIGHT_UNREACHABLE = 0.0` ("drops out of depscore ranking entirely") and `module = 0.5`. The plan picks ×0.4 for `unreachable` / ×1.0 for `module` while citing "consistency with the code-dependency depscore" — the cited precedent uses different numbers.
- **Evidence:** `git show origin/main:depscanner/src/depscore.ts`.
- **Suggested patch:** Add a "Relationship to `depscore.ts`" note: container depscore is a separate severity→90/70/50/30/10 scale; `unreachable` is ×0.4 (not ×0.0) **because static OS-package reachability is a weaker signal than code-dependency call-graph reachability** — the binutils-absent and `exec "$@"`-wrapper fallbacks mean a non-zero floor is the fail-closed choice. Name the constant `CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER` and cross-reference `REACHABILITY_WEIGHT_UNREACHABLE` in a code comment. This also closes the ×0.4-vs-×0.5 Open Question — **lock ×0.4**.
- **Flagged by:** architect-f1

### orchestrator-test-gap: The most behavior-changing file has no named tests `[CONSENSUS 1/6, multi-finding]`
- **Plan section:** Testing & Validation Strategy
- **Claim:** Task 2 changes `orchestrator.ts` behavior three ways (catalog try/catch, budget clamp, log expansion) and the Testing section names *zero* orchestrator tests. The acceptance criteria are behavioral claims with no corresponding tests.
- **Evidence:** Testing & Validation lists only `storage.ts`, `trivy-image-args`, route, and frontend tests.
- **Suggested patch:** Add named tests: (a) `runBaseImageAdvisor` — mock `loadCatalog` to throw `CatalogValidationError`, assert one `base_image_advisor_catalog_unavailable` warning and no exception escapes; (b) extract the budget-clamp expression into a pure helper and unit-test the boundary (`max(1,…)` floor when budget is exhausted); (c) cross-tenant 403 on **both** permission gates (org-A manager requesting an org-B project — `checkProjectManagePermission` runs `projectBelongsToOrg`).
- **Flagged by:** test-strategy-auditor-f1, f2, f4

## P2 — Quality Gaps

- **budget-clamp framing** (skeptic-f3, architect-f2) — *Codebase Analysis / Task 2.* The orchestrator's own comment says reachability cost is "naturally charged" against the loop budget; the real gap is only a ≤30s single-image overshoot of the 25-min total. Reframe item C's budget bullet as a minor tightening with the precise overshoot quantified, not a correctness bug.
- **KEV downweighting** (skeptic-f4) — *Risks & Open Questions.* Decide whether `is_kev` / high-`epss_score` findings are exempt from the `unreachable` multiplier. Recommendation: **do not exempt** — static reachability is precisely the signal that contextualizes a KEV ("not loaded in this image" genuinely lowers urgency) — but surface the decision explicitly in the plan rather than leaving it implicit.
- **ScannersPanel test under-specified** (test-strategy-f5) — *Testing & Validation.* "Add a `ScannersPanel.test.tsx` if none exists" is vague; none exists. Specify all three vitest cases (pending→skeleton, rejected→error+retry that re-issues the fetch, resolved-`[]`→section absent — Success Criterion 6's "distinct from empty" needs all three) and name the mock target `getBaseImageRecommendations`.
- **depscoreMin filter shift** (architect-f6) — *Regression watch.* `scanner-findings.ts` applies `.gte('depscore', depscoreMin)`; a downweighted `unreachable` HIGH (28) now falls below a saved `depscore_min=30` filter. Add a line to Regression watch confirming this is intended triage behavior.
- **log-payload tests** (test-strategy-f6) — *Testing & Validation.* The expanded `container_scan.reachability` log and the new `catalogHash` log are acceptance criteria (Success Criterion 4) with no test; add a logger-spy assertion.

## P3 — Nits & Opportunities

- **skeleton reuse** (pragmatist-f3) — reuse the summary fetch's loading affordance rather than a bespoke card-shaped skeleton; the load-bearing fix is distinguishing error from empty. (Counter: a card-shaped skeleton matches Deptex's skeleton precedent — minor, implementer's call.)
- **cut order in Overview** (scope-cutter-f5) — add one sentence noting A+B are blocking correctness, D/E/F the safe trim set if the PR must land fast.
- **demoted-count log** (opportunity-scout-f1) — have `upsertContainerFindings` tally and log how many findings got the `unreachable` multiplier (`{ total, demoted_unreachable }`) — makes the feature's impact self-reporting after the binutils deploy.
- **advisor-degraded UI notice** (opportunity-scout-f3) — if a scan's `warnings` contains `base_image_advisor_*`, render a small inline notice in `ScannersPanel` instead of a silent empty section.
- **catalogHash as a named field** (opportunity-scout-f5) — log `{ catalog_hash, dockerfile_count }` so catalog drift is greppable across runs.
- **reaper deletion log** (opportunity-scout-f4) — moot if folded into `scanner-cache-reap` (P1-2); ensure the merged handler logs `recommendation_rows_deleted`.
- **grep-verify `.Packages`** (skeptic-f7) — already done during `/plan-feature` grounding (zero consumers); Task 3 can just cite it.
- **retry independence** (skeptic-f8) — state in Task 6 that the recommendations error/retry is independent of the summary fetch's error handling (out of scope).
- **catalogHash dead-code** (scope-cutter-f3) — reviving `catalogHash()` for one log line is the safe drop if Task 2 needs trimming; otherwise fine.

## Suggested Plan Amendments

### Patch for `Risks & Open Questions / Task 1` — depscore-staleness
**Concern:** Success Criterion 1 is false until every project re-scans.
**Source:** skeptic-f5, architect-f4 [CONSENSUS 4/6]
**Recommended change:** Move the backfill `UPDATE` from "Optional / default no" to a required final step of Task 1, applied via Supabase MCP; reword Success Criterion 1 to not depend on a re-scan.

### Patch for `Implementation Tasks — Task 5` — reaper-overbuild
**Concern:** New route + manual QStash schedule is over-built and leaves the PR incomplete.
**Source:** pragmatist-f1, scope-cutter-f1, skeptic-f6 [CONSENSUS 3/6]
**Recommended change:** Fold `cleanup_dismissed_base_image_recommendations` into the existing `scanner-cache-reap` handler; drop the new route, new file, and new QStash-schedule step. Update the API table and Testing section accordingly.

### Patch for `Task 2 (item C)` — catalog-load-granularity
**Concern:** Per-Dockerfile try/catch produces N identical warnings on a bad catalog.
**Source:** skeptic-f2, architect-f3 [CONSENSUS 2/6]
**Recommended change:** Load+validate the catalog once before the loop (one warning + skip advisor on failure); per-Dockerfile catch only for per-file failures.

### Patch for `Competitive Research & Design Rationale / Task 1` — depscore-convention
**Concern:** ×0.4 contradicts `depscore.ts`'s `REACHABILITY_WEIGHT_UNREACHABLE = 0.0`.
**Source:** architect-f1 [SOLO]
**Recommended change:** Add a "Relationship to `depscore.ts`" note justifying the non-zero floor (weaker static signal); rename the constant `CONTAINER_UNREACHABLE_DEPSCORE_MULTIPLIER`; lock ×0.4 and remove the ×0.4/×0.5 Open Question.

### Patch for `Testing & Validation Strategy` — orchestrator-test-gap
**Concern:** Orchestrator behavior changes are untested.
**Source:** test-strategy-auditor-f1, f2, f4 [SOLO, multi-finding]
**Recommended change:** Add named tests for the catalog-failure catch, the extracted budget-clamp helper, and cross-tenant 403 on both permission gates.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| depscore staleness / backfill | 4 | P1 | skeptic, architect, pragmatist, opportunity-scout |
| reaper over-build | 3 | P1 | pragmatist, scope-cutter, skeptic |
| catalog-load granularity | 2 | P1 | skeptic, architect |
| depscore convention divergence | 1 | P1 | architect |
| test coverage gaps | 7 | P1 | test-strategy-auditor |
| budget-clamp framing | 2 | P2 | skeptic, architect |
| observability / opportunities | 6 | P2 | opportunity-scout, scope-cutter |
| UI polish | 3 | P3 | pragmatist, skeptic, opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | Vote (synthesized) |
|---|---|---|
| skeptic | 8 | REVISE |
| pragmatist | 4 | REVISE |
| scope-cutter | 5 | REVISE |
| architect | 6 | REVISE |
| test-strategy-auditor | 7 | REVISE |
| opportunity-scout | 5 | READY (non-blocking) |

## Recommended Next Step

**REVISE** — apply the 5 suggested amendments to `iac-container-v2-phase2-closeout.plan.md` (none is a redesign; the two biggest — backfill-required and reaper-fold — actually *shrink* the PR). A re-run of `/review-plan` is optional given the patches are mechanical; then `/create-worktree iac-container-v2-phase2-closeout` → `/implement`.
