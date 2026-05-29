# Plan Review — depscanner-dogfood (Revision 2)

**Verdict: REVISE**

Plan reviewed: `.cursor/plans/depscanner-dogfood.plan.md` (rev 2)
Generated: 2026-05-22
Mode: lean; debate: off
Personas: 6 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout
Vote tally: 1 READY / 4 REVISE / 1 REWORK
Findings: **5 P0 critical** / ~18 P1 high / ~16 P2 medium / ~10 P3 low

> **Note:** This supersedes the prior Rev-1 review (REWORK, 6/6 unanimous). Rev 2 applied the 11 P0/P1 patches from that review. Of the original 6 P0s, all were addressed. But the patches that addressed them introduced new P0s — most clustering around the `exclude_from_org_rollups` mechanism. The vote distribution (4 REVISE) signals these are fixable, not fatal.

## Summary

Rev-2 plan successfully resolved every Rev-1 P0 (M0 deleted, scope cut 27→13, strict 1:1 loosened, harness added, etc.) but introduced 5 new P0s, four of which cluster around the `exclude_from_org_rollups` patch (the one originally added to solve Rev-1's architect-f3 "pollution-of-prod-rollups"). The independent verdict: that patch over-engineered a problem with a simpler solution (dedicated test org). Drop it and 3 of 5 P0s vaporize. The remaining 2 P0s — snapshot-test pollution from "extending existing fixtures" + M1 milestone undersizing — are surgical fixes.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REWORK | skeptic-f2 | Rollup-isolation premise still load-bearing and wrong; OrganizationFindingsPage fans out per-project, so filtering backend aggregate queries can't isolate the dashboard |
| pragmatist | REVISE | pragmatist-r2-f2 | Rev 2 still carries the exclude_from_org_rollups complexity + duplicative annotations; both are pure scope cuts |
| scope-cutter | READY | scope-cutter-r1-f1 | Rev 2 absorbed M7→M6 fold and dropped 27→13; remaining items are tweaks, not rework |
| architect | REVISE | architect-r2-f2 | Rollup-query-undercount is real architectural gap; copy-or-symlink and harness auth-shape decisions also unresolved |
| test-strategy-auditor | REVISE | test-strategy-auditor-f1 | P0s have plausible fixes but harness has no self-tests; M6 gate can't fail by construction without negative-path demo |
| opportunity-scout | REVISE | skeptic-f3 | M1 still oversized at 11 sub-tasks; will starve opportunity surface unless rebalanced |

## P0 — Fundamental Concerns

### missing-endpoint: `PATCH /api/organizations/:id/projects/:projectId` doesn't exist `[SOLO]`
- **Plan section:** API Design / M1.8
- **Claim:** Plan's API Design table says "PATCH endpoint already accepts arbitrary project field updates; just allow the new column through whatever filter list it uses" — but `backend/src/routes/projects.ts` has only sub-resource PATCHes (notification-rules, repositories/settings, vulnerabilities/suppress, accept-risk), no base-resource PATCH on a project. Adding the `exclude_from_org_rollups` checkbox requires a NEW endpoint, RBAC gate, validator, frontend wiring — not a one-line allowlist tweak.
- **Evidence:** Grep of `router.patch` in projects.ts returns six sub-resource handlers, zero base-resource PATCH.
- **Suggested patch:** Either drop `exclude_from_org_rollups` entirely (see scope-cutter-r1-f3 / pragmatist-r2-f2 — use dedicated test org instead), OR add explicit M1.8 work: NEW endpoint with `manage_teams_and_projects` permission gate + test coverage. Re-cost M1.8 from [S] half-day to [M] 1-2 days.
- **Flagged by:** skeptic

### rollup-isolation-misframed: 3-4 backend filter sites won't isolate the Findings dashboard `[SOLO]`
- **Plan section:** Data Model / Frontend Design
- **Claim:** `OrganizationFindingsPage.tsx:368-410` fans out CLIENT-SIDE per project — calls `api.getProjects(organizationId)` then fires 5 per-project finding-type calls + `getOrganizationVulnerabilities`. Funnel + donut + Top Projects are aggregated frontend-side. Filtering only the 3-4 backend aggregate routes (whose locations are TBD per plan) leaves the actual dashboard rollup UNFILTERED. The dominant fix site is `GET /:id/projects` itself or the frontend fan-out calls — neither in the plan's "3-4 sites" estimate.
- **Evidence:** `OrganizationFindingsPage.tsx:368` `api.getProjects(organizationId)`; line 376 `getOrganizationVulnerabilities`; lines 382-410 5-way fan-out per project. Plan Data Model: "KEV/EPSS aggregate query (location TBD)" + "SLA org-aggregate query (location TBD)" — load-bearing TBDs.
- **Suggested patch:** Pre-/implement, commit to a contract: `GET /organizations/:id/projects?exclude_dogfood=true` (default TRUE for Findings page, FALSE for project list / canvas / Aegis). Add same param to `getOrganizationVulnerabilities`. Update OrganizationFindingsPage's calls to pass `exclude_dogfood: true`. Audit other frontend rollup call sites. Reframe M1.8 from "add filter to identified sites" to a 6-step backend+frontend change. Re-estimate 1.5-2 days. **Alternative: drop `exclude_from_org_rollups` entirely; use dedicated test org.**
- **Flagged by:** skeptic, architect (independent — same finding from two angles)

### milestone-undersized: M1 has 11 sub-tasks; sized [M]=3-4 days, realistic 5-7 `[SOLO]`
- **Plan section:** M1 — Foundation + first reference fixture (express)
- **Claim:** M1 sized [M] (3-4 days) but contains 11 sub-tasks spanning four workstreams: docs scaffolding (M1.1-1.4), schema design (M1.5), throwaway probe (M1.5.5), reference fixture authoring (M1.6), open-ended walkthrough iteration (M1.7), phase37 migration + 3-4 filter sites + frontend checkbox (M1.8), dependabot config (M1.9), PR ship (M1.10). M1.7 alone is [M] AND is an iteration loop. The plan's own gate ("if >5 days, surface to Henry") only triggers at 25-67% overrun.
- **Evidence:** Plan §M1 lists 11 numbered sub-tasks. Gate threshold (5d) for M sized at 3-4d implies a 67% overrun is plausible. M1.8 is undersized per skeptic-f1 + skeptic-f2.
- **Suggested patch:** Split M1 into M1a (docs + schema + seed-probe + dependabot, [M] 2-3d), M1b (migration + endpoint + checkbox + filter sites, [M] 2-3d, OR skip entirely if dropping `exclude_from_org_rollups`), M1c (express fixture + walkthrough, [M-L] 3-5d). Total 7-11 days, 3 PRs. OR keep one M1 PR but mark [L] and adjust gate to ">9 days = re-plan."
- **Flagged by:** skeptic

### snapshot-test-pollution: extending existing fixtures breaks `snapshot.ts` `[SOLO]`
- **Plan section:** Files modified / M2.1, M3.1-3, M4.1-3, M5.2-3
- **Claim:** Plan asserts "original files stay intact (existing snapshot tests still pass)" — but `depscanner/test/snapshot.ts:43-81` shells out the CLI against the WHOLE fixture directory (FIXTURES_ROOT = `path.resolve(__dirname, '../fixtures')`; iterates the manifest including test-nextjs/django/fastapi/flask/spring/gin/sinatra/laravel/rust-axum/aspnet). Adding Dockerfile + k8s.yaml + .env.example + .deptex sidecar into those directories WILL alter scan output (cdxgen sees Dockerfile manifest, Checkov/Trivy emit IaC, TruffleHog scans .env.example, Semgrep sees nginx). Content-stability ≠ scan-output-stability.
- **Evidence:** Snapshot runner walks the full fixture dir, not just original files. Most listed fixtures have no committed `snapshots/` (bootstrapping path on next regen). Plan §M2.1 says "Copy or symlink" but doesn't commit.
- **Suggested patch:** Decide NOW: dogfood corpus lives ENTIRELY at `depscanner/test-repos/<framework>/` as **standalone copies** of the matching taint-engine fixtures. The original `depscanner/fixtures/test-*` directories stay byte-stable. Update plan language from "extending existing fixture" to "copy as starting point; modify only the copy." Add explicit verification in M1.5.5: run `npm run snapshot -- --include-slow` before AND after to confirm zero unexpected diffs. Symlinks rejected — Windows portability.
- **Flagged by:** architect

### rollup-query-undercount: see skeptic-f2 (same finding from architect's angle) `[SOLO]`
- **Plan section:** Data Model
- **Claim:** Same as skeptic-f2 from a different angle. The "3-4 backend rollup query sites" estimate doesn't reckon with `OrganizationFindingsPage`'s per-project fan-out architecture. Filtering at the wrong layer leaves the actual rollup unfiltered.
- **Suggested patch:** Same as skeptic-f2 — commit to a `?exclude_dogfood=true` contract on `getProjects` + `getOrganizationVulnerabilities` with frontend call-site updates, OR drop `exclude_from_org_rollups` entirely.
- **Flagged by:** architect

## P1 — High-Priority Gaps

(All P1s `[SOLO]` — no-debate mode)

- **reuse-claim-overweighted** (skeptic-f4) — Existing fixtures are tiny (3-4 files / ~36 LOC each). Layered content (Dockerfile + k8s + IaC + secret + Semgrep + malicious-pkg + DAST deploy.sh + expected.yaml + annotations) dominates 5-10x. The "extending" framing overstates cost savings. Reframe: 9 of 13 fixtures REUSE the taint-engine source files (small fraction); the seed layers are still new authoring per fixture. Reset M2-M5 estimates from 2-3d to 3-5d per batch.
- **harness-untested-itself** (skeptic-f5 / test-strategy-auditor-f1) — M6's `dogfood-check.ts` has zero contract for its own correctness. M6.3 ("Should be 13/13 green") is green-by-construction. Add M6.1.5: vitest unit tests with mutation cases (drop required osv_id → FAIL; alias substitution → PASS; bucket boundaries; subset semantics). Add M6.3.5: deliberately break one fixture's expected.yaml, confirm harness FAILs with helpful diff, revert. ~30 min cost.
- **duplicative-source-of-truth-unresolved** (skeptic-f7 / pragmatist-r2-f1) — Rev-1's pragmatist-f2 said drop EITHER annotations OR expected.yaml. Rev 2 kept both with "forward-compatible with v2" rationale. But v1 has no annotation parser, so Henry maintains two artifacts in sync manually across 13 fixtures. Pick one for v1: recommend dropping inline annotations entirely (drop CONVENTIONS.md's per-language syntax matrix).
- **dedicated-test-org-cuts-scope** (pragmatist-r2-f2 / scope-cutter-r1-f3) — `exclude_from_org_rollups` column + Settings checkbox + filter propagation is real cross-stack work + permanent schema surface — for a problem solved more cheaply by creating a dedicated test org. Strike phase37 + UI + filter work from M1.8. Move the column to its own brief (real customer feature deserves its own /brainstorm). Saves ~1-2 days + vaporizes 3 of 5 P0s.
- **M2-M5-collapse-to-one-PR** (pragmatist-r2-f3) — M3+M4+M5 partial work is mechanical extension. Four sequential ecosystem PRs introduce week of artificial serialization + 4 review cycles for near-identical diffs. Compress to: M1 (foundation + express), M-extend (9 extensions), M-greenfield (react + rails), M6 (harness), M7 (sign-off) = 4-5 PRs total.
- **M7-overhead** (scope-cutter-r1-f1) — M7 produces zero shippable corpus: spot-check + OSV refresh + writeup + CLAUDE.md + memory note. Two PRs for ~1-2 days of mostly docs is the PR-overhead antipattern. Fold M7 into M6.
- **copy-or-symlink-unresolved** (architect-r2-f3) — Plan says "Copy or symlink per CONVENTIONS.md" but CONVENTIONS.md doesn't decide. Symlinks break on Windows (primary platform per env). Commit to copy. Add `.deptex/SOURCE.md` per fixture recording the SHA of the upstream fixture for traceability.
- **harness-auth-shape-undefined** (architect-r2-f4) — M6.1 says "Hit findings API for that project" but doesn't say HOW: user JWT (rotation pain, session-scoped) vs service role (bypasses RBAC, bypasses API contract — which is half the dogfood point). Commit to: service-role direct Supabase query in `dogfood-check.ts`. Document the tradeoff: M1.7 walkthrough validates the API surface manually.
- **aegis-context-loaders-leak** (architect-r2-f6) — R8 says Aegis allowed to interact with fixtures. But Aegis chat context loaders enumerate org-scoped projects. If they get filtered too, Aegis can't see fixtures. If they don't, Aegis's "show me org overview" answers will include 13 vuln projects. Clarify: rollup-exclusion affects ONLY org-aggregate dashboards, NOT Aegis context or project list.
- **cross-batch-regression-still-manual** (test-strategy-auditor-f2) — Rev 1's prior P1 lifted to P0 via M6, but M6 ships LAST. M2-M5's cross-batch gate remains "Henry re-syncs prior PRs' fixtures via UI button + records drift." Either move M6 earlier (immediately after M1) OR write a stop-gap shell script for M2-M5 to use.
- **DAST-single-use** (test-strategy-auditor-f3) — Prior P2 (rev-1 test-strategy-auditor-f8) not addressed. DAST is unverifiable post-M7 without re-deploying every fixture. Capture `.deptex/dast-baseline.har` per server-side fixture using the recent HAR-import feature.
- **rollup-filter-no-test** (test-strategy-auditor-f4) — `exclude_from_org_rollups` propagation has no integration test. Add a backend integration test that hits every rollup endpoint against a test org with 1 excluded + 1 non-excluded vuln project; assert excluded counts are zero. Or drop the column per pragmatist-r2-f2.
- **m6-cannot-fail-by-construction** (test-strategy-auditor-f6) — M6 runs against synthetic ground truth (each fixture hand-walked green). Add negative-path demo to PR description: deliberately remove an annotation, run harness, paste FAIL output, restore.

## P2 — Quality Gaps

(Selected, not exhaustive)

- skeptic-f6 — reachability bucket boundaries `{module|unreachable}` for "unreachable" not validated against measured 8-15% trial drift.
- skeptic-f8 — M1.5.5 probe via local CLI may green where prod Fly worker fails. Probe via Docker image too.
- skeptic-f9 — `exclude_from_org_rollups` on `projects` + `sync_frequency` on `project_repositories` = two flags on two tables; success criterion #3 conflates them.
- skeptic-f10 — Drift-detection vs alias-refresh has no protocol during M2-M5.
- skeptic-f11 — Gate-after-M1 threshold (>5 days) too tight given pessimistic-realistic floor of 5-7 days.
- skeptic-f12 — Phase37 migration risks not enumerated (schema:dump rebase race per `feedback_schema_dump_rebase`).
- pragmatist-r2-f4 — M6 harness overscoped: drop config-map + per-category breakdown + run-all step; ship single `--fixture` invocation.
- scope-cutter-r1-f2 — Drop v1b backlog memo as separate file; fold into M6.8 writeup.
- scope-cutter-r1-f4 — M1.5.5 seed-probe down to 1-hour spike on the genuinely unknown surface (malicious-pkg).
- scope-cutter-r1-f5 — Drop greenfield rails entirely OR replace with 1-CVE Rails stub.
- scope-cutter-r1-f6 — Drop manual UI cross-batch re-sync; let M6 harness handle.
- scope-cutter-r1-f7 — Collapse `test-repos/README.md` + `CONVENTIONS.md` into the runbook.
- architect-r2-f5 — PATCH allowlist explicit step missing from M1.8 (related to skeptic-f1).
- architect-r2-f7 — Phase37 filename collision risk; defer phase-number allocation to /implement.
- architect-r2-f8 — M1.5.5 probe via CLI ≠ prod pipeline; populate-dependencies, EPD, policy engine all skipped.
- test-strategy-auditor-f5 — M1.5.5 only probes scanners individually; integration glue (EPD, policy, populate-dependencies) untested.
- test-strategy-auditor-f7 — M7.2 OSV refresh has no decision tree for drift-vs-bug.

## P3 — Nits & Opportunities

(Opportunity-scout's 10 findings are all P3 by design)

- opportunity-scout-f1 — `exclude_from_org_rollups` is a real customer feature; add audit-log entry + docs page + tier consideration.
- opportunity-scout-f2 — Sketch `.github/workflows/dogfood-check.yml` for future CI/contributor unlock.
- opportunity-scout-f3 — `expected.yaml` schema as user-facing baseline/allowlist primitive (re-raised from rev 1).
- opportunity-scout-f4 — Greenfield fixtures as marketing screenshot material.
- opportunity-scout-f5 — Anchor M7.3 writeup against 3 pre-decided blog angles.
- opportunity-scout-f6 — Corpus as Aegis Fix Agent regression baseline.
- opportunity-scout-f7 — v1b fixtures as contributor onboarding fuel; note in CONTRIBUTING.md.
- opportunity-scout-f8 — Tier/abuse considerations on `exclude_from_org_rollups` (per `billing_prepaid_rewrite_direction`).
- opportunity-scout-f9 — Public live-demo gallery (rev-1 carry-over).
- opportunity-scout-f10 — Snapshot full findings JSON per fixture at PR merge as v2-harness baseline.
- architect-r2-f9 — Positive confirmation: rev 2 correctly leaves checkov.ts + trivy.ts untouched per architect-r1-f1.

## Suggested Plan Amendments

### Patch A — Drop `exclude_from_org_rollups` entirely; use dedicated test org
**Concern:** Five P1+P0 findings cluster around this column. Two independent personas (pragmatist + scope-cutter) recommend dropping it.
**Source:** pragmatist-r2-f2 + scope-cutter-r1-f3 (independent agreement)
**Recommended change:** Strike from plan: phase37 migration, `exclude_from_org_rollups` column + partial index, Settings checkbox, frontend filter wiring, rollup-query filter sites, `schema:dump` refresh, Success Criterion #9. Create a dedicated `deptex-dogfood` prod org manually before M1 walkthrough (already listed as an open Dependencies item). Move the column work to its own brief: "customer-facing intentionally-vulnerable-project flag" — gets weighed against billing-prepaid-rewrite et al on its own merits. **Vaporizes skeptic-f1, skeptic-f2, architect-r2-f2, test-strategy-auditor-f4, plus opportunity-scout-f1/f8 (no longer relevant in this arc).**

### Patch B — Copy, not extend; verify snapshot stability
**Concern:** Extending existing `depscanner/fixtures/test-*` will pollute snapshot tests.
**Source:** architect-r2-f1
**Recommended change:** All test-repos/ fixtures are standalone copies of their matching taint-engine fixture; the originals stay byte-stable. Add to M1.5.5 verification: `npm run snapshot -- --include-slow` before AND after each fixture lands; zero unexpected diffs. Strike "copy or symlink" wording — commit to copy. Add `.deptex/SOURCE.md` per fixture recording upstream SHA.

### Patch C — Re-size M1 (split or relabel)
**Concern:** M1 has 11 sub-tasks; [M] sizing wrong.
**Source:** skeptic-f3 + opportunity-scout vote
**Recommended change:** With Patch A applied, M1 drops the migration/UI/filter work — M1 becomes mostly docs + express fixture + walkthrough. Resize to [M-L] 4-6 days with explicit gate at >6 days. If not applying Patch A: split M1 into M1a (docs + dependabot, 2-3d), M1b (migration + UI + filter, 2-3d), M1c (express + walkthrough, 3-5d) — 3 PRs.

### Patch D — Drop inline annotations OR drop expected.yaml (pick one)
**Concern:** Both source-of-truth artifacts maintained without parser enforcement.
**Source:** skeptic-f7 + pragmatist-r2-f1 (independent agreement, rev-1 carry-over)
**Recommended change:** Recommend dropping inline annotations entirely for v1. expected.yaml is the canonical source the harness consumes. Strike M1.2's per-language comment syntax matrix from CONVENTIONS.md. Source files become unannotated realistic fixtures. v2 can re-introduce annotations when an annotation parser ships.

### Patch E — Add harness self-tests + negative-path demo
**Concern:** M6 harness has no contract for its own correctness.
**Source:** skeptic-f5 + test-strategy-auditor-f1 + test-strategy-auditor-f6 (triple agreement)
**Recommended change:** Add M6.1.5 — vitest unit tests for the diff logic (mutation cases). Add M6.3.5 — deliberately break one fixture's expected.yaml; harness FAILs; paste output in M6 PR description; revert.

### Patch F — Move harness to M2 (or stop-gap script)
**Concern:** Cross-batch regression manual through M5 until M6 lands.
**Source:** test-strategy-auditor-f2
**Recommended change:** Either (a) move M6 to immediately after M1 so `npm run dogfood:check` becomes the M3-M5 cross-batch gate, OR (b) ship a 50-line shell wrapper in M1.9 that diffs `findings.json` snapshots — used by M2-M5 until M6's full harness lands.

### Patch G — Commit copy-or-symlink and harness auth shape
**Concern:** Two architectural decisions deferred to /implement.
**Source:** architect-r2-f3 + architect-r2-f4
**Recommended change:** Lock: COPY (not symlink) for fixture reuse — Windows portability. Lock: `dogfood-check.ts` uses Supabase service-role direct query (NOT user JWT). Document tradeoffs in CONVENTIONS.md.

### Patch H — Clarify Aegis-exclusion semantics
**Concern:** Aegis context loaders may surface fixtures in chat.
**Source:** architect-r2-f6
**Recommended change:** Plan §Data Model addendum: "If exclude_from_org_rollups survives (Patch A not adopted): affects org-aggregate dashboards ONLY. Aegis context loaders and org canvas continue to see all projects. Fixtures are Aegis-visible by design." With Patch A adopted: moot.

### Patch I — DAST baseline capture per fixture
**Concern:** DAST regression unverifiable post-M7.
**Source:** test-strategy-auditor-f3
**Recommended change:** Add per-server-side fixture: capture `.deptex/dast-baseline.har` after first successful DAST scan (via HAR-import feature from PR #52). Harness re-imports HAR to verify without re-deploying. ~15-30 min per server-side fixture, ~3 hours total across 8.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| rollup-isolation / exclude_from_org_rollups complexity | 6 | P0 | skeptic, architect, pragmatist, scope-cutter, test-strategy-auditor |
| milestone-sizing | 3 | P0 | skeptic, opportunity-scout |
| snapshot-test / fixture-collision | 2 | P0 | architect |
| harness-correctness | 4 | P1 | skeptic, test-strategy-auditor |
| duplicative-source-of-truth | 2 | P1 | skeptic, pragmatist |
| dedicated-test-org-alternative | 2 | P1 | pragmatist, scope-cutter |
| scope-cut / PR-fold / dropped-fixture | 7 | P1 | pragmatist, scope-cutter |
| copy-vs-symlink / harness-auth | 2 | P1 | architect |
| cross-batch / DAST regression | 3 | P1 | test-strategy-auditor |
| reachability-bucket-stability / probe-env / migration-risk | 4 | P2 | skeptic |
| seed-probe-scope | 2 | P2 | skeptic, architect, test-strategy-auditor |
| OSV-refresh-decision-tree | 1 | P2 | test-strategy-auditor |
| opportunity / customer-facing-unlock | 10 | P3 | opportunity-scout |

## Persona Coverage Map

| Persona | R1 findings | Vote |
|---|---|---|
| skeptic | 12 | REWORK |
| pragmatist | 4 | REVISE |
| scope-cutter | 7 | READY |
| architect | 9 | REVISE |
| test-strategy-auditor | 7 | REVISE |
| opportunity-scout | 10 | REVISE |
| **Total** | **49** | **1 READY / 4 REVISE / 1 REWORK** |

## Recommended Next Step

**REVISE.** The plan is fundamentally on the right track — Rev-2's structural improvements (M0 deleted, scope cut, harness added, bucket-match, M1.5.5 seed-probe) all stuck. The new P0s are clustered around one over-engineered patch (`exclude_from_org_rollups`) plus surgical issues (snapshot-test pollution, M1 sizing). Two independent personas (pragmatist + scope-cutter) recommend dropping the column entirely in favor of a dedicated test org — applying that one patch (Patch A) vaporizes 3 of 5 P0s.

**Suggested path forward:**

1. **Apply Patch A** (drop `exclude_from_org_rollups`, use dedicated test org) — cuts ~1-2 days of work + vaporizes 3 P0s.
2. **Apply Patch B** (commit to copy, not extend; verify snapshot stability) — addresses the snapshot-test P0.
3. **Apply Patch C** (re-size M1) — once Patch A is in, M1 is naturally smaller; mark [M-L] 4-6 days.
4. **Apply Patch D** (drop inline annotations OR drop expected.yaml — recommend dropping annotations).
5. **Apply Patch E + F + G** (harness self-tests, move harness earlier or stop-gap, lock copy + service-role auth).
6. **Optionally Patch I** (DAST baseline HAR capture) — addresses a long-standing P1.
7. **Re-run `/review-plan depscanner-dogfood`** to confirm READY (or skip if confident).
8. **Then `/implement depscanner-dogfood`.**

Patches A-G are all surgical edits to a plan that's structurally sound. Estimated revision time: <1 hour.

Or — given scope-cutter voted READY and 4 voted REVISE rather than REWORK — Henry could opt to **proceed directly to /implement** treating the P0s as "fix during implementation rather than pre-plan-revision." That's a reasonable call for this kind of internal-quality arc where the cost of being wrong is "we re-walk a few fixtures" not "we shipped a broken feature to customers." But surgical-edit-then-implement is safer.
