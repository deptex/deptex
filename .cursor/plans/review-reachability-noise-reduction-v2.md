# Plan Review — reachability-noise-reduction-v2 (revision 2)
Verdict: **REVISE**
Plan reviewed: `.cursor/plans/reachability-noise-reduction-v2.plan.md` (revision 2)
Generated: 2026-05-18
Mode: lean (6 personas); debate: off — RE-review after rev 1 returned REWORK
Personas: 6 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout
Vote tally: 0 READY / 5 REVISE / 1 REWORK
Findings: 3 critical (P0) / 18 high (P1) / 14 medium (P2) / 8 low (P3)

## Summary

Revision 2 **genuinely closed all six rev-1 REWORK P0s** — the architect persona
independently verified that `source` is no longer written, dev-scope routes
through the non-key `environment` column (row identity holds), the corpus harness
is made SHA-pinnable, and the circular-validation / dual-scope risks now have named
tasks. The data-model foundation is sound and the dev-scope direction is endorsed.
What remains are **three localized P0s — all in tasks 4, 9, 13 — where a task
depends on a data path that does not yet exist** and no task wires it in:
(9) the precision fix assumes the cdxgen relationships graph is available in
`reachability.ts`, but it lives in the SBOM step; (13) the recall floor is placed
in `reachability-corpus.ts`, whose report shape carries no recall field;
(4) the dual-scope tiebreak needs `environment`/`is_direct`/`source`, but the
`dep-scan.ts` SELECT fetches only `id,name,version`. Each is a patch — widen a
SELECT, thread a parameter, serialize a field — not a redesign. 5 of 6 personas
voted REVISE; the data model is right, the remaining work is task-spec precision.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REVISE | skeptic-f2 | Mechanism sound, prior P0s closed; the 3 remaining P0s are real data-path gaps to patch before implementation. |
| pragmatist | REVISE | architect-f1 | Core `environment` rewrite sound; 3 P0s are localized task-level patches — a revision beats a rebuild. |
| scope-cutter | REVISE | architect-f1 | 3 P0s fixable in-task without re-architecting; full REWORK would waste effort. |
| architect | REVISE | architect-f1 | All 3 P0s verified-real but localized spec gaps; rev-2 data model + harness foundations are sound. |
| test-strategy-auditor | REWORK | test-strategy-auditor-f3 | Three task specs depend on data paths that verifiably don't exist and no task wires them in. |
| opportunity-scout | REVISE | architect-f1 | Core rewrite sound, rev-1 opportunities adopted; 3 P0s patchable without changing direction. |

## P0 — Fundamental Concerns

### task 9: the precision fix's relationships graph is not where the classifier runs `[architect-f1]`
- **Plan section:** Layer 2 task 9 (Precision fix — narrow, don't disable)
- **Claim:** Task 9 asserts "the graph is already loaded for Layer 2," but the Layer-2 relationships BFS lives in `sbom.ts` `patchDevDependencies` (SBOM step). The classifier runs in `reachability.ts` `updateReachabilityLevels`, which selects only `id, dependency_id, is_direct, files_importing_count` and has zero references to `relationships`/edges. Task 9 is unimplementable as written.
- **Suggested patch:** Task 9 must specify the data path: either (a) thread `relationships` through `ctx` into `UpdateReachabilityOptions` (mirroring the existing `graphTrusted`/`cveSinkPatterns` options), or (b) add a `dependency_version_edges` SELECT inside `updateReachabilityLevels`. Pick one explicitly; re-size task 9 S→M. **Combine with architect-f2 (P1):** a one-hop "is the parent imported" check demotes nothing — jackson-core/rustix parents are themselves un-imported transitives — so the predicate must be a full ancestor-closure (reuse Layer-2's `prodReachable` closure), and the acceptance must be a corpus-observed assertion that jackson/rustix land `module`, not a synthetic one-hop unit test.
- **Flagged by:** architect `[SOLO]` (corroborated by skeptic-f8, test-strategy-auditor)

### task 13: the recall floor is placed against a report shape with no recall field `[test-strategy-auditor-f3]`
- **Plan section:** Layer 3 task 13 (Recall floor + all-findings number)
- **Claim:** Task 13 adds the recall floor to `reachability-corpus.ts`/`evaluateReachabilityGates`, but that file's `RepoResultLike`/`CorpusReport` shapes carry only `ground_truth_matched` — no `recall_pct`/`avg_recall_pct`. Recall is computed exclusively in `oss-corpus.ts` and is not serialized into the per-repo objects the gate evaluator reads. The floor cannot be evaluated where the plan puts it.
- **Suggested patch:** Task 13 must: (1) confirm `oss-corpus.ts` serializes `recall_pct` per repo and `avg_recall_pct` into `report.json` — if absent, add it as an explicit sub-task; (2) extend `RepoResultLike`/`CorpusReport` with the recall fields; (3) define the floor precisely (fail if `avg_recall_pct < 90` OR any Layer-3-marked CVE has `observed===false`); (4) add a unit test in the gate test file for an unobserved Layer-3 CVE tripping the floor.
- **Flagged by:** test-strategy-auditor `[SOLO]`

### task 4: the dual-scope tiebreak SELECT does not fetch the columns it tiebreaks on `[test-strategy-auditor-f4]`
- **Plan section:** Layer 1 task 4 (Deterministic dual-scope PDV attachment)
- **Claim:** Task 4 says `pdByNameVersion` must prefer the production-scope row (`environment ≠ 'dev'`, or `is_direct=false && source='transitive'`), but `dep-scan.ts`'s `pdByNameVersion` is built from `.select('id, name, version')` — none of `environment`/`is_direct`/`source` are fetched. Task 14's PGLite test would pass against a fix that cannot discriminate.
- **Suggested patch:** Amend task 4 to require: widen the `dep-scan.ts` `project_dependencies` SELECT to `id, name, version, environment, is_direct, source`; change the map value to an object; on a `name@version` collision keep the row with `environment !== 'dev'` (covers both `'prod'` and `null`), deterministic tiebreak on `id` if still tied. Task 14 must seed the dev row first in one assertion and the prod row first in a second — proving order-independence — and assert the resolved `project_dependency_id` equals the prod row's id.
- **Flagged by:** test-strategy-auditor + skeptic-f4 + architect-f4 (three personas, independently) `[SOLO×3 — de-facto consensus]`

## P1 — High-Priority Gaps

- **architect-f2** [task 9] — one-hop parent-import check demotes nothing; needs an ancestor-closure predicate. (Folded into the task-9 P0 patch.)
- **architect-f3** [Data Model] — `environment` flips `dev↔null` run-to-run when `directSetTrusted` varies — non-monotonic depscore on a flaky cdxgen signal. **Patch:** make the transitive-dev mark sticky — when `!directSetTrusted`, do not overwrite an existing `environment='dev'` back to `null`; carry forward the prior run's value.
- **architect-f4 / skeptic-f4** [task 4] — task 4 under-specified (SELECT, map value shape, comparator). Folded into the task-4 P0 patch.
- **architect-f6** [task 6 / Risks] — the Layer-0 maven go/no-go checks graph *trust* but not graph *completeness*: cdxgen may omit `<scope>test</scope>` transitive components entirely, so `directSetTrusted=true` with test transitives absent still yields maven Gate 2 = 0%. **Patch:** the Layer-0 dump must also count test/provided-scope components actually present in `parseSbom()` output.
- **skeptic-f2** [task 10 / Overview] — the plan never states the precision fix *lowers* Gate 1 from 66.13% to ~63% before Layer 3 recovers it; the real lift required is ~12pp, not 9pp. **Patch:** state the numeric path (66% → ~63% after honest precision fix → ≥75%) and recompute the Layer-3 N target against the ~63% floor.
- **skeptic-f1** [task 11] — the `(14+N + 0.5·12)/(31+N)` target math bakes in the precision-fix demotions + ejs promotion without showing the derivation. **Patch:** add a "Baseline derivation" subsection; have task 10 record the *actual* post-Layer-2 observed counts and feed them into task 11's N.
- **skeptic-f5 / test-strategy-auditor-f2 / scope-cutter-f1 / test-strategy-auditor-f1** [task 12] — the independent oracle: (a) gates nothing mechanically — "unexplained disagreement" is an undefined escape hatch; (b) "Henry or a separate agent" is not concrete and an LLM oracle is non-deterministic; (c) is a no-op for definitional devDependency cases — it only discriminates on transitive-dev / heuristic cases. **Patch:** make the oracle a frozen committed artifact (`reachability-corpus-oracle.yaml` or an `oracle_reachability` YAML field), authored once by Henry against the call-path question only; weight the sample toward the hard cases (every transitive-dev-only dep Layer 2 marks + ≥2 heuristic prod-transitives); drop the LLM-oracle option; make a reachable-oracle-vs-unreachable-scan disagreement a hard Gate-3 failure, not a printed number.
- **skeptic-f7 / pragmatist-f6** [Risks — maven] — Success Criterion 2 hard-requires maven Gate 2 > 0%, but the `directSetTrusted=false` no-go branch has no designed fallback. **Patch:** add conditional task 0c — if petclinic's pinned graph is untrusted/incomplete, maven's contribution comes from *direct* `<scope>test</scope>` deps only (Layer 1 `collectMavenDevDeps`, no Layer 2 needed); state that direct test-scope deps alone satisfy maven Gate 2 > 0%.
- **pragmatist-f3** [task sizing] — Docker corpus reruns (tasks 5/10/15) still labelled 'S'. **Patch:** re-label 'M'; drop task 5 entirely (the plan calls it "informational, not a gate" — the `ejs` flip is covered by the Layer-1 unit test and re-measured at task 15).
- **test-strategy-auditor-f5** [Testing — snapshot] — the mechanical benign-drift assertion has no fast fixture that produces a dev-scope `module→unreachable` flip; default `test:fixtures` is 2 fixtures, not the "6/6" the plan claims. **Patch:** add a fast snapshot fixture with a direct devDependency carrying a vulnerable transitive; correct the fixture count.
- **test-strategy-auditor-f6** [task 6] — no committed cdxgen `sbom.json` fixture exists; if captured from a `directSetTrusted=false` SBOM it tests the skip path vacuously. **Patch:** sequence task 0b before task 6; capture the fixture from a verified-trusted SBOM; assert the BFS propagates ≥1 transitive-dev dep (positive assertion).
- **test-strategy-auditor-f7** [tasks 5/10/15] — maven Gate 2, the precision fix, and the recall floor are all first-verified only by the slow non-deterministic Docker corpus rerun. **Patch:** add a source-tree integration harness (no Docker) running `parseSbom` + `patchDevDependencies` + BFS against the committed `sbom.json` fixture, asserting propagation/precision outcomes directly; reserve the Docker rerun for the final gate.
- **scope-cutter-f3** [task 11] — the plan never verifies that 16-18 genuine dev/test-scope CVEs actually exist across the 3 pinned repos (express's 13 cluster on ~5 packages; padding with more advisories on the same package is correlated, not independent). **Patch:** task 0b/11 must count distinct dev-scoped vulnerable *packages* after pinning; if < ~12, surface a 75%-unreachable go/no-go (accept honest ~70% or add a repo).

## P2 — Quality Gaps

- **architect-f5** — `policy-engine.ts` reads an `is_dev_dependency` column distinct from `environment`; after Layer 2 a transitive-dev dep has `environment='dev'` but `is_dev_dependency=false` — two persisted dev flags silently diverge. Resolve in the task-8 audit.
- **pragmatist-f5** — the precision fix's `!directSetTrusted` branch is undefined (fall back to legacy heuristic, or suppress?). Pick one and write it down.
- **test-strategy-auditor-f8** — the all-findings number is computed but never gated or given a tolerance; add a soft gate (warn if `allowlistPct − allFindingsPct > 15pp`) or it is ignored diagnostics.
- **test-strategy-auditor-f9** — the "frozen pre-feature label set" is a YAML comment with no CI teeth; capture it as a committed `*-baseline.lock.yaml` and assert immutability.
- **scope-cutter-f2** — task 13's all-findings number has no ground truth; explicitly label it "informational, not gated" so it isn't misread as a second gate.
- **scope-cutter-f6** — task 6's committed SBOM fixture should be a hand-trimmed minimal graph, not a verbatim multi-thousand-line cdxgen dump.
- **pragmatist-f4** — task 4 is a pre-existing-bug fix bundled into a "classifier-only" arc; note it in STATUS so the `dep-scan.ts` change isn't a surprise.
- **skeptic-f3** — Data Model should state explicitly that the upsert UPDATEs the non-key `environment` column on conflict (confirm no `ignoreDuplicates`).
- **skeptic-f6** — Layer-0 `cloneRepo`: prefer `git init` + `fetch --depth=1 origin <ref>` (fetches only the pinned ref) over `clone --depth=1` (clones the default branch first); drop the dual `--branch` path.
- **skeptic-f8** — task 9 acceptance should be corpus-observed (jackson/rustix observed `module`), not a synthetic unit test.

## P3 — Nits & Opportunities

- **opportunity-scout-f1** — also stamp the heuristic-orphan `unreachable` branch with `{ reason, scope:'orphan', verdict:'orphan_transitive_unreachable' }` so every `unreachable` row is self-describing (one object literal).
- **opportunity-scout-f2** — `printGateReport` should emit the full-weight `unreachable`-only % directly (`unreachableCount/observedTotal`) — satisfies Success Criterion 5 in one line.
- **opportunity-scout-f3** — persist the oracle verdict as a YAML field so task 12 is a permanent gate, not a one-shot.
- **opportunity-scout-f4** — serialize `directSetTrusted` per repo into `report.json` so the maven go/no-go is a recorded signal, not an ad-hoc probe.
- **opportunity-scout-f6** — opportunistically flag any remaining moving refs in `oss-corpus.yaml` once `cloneRepo` is fixed.
- **pragmatist-f1** — only petclinic is on a moving ref; pinning it to a release tag may avoid the `cloneRepo` rewrite entirely (express/bat are already tags).
- **pragmatist-f7** — "Layer 0" is two small prerequisite tasks; folding them into Layer 3 keeps the plan at 3 layers (cosmetic).
- **architect-f7** — note in Data Model that `source` (literal manifest) and `environment` (propagated scope) are *intentionally* allowed to disagree for transitive-dev deps, so a future reader doesn't "fix" it.

## Suggested Plan Amendments

### Amendment 1 — task 9: specify the graph data path + ancestor closure (resolves architect-f1, f2)
Thread `relationships` through `ctx` into `UpdateReachabilityOptions` (or add a
`dependency_version_edges` SELECT in `updateReachabilityLevels`). Replace the
one-hop "parent imported" check with an ancestor-closure predicate reusing
Layer-2's `prodReachable` closure. Re-size task 9 S→M. Acceptance = corpus-observed
jackson/rustix `module`.

### Amendment 2 — task 13: wire the recall floor to a field that exists (resolves test-strategy-auditor-f3)
Confirm/add `recall_pct` + `avg_recall_pct` serialization into `report.json` in
`oss-corpus.ts`; extend `RepoResultLike`/`CorpusReport`; define the floor (`< 90%`
or any unobserved Layer-3 CVE); add a unit test.

### Amendment 3 — task 4: widen the SELECT, specify the comparator (resolves test-strategy-auditor-f4, architect-f4, skeptic-f4)
`dep-scan.ts` SELECT → `id, name, version, environment, is_direct, source`; map
value an object; deterministic prefer-prod comparator. Task 14 tests both
insertion orders and asserts the resolved id.

### Amendment 4 — make the oracle concrete and gateable (resolves test-strategy-auditor-f1/f2, skeptic-f5, scope-cutter-f1)
Frozen committed oracle artifact authored once by Henry against the call-path
question; sample weighted to transitive-dev + heuristic cases; LLM-oracle option
dropped; reachable-oracle-vs-unreachable-scan = hard Gate-3 failure.

### Amendment 5 — scope the maven no-go fallback (resolves skeptic-f7, pragmatist-f6, architect-f6)
Conditional task 0c: if petclinic's pinned graph is untrusted/incomplete, maven
Gate 2 is satisfied by direct `<scope>test</scope>` deps via Layer 1 alone. The
Layer-0 dump checks graph completeness, not just trust.

### Amendment 6 — honest baseline + task sizing (resolves skeptic-f1/f2, pragmatist-f3, scope-cutter-f3)
State the 66% → ~63% (post-precision-fix) → ≥75% numeric path; add a baseline
derivation; re-size the Docker reruns 'M' and drop task 5; verify ~12+ distinct
dev-scoped vulnerable packages exist across the pinned repos before committing to
the 16-18 target.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| data-path underspecification (tasks 4/9/13) | 6 | P0 | architect, test-strategy-auditor, skeptic |
| benchmark integrity (oracle, recall, baseline) | 8 | P0 | test-strategy-auditor, skeptic, scope-cutter |
| precision-fix correctness | 4 | P0 | architect, skeptic, pragmatist |
| maven Gate-2 fallback | 4 | P1 | skeptic, pragmatist, architect |
| test coverage (snapshot, fixture, offline harness) | 4 | P1 | test-strategy-auditor |
| task sizing / scope | 4 | P1 | pragmatist, scope-cutter |
| environment monotonicity / consumer drift | 3 | P1 | architect |
| opportunities | 8 | P3 | opportunity-scout, others |

## Persona Coverage Map

| Persona | R1 findings | R2 | Vote |
|---|---|---|---|
| skeptic | 8 | — | REVISE |
| pragmatist | 7 | — | REVISE |
| scope-cutter | 6 | — | REVISE |
| architect | 7 | — | REVISE |
| test-strategy-auditor | 9 | — | REWORK |
| opportunity-scout | 6 | — | REVISE |

## Recommended Next Step

**REVISE.** The rev-1 REWORK P0s are genuinely closed and the data model is sound —
this is no longer a direction problem. Apply Amendments 1-6 (a targeted rev-3 patch
pass — three task-spec corrections plus the oracle/baseline/maven-fallback
tightening), then proceed to `/implement`. A third full `/review-plan` is optional;
the remaining items are concrete patches with no architectural uncertainty left —
`/explain-plan` then `/implement` is a reasonable path once the patches are in.
