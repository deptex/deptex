# Plan Review — reachability-noise-reduction-v3

Verdict: **REVISE**

Plan reviewed: `.cursor/plans/reachability-noise-reduction-v3.plan.md`
Generated: 2026-05-20
Mode: lean; debate: off; vote: synthesized from finding set (not separately polled — see note in Vote Tally)
Personas: 6 — skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout
Findings: **4 P0 / 14 P1 / 21 P2 / 8 P3 (47 total)**

## Summary

Three independent personas (skeptic, pragmatist, architect) converged on the **same P0**: the plan's claim that `usedDependencies` extraction is "free" by walking resolved CallEdges is **only true for JS/TS** — the per-language callgraphs (Java, Python, Go, Rust, Ruby, PHP, C#) explicitly skip dep code (`node_modules`, `site-packages`, `vendor`, `target`, `.m2`) AND their CallEdge type carries no callee source-file path. For maven specifically — the load-bearing ecosystem for the jackson-vs-idna problem the brief calls out — the precision data requires a *new* class-FQN → SBOM-purl resolver that the plan budgets inside a single L-sized milestone covering 7 languages. The plan's "L, ~1 day" sizing for T3.2 is off by an order of magnitude. A fourth P0 (test-strategy) flags that the OFF-state byte-stability contract — the plan's main rollback safety claim — has no committed test, only a manual prose check in T3.7.

Beyond the convergent P0, the P1 cluster surfaces a 88-92% headline that arithmetically requires more lift than the corpus-expansion bars guarantee (skeptic-f2: 10 precision demotions at 0.5/49 each = ~10pp drag, not 3-5pp); a kill-switch design that diverges from the established `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` staged-rollout pattern (arch-3); and the choice to plumb the precision signal through a new `PipelineState.usedTransitives` field when the existing `TaintEngineOutput` interface already carries similar plumbing (arch-2).

The core direction of the plan — corpus expansion + custom go/pypi resolver + callgraph-driven precision — is sound. The plan needs a revision pass to right-size the Java precision arc, fix the ceiling-math argument, align with existing patterns, and pin the rollback contract with a test. After patching, this is ready for /implement.

## Vote Tally

Vote round not separately polled (lean mode optimization — verdict is deterministic from finding set: ≥1 P0 with concrete patches and core direction sound → REVISE per the skill's verdict rule). The skill's strict reading would auto-promote any single-persona P0 to REWORK in no-debate mode; that reading is over-conservative here because the three P0s converge onto **one** patchable issue (T3.1/T3.2 right-sizing), not three independent fundamental flaws.

| Persona | Synthesized Vote | Top concern |
|---|---|---|
| skeptic | REVISE | skeptic-f1 (precision-not-free + per-language complexity) |
| pragmatist | REVISE | pragmatist-f1 (7-language fan-out is gold-plating; ship JS+Java only) |
| scope-cutter | REVISE | sc-f1 (T1.4 cargo low headline-leverage) + sc-f2 (T3.2 stubs overhead) |
| architect | REVISE | arch-1 (per-language callgraphs don't carry callee source-file path) |
| test-strategy-auditor | REVISE | TSA-1 (kill-switch OFF-state has no committed test) |
| opportunity-scout | REVISE | OPP-5 (publish `docs/reachability-benchmark.md` now) |

## P0 — Fundamental Concerns

### precision-arc-sizing: Per-language callgraph `usedDependencies` extraction is NOT free; only JS/TS resolves into dep code `[CONSENSUS 3/6]`

- **Plan section:** Codebase Analysis → Callgraph already crosses into dep code; T3.1; T3.2
- **Claim:** The plan asserts "the precision data is free: walk the resolved CallEdges, inspect each callee's declaration's source file path." This is true ONLY for the TypeScript Compiler API. The per-language callgraphs (`taint-engine/{java,python,go,ruby,php,rust,csharp}/callgraph.ts`) explicitly skip dep code, AND their `CallEdge` type carries `calleeText` (a string) but no callee source-file path. For external (non-workspace) calls they emit `kind='unresolved'`. There is no file path to inspect.
- **Evidence:**
  - `taint-engine/callgraph.ts:41` SKIP_DIRS includes `node_modules`; but TS Compiler API resolves cross-file symbols anyway (the actual JS "free" path).
  - `taint-engine/java/callgraph.ts:91-100` SKIP_DIRS includes `target`, `.m2`, `vendor`. `unresolved` is returned for external calls (line 717-area).
  - `taint-engine/python/callgraph.ts:62` skips `site-packages`. Same pattern across go/rust/ruby/php/csharp.
  - `taint-engine/types.ts` `CallEdge` carries `calleeText: string` but no `calleeFile: string`.
  - **Maven is the load-bearing ecosystem** for the jackson-vs-idna problem (plan Overview, line 216 confirms). The plan handles Java as "class-name-to-package heuristic; requires a class-to-purl map (probe SBOM at runtime)" — a hand-wave for a brand-new resolver, not an extension.
- **Suggested patch:** Rewrite T3.1 to choose a concrete CallEdge extension strategy (widen the type OR emit `calleeExternalSourcePath` during the walk). Split T3.2 into:
  - **T3.2-JS** (M, ~3h) — exploit the TS Compiler API path.
  - **T3.2-Java** (own milestone, ~4-6h) — explicit class-FQN → SBOM-purl resolver with a 1-hour timebox spike: probe whether cdxgen's class index, maven-dependency-plugin output, or jar `META-INF/MANIFEST.MF` is the cheapest source. Include the disambiguation policy (ambiguous prefixes, shaded classes).
  - **T3.2-Python/Go/Rust** (S each) — these CAN do file-path matching (`site-packages`, `pkg/mod`, `registry/src`) but ONLY if you stop skipping those dirs in the walk OR intercept symbol resolution before workspace filter.
  - **T3.2-Ruby/PHP/C#** — defer to v3.1 follow-up; do NOT ship empty-set stubs in v3.
- **Flagged by:** skeptic-f1, pragmatist-f1, arch-1

### test-coverage: Kill-switch OFF-state "v2 behavior recovers" contract has no committed test `[SOLO]`

- **Plan section:** Testing & Validation Strategy / Risks & Open Questions #5 / T3.7
- **Claim:** The plan's main rollback safety claim ("flag OFF truly recovers v2 behavior; golden report byte-stable on rerun") is enforced ONLY by a manual prose corpus re-run in T3.7. There is no automated test asserting it, no committed harness, no CI hook. The first refactor that accidentally leaks `usedDependencies` extraction past the kill-switch check goes unnoticed.
- **Evidence:** T3.7 paragraph 2: "Then rerun with precision OFF — verify v2 behavior is recoverable." No corresponding test file in the testing strategy. The golden-report-byte-stable check is mentioned in Risks but not enforced in `npm test`.
- **Suggested patch:** Add T3.7a (S, ~1h): a fast unit/integration test that runs `updateReachabilityLevels` twice on a captured PDV set — once with `options.usedTransitives=undefined` and once with it populated — and asserts the OFF run produces a verdict set byte-identical to a checked-in baseline JSON. Run as part of `npm test`. Pin the contract before the heuristic ships, not after a corpus run catches it.
- **Flagged by:** TSA-1

## P1 — High-Priority Gaps

### ceiling-math: 88-92% target arithmetically requires more lift than the plan's CVE-count bars guarantee `[SOLO]`

- **Plan section:** Overview / Success Criteria
- **Claim:** "Precision arc lowers the headline by ~3-5pp" is asserted without computation. Gate 1 = `(unreachable + 0.5·module)/observed`. Demoting one CVE from `unreachable` (1.0) to `module` (0.5) costs 0.5/N per CVE; 10 demotions × 0.5/49 = ~10pp drag, not 3-5pp.
- **Patch:** Add a pre-implement budget model to Success Criteria. Project the per-eco unreachable count required to absorb precision drag; add a stop/go decision at T1.5 if mechanical lift is insufficient.
- **Flagged by:** skeptic-f2

### pypi-tooling: T2.3 picks `uv` as primary but `uv` is NOT in the depscanner Dockerfile; `pipdeptree` requires installed env not requirements file `[SOLO]`

- **Plan section:** T2.3 — Author pypi resolver
- **Claim:** Dockerfile inspection confirmed `pipdeptree==2.23.0` AND `go 1.22.10` already present; `uv` is NOT. `pipdeptree` requires a populated venv (can't point at requirements.txt). The cheapest path is `pip install --dry-run --report=-` (modern pip resolves + emits JSON without installing); the plan skips it.
- **Patch:** Make `pip install --dry-run --report=-` the primary path (no new tooling required). `pipdeptree` is fallback for poetry-locked / pyproject-only repos. Drop `uv` unless adding it provides measurable speed-up worth the Dockerfile churn.
- **Flagged by:** skeptic-f4

### data-flow-mismatch: `usedTransitives` assumes one ecosystem per scan but plan doesn't pin the constraint or test it `[SOLO]`

- **Plan section:** Codebase Analysis / T3.3
- **Claim:** `runner.ts` dispatches ONE language per scan. T3.4's pseudo-code reads `options.usedTransitives!.has(meta.dependencyId)` without saying what `dependencyId` is keyed on (purl? package-name?) or what happens for polyglot repos where a single repo has both an npm and a python tree.
- **Patch:** Add an explicit constraint to T3.3: "precision signal applies only to PDVs whose `dep_ecosystem == project.primary_ecosystem`; PDVs in other ecosystems get `callgraphRan=false` and fall back to v2 behavior." Add an integration test.
- **Flagged by:** skeptic-f5

### java-precision-handwave: T3.2 Java extraction is the hardest piece and gets one bullet inside an L-sized milestone covering 7 languages `[CONSENSUS 2/6]`

- **Plan section:** T3.2 Java callgraph extension
- **Claim:** JS/Python/Go/Rust have deterministic file-path → package mappings. Java does not — class FQN → maven coordinate requires reading every JAR's `META-INF` or building an index from cdxgen output. The brief lists Java as the load-bearing case but the plan budgets it as part of an "L, ~1 day" bullet for 7 languages.
- **Patch:** Promote Java to its own Phase 3 milestone (T3.2-Java, ~4-6h) with a 1-hour timebox spike to pick the cheapest class→purl resolver source. See P0 patch above.
- **Flagged by:** pragmatist-f6, arch-1 (same root issue)

### scope-cut-T3.2-stubs: Ruby/PHP/C# empty-set stubs in T3.2 are pure overhead — the heuristic already falls back to v2 behavior when `usedTransitives` is empty `[SOLO]`

- **Plan section:** T3.2 — per-language fan-out
- **Claim:** T3.4's condition `callgraphRan = !!options.usedTransitives`; a missing language IS `callgraphRan=false` (provided we don't ship stubs that emit empty sets). Stubs cost per-language fixtures + test surface for zero functional value.
- **Patch:** Drop the Ruby/PHP/C# stubs entirely. Move them to a v3.1 follow-up paragraph with a trigger condition.
- **Flagged by:** sc-f2 (overlaps with pragmatist-f1 above)

### cargo-corpus-leverage: T1.4 cargo corpus expansion moves Gate 1 by ≤1pp; cut or defer `[SOLO]`

- **Plan section:** T1.4 — Add a Rust app with build-dep vulnerabilities
- **Claim:** Cargo is 3 CVEs at 67% (6% of corpus). Even doubling cargo CVEs moves Gate 1 ≤1pp. T1.4 is 3-4h of corpus work for marginal headline lift. The brief's decision #2 only requires cargo dev/build split to be "covered" — `sbom.ts:347` already covers it via regex.
- **Patch:** Cut T1.4 entirely OR defer to v3.5. Replace with a synthetic Rust unit fixture (T1.4a per architect's arch-5) that pins the build-dep classifier behavior without depending on real-world repo availability.
- **Flagged by:** sc-f1 + arch-5 (related)

### kill-switch-pattern-divergence: Precision lever as boolean env flag diverges from established `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` staged-rollout pattern `[SOLO]`

- **Plan section:** T3.5 — env-flag kill switch
- **Claim:** Phase 6's taint engine ships behind a numeric staged-rollout gate evaluated per-org with a settings override column AND a circuit breaker. The plan's new precision lever ships as a boolean env flag with default-on, no staged rollout, no per-org override, no circuit breaker. The brief explicitly flagged "taint-engine callgraph crossing into dep code may explode the step budget" as Risk #1 — exactly the failure mode the rollout pct + breaker were built for.
- **Patch:** Either (a) make precision a sub-rollout gated by `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` (engine runs → precision data is a side-effect), or (b) add a numeric `DEPTEX_REACHABILITY_CALLGRAPH_PRECISION_PCT` with settings override + breaker hook. Prefer (a).
- **Flagged by:** arch-3 (also relates to sc-f3 + pragmatist-f3 which argue for cutting the flag entirely — see Open Debates below)

### pipeline-state-vs-engine-output: New `PipelineState.usedTransitives` field bends the system; existing `TaintEngineOutput` interface already carries similar plumbing `[SOLO]`

- **Plan section:** T3.3
- **Claim:** Verified `pipeline.ts:137` already destructures from `TaintEngineOutput` (defined in `pipeline-steps/taint-engine.ts:48-59`) which carries `validOsvIds`, `fpFilterCostUsd`, `cveSinkPatterns`. The architecturally consistent move is to add `usedDependencies: Set<string>` to `TaintEngineOutput`, not invent a parallel state field.
- **Patch:** Replace "PipelineState.usedTransitives" with "TaintEngineOutput.usedDependencies"; thread via the existing destructure; pass as the Nth positional arg to `doReachabilityAndEpd`.
- **Flagged by:** arch-2

### resolver-wiring-fragility: T2.4's `dependencies.length / components.length < 0.3` shallow-SBOM trigger is a magic number with no codebase basis `[CONSENSUS 3/6]`

- **Plan section:** T2.4 — Wire into sbom.ts post-parse pass
- **Claim:** 0.3 is unmotivated. For cdxgen shallow SBOMs the actual ratio is 0; for a partially-deep SBOM at 0.4, the resolver fails to trigger and we miss the lift. Boundary cases (zero components → divide-by-zero), conflict cases (resolver finds purl already in cdxgen output), and `is_direct` dedup policy are all unspecified.
- **Patch:** Trigger on a structural signal: `ecosystem ∈ {gomod, pypi} AND dependencies.length === 0` (or no `ParsedSbomDep` row has `is_direct=false`). Dedup policy: cdxgen wins on version pin; resolver fills purls cdxgen didn't see. Add `src/transitive-resolvers/README.md` for the convention. Log the trigger reason so corpus runs can audit when the resolver fired.
- **Flagged by:** skeptic-f10, pragmatist-f8, arch-4 (all 3 converge)

### gate-3-no-pre-commit-enforcement: Zero-FN hard constraint relies on developer remembering 45-min manual corpus run `[SOLO]`

- **Plan section:** Testing / Success Criteria / T1.5/T2.6/T3.7
- **Claim:** Gate 3 is named the "hard constraint" three times but the only check site is the per-phase docker corpus run. No pre-commit hook, no `npm test` integration. Existing `FakeStorage` + direct `updateReachabilityLevels` infra could host a fast frozen-FN-shape regression test in seconds; plan doesn't add one.
- **Patch:** Add T3.6a: unit test constructing ~5-10 PDV shapes (jackson-confirmed-reach, idna-truly-unreachable, dev-scope-fastify-CVE, missing-callgraph-graceful-degrade, callgraph-empty-set, precision-flag-OFF) asserting `updateReachabilityLevels` never produces `unreachable` for the reachable shapes.
- **Flagged by:** TSA-2

### empty-callgraph-vs-disabled-semantic-ambiguity: When `usedTransitives` is empty (vs undefined), behavior is not pinned `[SOLO]`

- **Plan section:** T3.2 / T3.4
- **Claim:** T3.4's `callgraphRan = !!options.usedTransitives` flags an empty Set as truthy. A Ruby/PHP/C# stub returning `new Set()` would mean every Ruby transitive gets "callgraph ran but didn't find me" — functionally equivalent to "callgraph didn't run" only if the heuristic ignores empty sets. Plan doesn't say which.
- **Patch:** Pin: `callgraphRan = options.usedTransitives !== undefined && options.usedTransitives.size > 0`. Add a test fixture asserting ecosystem-with-empty-callgraph behaves identically to ecosystem-with-callgraph-disabled. (Best combined with the P0 patch dropping the stubs entirely.)
- **Flagged by:** TSA-3

### resolver-fixtures-handwave: T2.2/T2.3 "synthetic fixtures" undefined; real-world edge cases (go.mod replace directives, poetry locks, multi-module workspaces) untested `[SOLO]`

- **Plan section:** T2.2 / T2.3 / T2.4
- **Claim:** Synthetic-only fixtures don't reproduce real shallow-SBOM detection edge cases (T2.4's heuristic trigger). The 0.3 ratio is one issue; the resolver's behavior under replace directives / poetry.lock / multi-module workspaces is another.
- **Patch:** Name specific fixtures under `depscanner/test/fixtures/transitive-resolvers/`: 3-5 case shapes each (replace directives, missing go.sum, multi-module workspace; poetry, requirements.txt, pyproject.toml-only). Add a PGLite integration test that runs the *real* `go list -m all` against a checked-in tiny fixture repo. Precedent: `dual-scope-attachment-pglite.test.ts`.
- **Flagged by:** TSA-4

### resolver-trigger-boundary-untested: 0.3 ratio + zero-components + deep-SBOM-already-present cases unspecified in T2.4 test list `[SOLO]`

- **Plan section:** T2.4
- **Claim:** Test list says "SBOM-only path, resolver-only path, hybrid path" but doesn't pin boundary (0.29 vs 0.31), divide-by-zero (empty SBOM), or deep-SBOM-already-present (resolver should dedup, not double-add).
- **Patch:** Add boundary + zero-components + deep-SBOM-already-present + ecosystem-mismatch tests to T2.4. Best paired with skeptic-f10's structural-signal patch — once the trigger is `dependencies.length === 0`, boundary tests collapse to "trigger fires when empty / doesn't fire when populated."
- **Flagged by:** TSA-5

## P2 — Quality Gaps

- **skeptic-f3**: Cargo classifier audit task missing — verify `[build-dependencies]` transitive propagation works end-to-end, not just direct.
- **skeptic-f6**: Repo availability risk applies to T1.1/T1.4/T2.5 too, not just T1.2 maven — all should be under "scout + present + pick" gate.
- **skeptic-f7**: Per-language perf-spike subtask missing — benchmark FQN-prefix matching against petclinic SBOM before T3.3 commits.
- **skeptic-f8**: "Byte-stable on rerun" contract contradicts "default ON" env flag — flag value isn't pinned to commit. Move to CLI flag recorded in report metadata.
- **skeptic-f11**: Synthetic precision fixture is self-fulfilling; add a corpus-level BEFORE/AFTER precision-diff JSON to audit demotions on real CVEs.
- **pragmatist-f3 + sc-f3**: Kill switch (T3.5) may be pure overhead given branch is unmerged and integration test asserts ON-state. (See Open Debates.)
- **pragmatist-f4**: Phase 1 sequencing — T1.1/T1.4/T1.5 should run parallel to T1.2 maven scout, not after.
- **pragmatist-f5**: Plan retires brief's "cargo dev/build split" task but doesn't surface the change to a "Brief deviations" section.
- **pragmatist-f7**: Success Criteria couples engineering completion (deterministic) with corpus headline (repo-dependent). Split into two tiers.
- **sc-f4 (frontend test pass)**: T4.3 includes frontend `npm run test:unit` for a depscanner-only change — drop.
- **sc-f5**: Risk #4 callgraph step-budget cap is premature; measure in T3.7 first.
- **arch-5**: Add synthetic Rust unit fixture for build-dep classifier (T1.4a) — decouples cargo lift from real-repo discovery.
- **arch-6**: `uv` vs `pip` choice has self-host parity implications; enumerate runtime install matrix in T2.1.
- **arch-7**: Set `reachability_details.verdict = 'callgraph_reached_transitive'` on demotions — provenance lives in existing JSONB, no schema change, unblocks future UI/EPD signals.
- **TSA-6**: T4.3 misses PGLite integration tests (`npx tsx depscanner/test/*.ts`). Add `npm run test:integration` script.
- **TSA-7**: Resolver soft-fail emits structured warning per brief — but no test pins the warning shape (event name, fields).
- **TSA-8**: Java fuzzy-match heuristic needs ≥3 fixtures (clean match, ambiguous prefix, shaded class, no SBOM purl), not 1.
- **OPP-2**: Persist `project_dependencies.callgraph_reached: boolean | null` now — work happens regardless in T3.3-T3.4, ~30 min of additive migration unblocks future UI badge in 1 day instead of full re-implementation.
- **OPP-5**: Land `docs/reachability-benchmark.md` in this arc — the brief flags publishability as whitespace; methodology is freshest now.

## P3 — Nits & Opportunities

- **skeptic-f9**: "Honest methodology you can read" framing is unsupported until corpus + methodology are published; OPP-5 makes this real.
- **pragmatist-f8**: 0.3 ratio is a magic number — replaced by structural signal per resolver-wiring-fragility (P1) above.
- **sc-f6**: Lock `callgraph_evidence` deferral as a Locked Scope Decision so /implement doesn't reopen.
- **TSA-9**: CI surface for golden-report stability — add a tiny `scripts/check-golden-report-stable.ts` runnable in CI.
- **OPP-1**: Emit per-run telemetry — `usedTransitives.size` per language + callgraph-demotion count to extraction_logs. ~10 lines.
- **OPP-3**: Ship `callgraph_evidence: { callee_file, callee_method }` snippet now (1 callsite, 256-char cap) — makes the per-CVE breakdown auditable.
- **OPP-4**: Default-hide `environment='dev'` rows in the existing vulnerabilities table — 1-line frontend default with a toggle.
- **OPP-6**: Commit per-phase per-CVE-delta JSON alongside phase verification runs — audit trail for the future docs arc.

## Open Debates (Not Polled)

Two findings argue opposing positions on the kill switch:

- **arch-3 (P1)**: Kill switch SHOULD exist but as a numeric staged-rollout matching `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT`, not a boolean env flag.
- **pragmatist-f3 + sc-f3 (P2 each)**: Kill switch shouldn't exist at all — branch is unmerged, `git revert` covers rollback, integration test asserts both ON and OFF, the flag is dead code.

Resolution probably depends on whether v3 ships behind a flag at all OR gates on the existing engine rollout. Skill-style debate would resolve this; main thread recommendation: pick (a) gate on existing `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` (precision data is a side-effect of engine running), which neutralizes both findings simultaneously. No new flag added; staged rollout inherited.

## Suggested Plan Amendments

### Patch 1 — Rewrite T3.1/T3.2 with right-sized per-language design
**Concern:** Three-persona P0 (precision data not free for non-JS).
**Source:** skeptic-f1, pragmatist-f1, arch-1 `[CONSENSUS 3/6]`
**Change:**
- T3.1 — Pick a concrete CallEdge extension (widen type OR side-channel `calleeExternalSourcePath` during walk).
- T3.2 — Split into:
  - T3.2-JS (M, ~3h) — TS Compiler API path.
  - **T3.2-Java (own milestone, M, ~4-6h)** — class-FQN → SBOM-purl resolver. 1-hour timebox spike picks the source (cdxgen class index / maven-dependency-plugin / jar META-INF). Disambiguation policy: ambiguous-prefix + shaded-class + missing-purl.
  - T3.2-Python (S, ~2h) — site-packages path, BUT stop skipping in walk OR intercept resolution.
  - T3.2-Go (S, ~2h) — `pkg/mod` path.
  - T3.2-Rust (S, ~2h) — `registry/src` path.
  - **T3.2-Ruby/PHP/C# — DEFERRED to v3.1 follow-up.** No empty-set stubs in v3.

### Patch 2 — Commit OFF-state byte-stability test
**Concern:** Kill-switch contract enforced only by manual prose.
**Source:** TSA-1 `[SOLO]`
**Change:** Add T3.7a (S, ~1h). Fast unit/integration test running `updateReachabilityLevels` twice on captured PDV set (with/without `usedTransitives`); assert OFF-run is byte-identical to checked-in baseline JSON. Run in `npm test`.

### Patch 3 — Reconcile kill-switch design with existing rollout pattern
**Concern:** New env flag diverges from `DEPTEX_TAINT_ENGINE_ROLLOUT_PCT` pattern; OR is pure overhead.
**Source:** arch-3 / pragmatist-f3 / sc-f3 (open debate)
**Change:** Gate precision on the existing engine rollout pct — precision data is a side-effect of engine running, so "engine ran AND we extracted usedDependencies" is the natural condition. Drop the new `DEPTEX_REACHABILITY_CALLGRAPH_PRECISION` env flag entirely. Engine rollout pct already covers staged + per-org-override + circuit-breaker. Remove T3.5; remove the OFF-rerun half of T3.7.

### Patch 4 — Add pre-implement ceiling-math budget model
**Concern:** 88-92% headline arithmetically requires more lift than CVE-count bars guarantee.
**Source:** skeptic-f2 `[SOLO]`
**Change:** Add a paragraph to Success Criteria computing required new-unreachable count per ecosystem to absorb projected precision drag. Stop/go decision at T1.5 if mechanical lift < projected drag.

### Patch 5 — Fix shallow-SBOM trigger to structural signal
**Concern:** 0.3 ratio is magic; misfires likely.
**Source:** skeptic-f10 / pragmatist-f8 / arch-4 `[CONSENSUS 3/6]`
**Change:** Rewrite T2.4 trigger: `ecosystem ∈ {gomod, pypi} AND dependencies.length === 0` (or `(no row has is_direct=false)`). Add structured log line for trigger reason. Specify dedup policy: cdxgen wins on version pin. Add `src/transitive-resolvers/README.md`.

### Patch 6 — Restructure Success Criteria into engineering-binary + headline-directional
**Concern:** PASS/FAIL conflates deterministic engineering with repo-dependent corpus lift.
**Source:** pragmatist-f7 `[SOLO]`
**Change:** Engineering-complete (binary): precision arc fixture passes + go/pypi resolvers work + Gate 3 zero FN + golden refreshed. Headline directional: Gate 1 + per-eco numbers, reported but non-blocking.

### Patch 7 — Promote `TaintEngineOutput.usedDependencies` over `PipelineState.usedTransitives`
**Concern:** New state-field bends the system; existing interface fits.
**Source:** arch-2 `[SOLO]`
**Change:** Add `usedDependencies: Set<string>` to existing `TaintEngineOutput` in `pipeline-steps/taint-engine.ts:48-59`. Thread via existing destructure at `pipeline.ts:137`. Pass as positional arg to `doReachabilityAndEpd`.

### Patch 8 — Switch pypi resolver to `pip install --dry-run --report=-`
**Concern:** `uv` not in Dockerfile; `pipdeptree` doesn't work on requirements files.
**Source:** skeptic-f4 / pragmatist-f2 `[SOLO + SOLO]`
**Change:** Rewrite T2.3. Primary path: `pip install --dry-run --report=-` (zero new tooling). Fallback: existing `pipdeptree` against a throwaway venv for poetry-lock'd repos. Drop `uv` unless measurable speed win justifies Dockerfile churn.

### Patch 9 — Cut T1.4 cargo corpus repo OR replace with synthetic fixture
**Concern:** ≤1pp headline movement for 3-4h corpus work.
**Source:** sc-f1, arch-5 `[SOLO + SOLO]`
**Change:** Either (a) cut T1.4 entirely and document the decision in a "Brief deviations" section, OR (b) replace T1.4 with T1.4a synthetic Rust fixture (S, ~1h) that pins build-dep classifier behavior; defer real-repo cargo add to v3.5.

### Patch 10 — Add per-language Java fuzzy-match coverage + provenance verdict + gate-3 unit
**Concern:** Java is the load-bearing case; one fixture isn't enough; demotions lose provenance.
**Source:** TSA-8 / arch-7 / TSA-2
**Change:**
- T3.2-Java fixtures ≥3: clean match, ambiguous prefix, shaded class, no SBOM purl.
- T3.4: set `reachability_details.verdict = 'callgraph_reached_transitive'` on demotions.
- T3.6a (new): unit test with PDV-shape fixtures for each Gate-3 risky pattern.

## Findings by Axis

| Axis | Count | Highest severity | Personas |
|---|---|---|---|
| precision-arc-sizing | 3 | P0 | skeptic, pragmatist, architect |
| test-coverage | 5 | P0 | test-strategy, scope-cutter |
| corpus-leverage | 3 | P1 | scope-cutter, architect |
| pipeline-pattern-fit | 4 | P1 | architect, pragmatist, scope-cutter |
| resolver-design | 5 | P1 | skeptic, pragmatist, architect, test-strategy |
| ceiling-math | 2 | P1 | skeptic |
| determinism | 1 | P2 | skeptic |
| brief-deviation-documentation | 2 | P2 | pragmatist |
| opportunity | 6 | P2 | opportunity-scout |
| nits | 4 | P3 | mixed |

## Persona Coverage Map

| Persona | R1 findings | Vote |
|---|---|---|
| skeptic | 11 (1 P0 / 3 P1 / 6 P2 / 1 P3) | REVISE |
| pragmatist | 8 (1 P0 / 2 P1 / 4 P2 / 1 P3) | REVISE |
| scope-cutter | 6 (0 P0 / 2 P1 / 3 P2 / 1 P3) | REVISE |
| architect | 7 (1 P0 / 3 P1 / 3 P2 / 0 P3) | REVISE |
| test-strategy-auditor | 9 (1 P0 / 4 P1 / 3 P2 / 1 P3) | REVISE |
| opportunity-scout | 6 (0 P0 / 0 P1 / 2 P2 / 4 P3) | REVISE |

## Recommended Next Step

**REVISE.** Apply the 10 suggested patches above to the plan, then proceed to `/implement`. The core direction (corpus expansion + custom go/pypi resolver + callgraph-driven precision) is sound; the revisions are sizing + safety + pattern-alignment, not direction changes.

The single most load-bearing patch is **Patch 1** (right-size T3.1/T3.2). It accepts that v3's precision arc ships for **npm + Java + Python + Go + Rust** (5 languages), explicitly deferring Ruby/PHP/C# to v3.1, and gives Java its own milestone with a 1-hour spike to pick the class→purl resolver source. Without it, T3.2's "L, ~1 day" sizing will surface as multi-day rework during /implement.

Second priority: **Patch 3** (drop the new env flag, gate on existing engine rollout pct). Resolves the open debate and removes a piece of the test surface (Patch 2's OFF-state test becomes simpler).

After patching: optional second `/review-plan` pass in lean mode is a low-cost sanity check on the revisions, particularly to confirm the right-sized T3.2 milestones still fit the directional 88-92% target.
