# Reachability Noise-Reduction v3 — Feature Brief

## Problem Statement

The depscanner reachability classifier currently reports **79.6% noise reduction** (Gate 1) on a 49-CVE / 4-repo corpus, with severe per-ecosystem imbalance: npm 86%, maven 10%, cargo 67%, **go/pypi 0% measurable**. Two structural issues hold the headline back:

1. **Coverage holes**: cdxgen emits direct-deps-only SBOMs for go/pypi without `--deep` (which recursively git-clones every dep and blows the step budget), so there are no transitive deps to classify `unreachable`. Maven's `dependencies` graph is too shallow to walk for transitive dev-only propagation (the BFS was disabled in v2 because it over-marked production deps).
2. **Precision misses**: the M4 heuristic (`transitive + files_importing_count===0 → unreachable`, with a framework-embedded-runtime exception) can't distinguish a transitive that is genuinely never exercised (`idna` in `bat`) from one that is called via a framework's request handler (`jackson-core` in `petclinic`). Both look identical to the classifier; both get flagged `unreachable`. The first is correct; the second is a precision miss inflating the metric dishonestly.

v3 lifts the headline toward **~88-92% honest** by (a) closing the coverage holes (custom go/pypi transitive resolver, maven app swap, cargo dev/build split), and (b) tightening precision with a prod-transitive callgraph pass (extend the existing taint-engine callgraph to demote called-but-not-imported transitives to `module`).

## Current State in Deptex

**Pipeline.** `depscanner/src/pipeline.ts` runs the extraction pipeline; `dep-scan.ts` produces the PDV set; `reachability.ts::updateReachabilityLevels` classifies each PDV into `confirmed | data_flow | function | module | unreachable`. Tiered weights in `depscanner/src/lib/depscore.ts` and `backend/src/lib/depscore.ts`.

**SBOM ingestion.** `depscanner/src/sbom.ts::parseAndPatchSbom` parses cdxgen output. `collectMavenDevDeps`, `collectCargoDevDeps`, `collectNpmDevDeps` extract scope-classified direct deps; `patchDevDependencies` BFS-propagates dev scope across the SBOM `dependencies` graph (npm + cargo only; maven disabled per v2 deviation).

**Corpus harness.** `depscanner/scripts/reachability-corpus.ts` runs the corpus YAML, computes 3 gates, validates against `reachability-corpus-baseline.lock.yaml` (frozen labels) and `reachability-corpus-oracle.yaml` (independent verdicts). Golden report at `scripts/reachability-corpus.golden-report.json`.

**Current corpus** (`scripts/reachability-corpus.yaml`):
- `express 4.18.2` — 36 CVEs, npm
- `spring-petclinic@c7ee170` — 10 CVEs, maven
- `bat v0.24.0` — 3 CVEs, cargo
- `fastify v4.26.0` — 12 dev-scope CVEs across 10 distinct packages, npm

**v2 carry-overs (knowingly punted):** oracle independence (one author), jackson-vs-idna precision (mild over-classification, not Gate-3 fail), v2 branch unmerged. v3 picks up jackson-vs-idna; defers oracle independence and PR sequencing.

**Branch.** Continue on `worktree-reachability-noise-reduction` — v3 commits stack on top of v2's tip `2b02e19`. No new branch.

## Competitive Landscape

### Endor Labs
Claims **97% noise reduction** ([appsecsanta review](https://appsecsanta.com/endor-labs)); customer-average **92%**. Function-level call graph from app entry-points. JavaScript phantom-dependency detection added 2024 ([Endor blog](https://www.endorlabs.com/learn/javascript-typescript-nodejs-reachability-phantom-dependency-detection)). **Does not publish methodology, corpus, or false-negative rate.** Marketing number; cannot be cross-verified.

### Snyk
No published noise-reduction percentage ([Snyk docs](https://docs.snyk.io/manage-risk/prioritize-issues-for-fixing/reachability-analysis)). Emphasizes coverage breadth (>99% of applicable vulns reachable-analyzable for Java/JS/Python/C#). Acknowledges "trade-off between accurate results, minimizing false positives, and recall rates." Conservative published positioning vs. competitor marketing.

### Socket (Coana acquisition)
**Tiered** model ([Socket docs](https://docs.socket.dev/docs/reachability-analysis)):
- **Tier 3 (dependency-level)**: up to **35%** FP reduction
- **Tier 2 (precomputed reachability)**: up to **80%** FP reduction
- **Tier 1 (full application reachability)**: up to **90%** FP reduction

Explicitly different depth-vs-cost tiers. Six ecosystems by end of 2024.

### Semgrep
Whitepaper ([Semgrep reachability](https://semgrep.dev/blog/2025/what-you-should-know-about-dependency-reachability-in-sca/)) advocates dataflow reachability over function-level. No published numbers. "100 alerts vs 5 actionable" is their pitch framing.

### Coana benchmarking research
Deliberately avoids common benchmarks because **vendors game them** ([Coana article](https://www.coana.tech/resources/article/how-to-evaluate-an-sca-with-reachability-benchmarking-hard-to-analyze-language-features)). Recommends testing on your own corpus — which is exactly what `reachability-corpus.yaml` is. False-negative rate is the right axis to watch, not false-positive rate.

## Landscape Synthesis

| Layer | Status | Who has it |
|---|---|---|
| Dependency-level reachability (just "is it imported") | **Table-stakes** | Everyone (Snyk, Socket Tier 3, Dependabot, Mend) |
| Dev/build-scope classification | **Frontier (uneven)** | Snyk implicit, Socket implicit; **methodology unpublished** |
| Function-level call graph through app source | **Frontier** | Endor, Socket Tier 1, Semgrep, Deptex taint engine (Phase 6) |
| Prod-transitive callgraph precision (jackson-vs-idna) | **Whitespace** | No vendor publishes methodology |
| Published held-out corpus + frozen baseline + oracle | **Whitespace** | No vendor publishes |

**Deptex position today:** at parity with the honest band (~80%); ahead on methodology transparency (the corpus + lock + oracle is publishable); behind on raw marketing number (Endor's 97%); whitespace in honest reproducible reachability benchmarking.

**Feasibility verdict.** Corpus expansion is mechanical and low-risk (days). Custom go/pypi resolvers are well-understood (`go list -m all` and `pipdeptree` are the obvious paths). Taint-engine callgraph extension to mark prod-transitives is moderate (~1 week) and reuses existing infra. Cargo dev/build split is a small ecosystem-correctness win (~half day). The ~85-92% honest ceiling on a *representative* corpus is real — pushing above means either (a) corpus engineering that drifts from customer reality, or (b) Endor-style marketing on a proprietary corpus. v3 targets the top of the honest band.

**Top three risks:**
1. **Taint-engine callgraph crossing into dep code may explode the step budget.** Mitigation: cap depth, sample, or only resolve the deps in the SBOM rather than walking every file.
2. **Custom go/pypi resolver pulls in tooling that may not work in container env.** Mitigation: probe `go` / `pip` availability in depscanner Dockerfile; fall back to `unreachable` if resolver fails.
3. **Maven corpus swap is repo-availability-dependent.** Need a maven app with vulnerable test-scope deps at a tagged ref. Mitigation: scout 2-3 candidates, prefer apps with active vulnerability disclosures already published.

## User Stories

- **As Deptex (the team)**, I want a defensible noise-reduction headline number with published methodology, so positioning vs Endor/Socket/Snyk isn't just a marketing-claim arms race.
- **As a customer evaluating SCA tools**, I want to read how Deptex's reachability works on a corpus I can inspect, so I can trust the % isn't gamed.
- **As a Deptex pipeline maintainer**, I want the corpus to surface real classifier regressions early via Gate 3, so we don't ship false-negative regressions to prod.

(There is no end-user UI surface in this arc — it's a pipeline + corpus arc. The headline number surfaces in marketing copy and future docs only.)

## Locked Scope Decisions

1. **Headline target: ~88-92% honest noise reduction (Gate 1).** Rationale: top of the honest band per the metric's natural ceiling. Above Snyk's published positioning; below Endor's unverifiable 97% but with published methodology. (Henry: "as good as possible.")

2. **All five ecosystems in scope.** npm dilution (1 more app), maven app swap, cargo dev/build split, go/pypi custom transitive resolver. Henry: "work on al[l]."

3. **Stack on `worktree-reachability-noise-reduction` (same branch).** No new branch. v3 commits go on top of v2's tip. v2 PR sequencing is deferred — Henry's call when/whether to PR. (Henry: "same branch and just work on getting the number up.")

4. **go/pypi: build our own per-ecosystem transitive resolver inside depscanner.** Not upstream cdxgen contribution. Rationale: depscanner ships in days; upstream cdxgen review cycle is weeks-to-months. Trade-off accepted: maintenance burden lives in depscanner.

5. **Precision arc (jackson-vs-idna): extend the taint-engine callgraph to produce a `used_dependencies: Set<purl>` and demote called-but-not-imported transitives from `unreachable` to `module`.** Reuses existing taint-engine infra rather than building a parallel analysis. Will LOWER headline number by ~3-5pp (jackson and similar move from heuristic-unreachable to module-known-used) — accepted as the honesty cost.

6. **Maven corpus: I scout 2-3 candidate apps with vulnerable test-scope deps, present with predicted Gate-1 lift, you pick.** No commitment to a specific repo yet.

7. **Acceptance gates: directional, not formally tightened.** Gate 1 informal target ≥88%. Gate 2 (every ecosystem >0%) and Gate 3 (zero false negatives) carry forward from v2 unchanged. (Henry: "just make it working and as good as possible.")

8. **Out of scope for v3 (deferred):**
   - Oracle independent review (still one-author from v2)
   - Socket-style tiered UI / dashboard publishing
   - Cargo build-dep classification (kept in scope per #2 above — clarification: covered in this arc as a sub-task of the cargo work)
   - Snyk-style "hide dev by default" UI surface
   - Multi-hop maven graph upstream fix (cdxgen contribution)

## Data Model

**Likely no schema changes.** The precision arc piggybacks on existing `project_dependencies.environment` and the heuristic's runtime classification. Plan-feature should verify:

- `taint-engine`'s callgraph output already lives in memory during the run; the prod-transitive marking can be a post-pass that updates `project_dependencies.environment` or a new in-memory flag consumed by `updateReachabilityLevels`.
- If a new column is needed (e.g., `project_dependencies.callgraph_reached: boolean` to persist the per-run finding), it's additive and ships with a `schema:dump` refresh.

Plan-feature will decide. Default to in-memory; only add a column if downstream consumers (frontend, AI tools) need it.

## API Endpoints

None. v3 is a pipeline + corpus change. The corpus harness CLI gains no new endpoints; existing `npm run scan:oss-corpus` and `npm run test:reachability-corpus` continue to work.

## Frontend Surface

None in v3. (A future arc could publish a benchmark dashboard page Socket-style; explicitly deferred.)

## User Flows

**Maintainer flow (CI / weekly run):**
1. Maintainer runs `DEPTEX_SKIP_OPTIONAL_SCANS=1 npm run scan:oss-corpus -- --repos=scripts/reachability-corpus.yaml --output=oss-corpus-runs/v3-trial-N --parallel=2 --no-rule-gen --scan-timeout=900`
2. Maintainer runs `npm run test:reachability-corpus -- --report=oss-corpus-runs/v3-trial-N/report.json`
3. Output: Gate 1 % + Gate 2 per-ecosystem + Gate 3 false-negatives + baseline-lock diff + oracle diff
4. v3 PASS condition: Gate 1 ≥ ~88% and Gate 2 all ecosystems >0% and Gate 3 zero FN.

**Customer-facing flow:** N/A in v3.

## Edge Cases & Failure-Mode Policy

- **Custom go/pypi resolver fails (e.g., container can't run `go list` or `pipdeptree`):** soft-fail — emit a structured warning, fall back to cdxgen's direct-deps-only SBOM. Classifier behavior matches v2 for that scan. Pipeline does NOT hard-fail.
- **Taint-engine callgraph times out / runs over step budget:** hard-fail the callgraph extension; mark all transitives by heuristic only. Don't silently inflate.
- **Maven corpus swap: candidate repo unavailable / 404 at the tagged ref:** scout flow includes pinned commit SHA per candidate; fail loudly at corpus-config-load time, not at scan time.
- **Oracle diverges from baseline on a previously-locked label:** baseline lock is the source of truth; oracle update requires explicit edit. Surface the diff in the gate output but don't auto-update.

## Non-Functional Requirements

- **Per-repo scan time:** keep within the ~30-180s warm-VDB range from v2. The callgraph extension is the budget risk — cap at +30s per repo.
- **Corpus run total:** ≤ 30 min for the full corpus at `--parallel=2`. Adding go/pypi may push toward 45 min; acceptable.
- **AI cost ceiling:** none introduced by v3. The precision arc is deterministic.
- **Determinism:** every gate output must be byte-stable across re-runs given the same SBOM + worktree. The callgraph extension is deterministic by construction; the custom resolvers must be deterministic.
- **Backward compat:** v2's golden report stays valid (re-running v2 commits → same numbers). v3 commits invalidate the golden report; refresh in the same commit.

## RBAC Requirements

None. Pipeline-internal arc.

## Dependencies

- v2 branch tip `2b02e19` (already on `worktree-reachability-noise-reduction`)
- Taint-engine callgraph infrastructure (Phase 6 + 6.5 — shipped)
- cdxgen behavior unchanged (no upstream contribution)
- `go` runtime + `python` + `pipdeptree` available in depscanner Dockerfile (need to verify or add)
- VDB cache still resident at `~/.deptex/vdb` (~55GB; v2 mounted via `bin/deptex-scan`)
- `DEEPINFRA_API_KEY` not required for v3 (no AI calls)

## Success Criteria

- **Gate 1 ≥ 88%** on the v3 corpus (informal target per Henry's framing)
- **Gate 2** every ecosystem >0% noise reduction (carries from v2)
- **Gate 3** zero false negatives (carries from v2)
- **go/pypi measurable** (non-zero transitive deps in SBOM for at least one repo per ecosystem)
- **maven ≥ 40%** noise reduction (the post-swap target if a viable repo lands)
- **Precision pass shipped** — taint-engine callgraph demotes called-but-not-imported transitives; jackson-style cases verified by fixture
- **Golden report refreshed** to v3 state at branch tip
- **Branch state:** ready to PR (Henry's call on timing)

## Open Questions

- **(blocks /plan-feature)** None.
- **(can defer to /implement)** Which maven app exactly — needs the scouting pass during /implement's M0. Candidates likely include spring-petclinic at an older tag, github.com/Mastercard/openapi-validator-tests, or a Vul4J-derived sample.
- **(can defer to /implement)** Whether the precision arc needs a new column on `project_dependencies` or can stay in-memory. Default: in-memory.
- **(informational)** Whether to publish the corpus + methodology in a public benchmark doc. Future arc.

## Recommended Next Step

`/plan-feature` against this brief. Plan should:
- Order the work by risk: cargo dev/build split FIRST (smallest, ecosystem-correct win), then go/pypi resolver, then maven repo swap + corpus expansion, then the precision arc, then re-gate.
- Treat the precision arc as a single milestone with a hard rollback (env flag `DEPTEX_REACHABILITY_CALLGRAPH_PRECISION=on`) so it can be gated independently if it tanks numbers unexpectedly.
- Schema:dump unnecessary unless a column is added; verify during plan.
- Branch stays `worktree-reachability-noise-reduction`.
