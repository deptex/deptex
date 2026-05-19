# Reachability Noise Reduction v2 — Dependency-Scope Tracking — Implementation Plan

> **Revision 3 (2026-05-18)** — patched after the second `/review-plan` returned
> REVISE (5/6). Rev 2's data-model rewrite was confirmed sound; rev 3 closes three
> task-level data-path P0s (tasks 4/8/12) plus the oracle, baseline-honesty and
> maven-fallback P1s. Rev-3 changes are marked **[R3]**. Reviews:
> `.cursor/plans/review-reachability-noise-reduction-v2.md`.

## Overview

The M4 corpus passes 3/3 gates at **66.13%** corpus-wide noise reduction, but the
honest decomposition is weaker: full-weight `unreachable` verdicts account for only
~42%. This arc lifts the number to **≥75%** legitimately — by making the
reachability classifier recognise **dependency scope** (dev/test/build vs runtime)
instead of reverse-engineering it from the brittle `is_direct + files_importing_count`
heuristic. A devDependency's vulnerable code is, by definition, not on the
production call path; classing it `unreachable` (depscore weight 0.0) is a
structural fact — the Snyk `--dev` / Dependabot `dependency-type` approach.

**[R3] Honest numeric path.** The arc does not climb monotonically from 66%. The
Layer-2 precision fix demotes two currently over-aggressive `unreachable` verdicts
(jackson-core, rustix) to `module`, which *lowers* Gate 1 to **~63%** before Layer 3
recovers it. So the real lift Layer 3 must deliver is ~12pp (63→75), not 9pp.
This is the correct, honest cost of removing false positives; the plan is sized
against the ~63% floor, not the 66% headline.

**Mechanism (rev 2, retained).** Dev-scope routes through the existing
`environment` column — a plain (non-key) column already derived from `source`
(`deps-sync.ts:153`) and already the system's dev-signal (`teams.ts:2708`
`envWeight`). `source` stays the literal manifest declaration; `environment`
carries the propagated scope; the classifier reads `environment`. Row identity is
untouched (`environment` is not in the upsert conflict key).

Four layers plus close-out: (0) make the corpus reproducible and run the maven
go/no-go; (1) classifier reads `environment`, dev-scope ⟹ `unreachable`, plus a
cargo dev-dep collector and the dual-scope attachment fix; (2) transitive dev-only
propagation over the cdxgen dependency graph, feeding `environment`, plus a
graph-threaded precision fix; (3) corpus expansion + independent-oracle validation
+ a recall floor.

No DB migration. No API. No frontend page. No runtime LLM call.

## Competitive Research & Design Rationale

Scope-aware reachability is industry-standard; Deptex is behind on it. Snyk's
`--dev` is opt-in (dev deps dropped from `snyk test` by default); GitHub Dependabot
exposes `dependency-type` and down-ranks dev-only alerts; Socket separates
"production reachability" from total surface; Endor Labs' published 80-90% noise
reduction leans on never counting test/build deps as runtime-reachable. The
standard rule: a dependency reachable in the graph *only* through dev/test/build
manifests is not on the production call path. Deptex differentiates by keeping
dev-scope findings **visible** (depscore weight 0.0, not suppressed) — locked brief
decision #1.

## Codebase Analysis

### Scope data and the `environment` column (verified)

- `schema.sql:1058` — `project_dependencies` has `source text NOT NULL` and
  `environment text`. The upsert conflict key (`deps-sync.ts:173`,
  `onConflict: 'project_id,name,version,is_direct,source'`) includes `source` but
  **not** `environment`. Writing `environment` is row-identity-safe; the upsert
  UPDATEs non-key columns on conflict (no `ignoreDuplicates` is set on this
  upsert — verified).
- `sbom.ts:36-37,208,247,258` — `ParsedSbomDep.source`; `patchDevDependencies`
  flips direct dev deps; `collectDevDependencyNames` handles **npm/pypi/maven only**.
- `deps-sync.ts:153` — `environment` derived: `source==='dependencies' ? 'prod' :
  source==='devDependencies' ? 'dev' : null`.
- `pipeline-steps/sbom.ts:163` — `patchDevDependencies` call site; `parseSbom()`
  returns `relationships: ParsedSbomRelationship[]` + `directSetTrusted: boolean`.

### Data paths the rev-2 tasks assumed but that do not exist **[R3 — review findings]**

- **`reachability.ts` has no relationships graph.** `updateReachabilityLevels`
  selects `id, dependency_id, is_direct, files_importing_count` only; zero
  references to `relationships`/edges. The Layer-2 BFS lives in `sbom.ts`
  `patchDevDependencies` — a different pipeline stage. The precision fix (task 8)
  must have the graph *threaded in*; it is not "already loaded."
- **`dep-scan.ts` `pdByNameVersion` is source-blind.** Built from
  `.select('id, name, version')` — `environment`/`is_direct`/`source` are not
  fetched, so the dual-scope tiebreak (task 4) has no data to tiebreak on.
- **`reachability-corpus.ts` has no recall field.** `RepoResultLike` carries only
  `ground_truth_matched`. `recall_pct`/`avg_recall_pct` are computed in
  `oss-corpus.ts` and are not part of the report shape the gate evaluator reads —
  the recall floor (task 12) must extend both the serializer and the types.
- **`oss-corpus.ts:291-293`** — `cloneRepo` uses `clone --depth=1 --branch <ref>`;
  `--branch` rejects commit SHAs.

### The existing dev-weight mechanism (verified)

`environment === 'dev'` already drives a `0.4` depscore multiplier in
`teams.ts:2708` (`envWeight`) and `depscore.ts:85,238`. `notification-dispatcher.ts:585`
reads `environment`; `policy-engine.ts` reads a separate `is_dev_dependency`
column. The reachability-tier weight and `envWeight` are separate multiplicative
factors — a dev dep getting both `envWeight=0.4` and `reachability_level=
unreachable` (0.0) is not a contradiction; the `unreachable` tier dominates.

## Data Model

**No new tables. No migration. `source` is never written by this feature.**

Dev-scope travels via the existing `environment` column:

- `ParsedSbomDep` gains an in-memory boolean `devScoped`. `patchDevDependencies`
  sets it for direct dev deps (Layer 1) and transitive dev-only deps (Layer 2).
- `deps-sync.ts:153` `environment` becomes `d.source==='dependencies' ? 'prod' :
  (d.source==='devDependencies' || d.devScoped) ? 'dev' : null`. `source` is
  unchanged.
- **[R3] Sticky transitive-dev marking.** Layer-2 propagation only runs when
  `directSetTrusted`. To avoid `environment` flip-flopping `dev↔null` run-to-run
  on a flaky cdxgen graph (non-monotonic depscore — architect-f3): when
  `!directSetTrusted`, deps-sync must **not** overwrite an existing
  `environment='dev'` back to `null`. It reads the prior row's `environment`
  before upsert and carries a `'dev'` value forward. A dep only loses `'dev'` when
  a *trusted* run positively reclassifies it.
- **[R3]** `source` (literal manifest) and `environment` (propagated scope) are
  *intentionally allowed to disagree* for transitive-dev deps — a future reader
  must not "reconcile" them.

## API Design / Frontend Design

None. The classifier writes a structured `reachability_details` (task 3) so a
later dev-scope badge needs no schema work.

## Implementation Tasks

**Shippable unit:** Layer 0 + Layer 1 + Layer 2 + Layer 3. No smaller cut is
independently shippable (the precision fix removes maven's only Gate-2 unreachable,
so Layer 2 + the maven corpus expansion must land together).

### Layer 0 — Corpus reproducibility + maven go/no-go (M)

0a. **SHA-pinnable corpus clones** (S) — `oss-corpus.ts`. **[R3]** Rewrite
   `cloneRepo` to `git init` + `git remote add` + `git fetch --depth=1 origin
   <ref>` + `git checkout FETCH_HEAD` — one code path that accepts a branch, tag,
   or 40-char SHA, fetching only the pinned ref (no initial default-branch clone).
   Acceptance: a SHA, a tag, and a branch name all check out.

0b. **Pin every corpus repo + dump the maven graph** (S) — `reachability-corpus.yaml`.
   Replace `spring-petclinic: ref: main` with a fixed release tag/SHA. **[R3]**
   The pinned run must dump, for petclinic: `directSetTrusted`, `relationships.length`,
   **and** the count of `<scope>test</scope>`/`provided` components actually
   present in `parseSbom()` output (graph *completeness*, not just *trust* —
   architect-f6). Record the resolved dependency set.

0c. **[R3 — new] Maven go/no-go branch** (S, conditional) — if 0b shows petclinic's
   graph is untrusted (`directSetTrusted=false`) **or** incomplete (test-scope
   transitives absent), Layer 2 cannot recover maven's Gate-2 unreachables. In
   that case maven's contribution comes from **direct** `<scope>test</scope>` deps
   only — `collectMavenDevDeps` already handles these (Layer 1, no Layer 2). Direct
   test-scope maven deps alone satisfy Gate 2's "> 0% unreachable" for maven. This
   is the designed fallback; the arc does not stall. Decision recorded in STATUS.

### Layer 1 — Direct dev-scope classification (S/M)

1. **Cargo dev-dep collector** (S) — `sbom.ts`. Add `collectCargoDevDeps`
   (`Cargo.toml` `[dev-dependencies]` + `[build-dependencies]`) to
   `collectDevDependencyNames`. No composer/gem collectors this arc. Acceptance:
   unit test over a `Cargo.toml` fixture.

2. **`patchDevDependencies` sets `devScoped`** (S) — `sbom.ts`. Add
   `devScoped: boolean` to `ParsedSbomDep`; set `true` for every direct dep
   currently flipped to `source='devDependencies'`.

3. **Classifier reads `environment`; dev-scope ⟹ `unreachable`** (M) —
   `reachability.ts` + `deps-sync.ts`.
   - `deps-sync.ts:153` — amend the `environment` derivation per Data Model
     (`|| d.devScoped`, plus the sticky-carry-forward rule).
   - `reachability.ts` — add `environment` to the `project_dependencies` SELECT
     and `pdMetaMap`; add exported `isDevScoped(environment): boolean`.
   - In `updateReachabilityLevels`, before the heuristic ladder: `isDevScoped`
     ⟹ `level='unreachable'`, `details={ reason, scope:'dev',
     verdict:'dev_scope_unreachable' }`. **[R3]** Also stamp the *existing*
     heuristic-orphan `unreachable` branch with `details={ reason:'no source file
     imports this transitive dependency', scope:'orphan',
     verdict:'orphan_transitive_unreachable' }` so every `unreachable` row is
     self-describing (opportunity-scout-f1 — one object literal).
   Acceptance: a dev-scope PDV classifies `unreachable` with zero usage slices;
   `isDevScoped` unit-tested.

4. **[R3 — rewritten] Deterministic dual-scope PDV attachment** (S) —
   `dep-scan.ts`. The dev-scope feature exposes a pre-existing source-blind
   last-write-wins bug in `pdByNameVersion` (bundled here because dev-scope makes
   it a Gate-3 false-negative risk — noted in STATUS). Concretely:
   - Widen the `project_dependencies` SELECT to
     `id, name, version, environment, is_direct, source`.
   - Change the `pdByNameVersion` map value from a bare `id` string to
     `{ id, environment }`.
   - On a `name@version` collision, keep the row with `environment !== 'dev'`
     (covers both `'prod'` and `null`); if still tied, deterministic tiebreak on
     `id` ascending.
   Acceptance: covered by task 13's integration test.

### Layer 2 — Transitive dev-only propagation + precision fix (M)

5. **`patchDevDependencies` propagates over the graph** (M) — `sbom.ts`. Extend
   the signature to accept `relationships` + `directSetTrusted`. When
   `directSetTrusted`: build `parentBomRef → childBomRef[]` adjacency; `prodReachable`
   = closure from `source==='dependencies'` deps; `devReachable` = closure from
   `devDependencies`. Any `source==='transitive'` dep in `devReachable` but not
   `prodReachable` gets `devScoped=true`. When `!directSetTrusted`, skip
   propagation. Per-`bomRef` (per-version). Acceptance: unit tests over synthetic
   graphs (linear dev/prod, diamond-under-both stays prod, unwired skipped) **plus
   one test over a committed real cdxgen `sbom.json` fixture** captured at task
   0b's pin from a `directSetTrusted=true` SBOM — the test asserts the BFS
   propagates ≥1 transitive-dev dep (positive assertion, not "runs clean"). **[R3]**
   The fixture is a hand-trimmed minimal graph (relationships + ~10-15
   representative components), not a verbatim cdxgen dump.

6. **Wire relationships into the SBOM step** (S) — `pipeline-steps/sbom.ts:163`.
   Pass `relationships` + `directSetTrusted` into `patchDevDependencies`. tsc
   clean; `test:fixtures` still passes.

7. **Audit `environment` consumers** (S) — Layer 2 flips transitive-dev deps'
   `environment` `null→'dev'`. Confirm `teams.ts:2708`, `notification-dispatcher.ts:585`,
   `depscore.ts` handle the new `'dev'` transitives (down-weight is intended).
   **[R3]** Also resolve where `is_dev_dependency` (read by `policy-engine.ts`) is
   set and whether it now diverges from `environment` for transitive-dev deps —
   either derive it from the same `devScoped` signal or document in STATUS that
   policy-engine intentionally sees only manifest-literal direct-dev scope
   (architect-f5). Verification gate; document the behaviour change.

8. **[R3 — rewritten] Precision fix — graph-threaded ancestor closure** (M) —
   `reachability.ts` + `pipeline-steps/reachability.ts`. The jackson-core/rustix
   false positives come from the `transitive + filesImporting===0 ⟹ unreachable`
   heuristic firing on *used* production transitives.
   - **Data path:** thread the dependency edge graph into the classifier. Either
     (a) pass `relationships` through `ctx` into `UpdateReachabilityOptions`
     (mirroring the existing `graphTrusted`/`cveSinkPatterns` options), or (b) add
     a `dependency_version_edges` SELECT inside `updateReachabilityLevels`. Pick
     (a) — it reuses the SBOM-step data already in memory and avoids a new query.
   - **Predicate:** a production transitive keeps heuristic-`unreachable` only when
     **no ancestor in the transitive inbound-edge closure** is either imported
     (appears in usage slices) or a direct prod dep. A one-hop parent check is
     insufficient — jackson-core/rustix parents are themselves un-imported
     transitives; the reachable ancestor is several edges up. Reuse the
     `prodReachable`-style closure from task 5.
   - **`!directSetTrusted` branch:** when the graph is untrusted the closure
     cannot run — in that case **suppress** heuristic-`unreachable` for production
     transitives (floor at `module`). Accept that a genuinely-orphaned prod
     transitive caps at `module` on an untrusted-graph scan; never re-introduce
     the jackson/rustix false positive.
   Acceptance is **corpus-observed** (task 9): petclinic `CVE-2026-29062` and bat
   `CVE-2024-43806` observed as `module`, plus a synthetic-graph unit test for the
   orphaned-prod-transitive case staying `unreachable`.

9. **Layer-2 verification** (M) — rebuild the depscanner Docker image; rerun the
   corpus. Record the **actual** post-Layer-2 observed `unreachable`/`module`
   counts — these feed task 10's N target. Gate 1 will dip to ~63% (precision fix);
   maven Gate 2 may be 0% pending Layer 3 (or carried by Layer-1 direct test-scope
   deps per task 0c). Expected mid-arc.

### Layer 3 — Corpus expansion + honest validation (M/L)

10. **Add dev/test-scope CVEs to the pinned repos** (M) — `reachability-corpus.yaml`.
    **[R3] Baseline derivation** (state in the plan/STATUS): current observed
    15 unreachable / 11 module → after the precision fix 13/13 → after Layer-1
    `ejs` 14/12 → so the gate floor entering Layer 3 is `(14 + 0.5·12)/31 ≈ 64.5%`.
    Target `(14+N)/(31+N) ≥ 0.75` with the actual post-Layer-2 counts from task 9
    substituted for 14/12. **[R3]** Before committing to N, grep the pinned
    manifests and **count distinct dev/test-scope vulnerable *packages*** (not
    advisories — express's 13 cluster on ~5 packages; correlated advisories on one
    package are not independent signal). Target **16-18 net-new `unreachable` CVEs
    across ≥12 distinct vulnerable dev-scoped packages**. If fewer than ~12 distinct
    packages exist across the 3 repos, surface a go/no-go: accept an honest ~70%
    or add a 4th pinned repo. Hand-label each CVE grep-verified at the pin;
    petclinic test-scope deps must be re-grepped at the actual pinned tag (rev-1
    named deps that grep-failed).

11. **[R3 — rewritten] Independent-oracle validation** (M) — the corpus is
    hand-labelled by the same person shipping the dev-scope rule. For correctly-
    scoped deps the classifier reproducing the manifest is *definitionally true*
    and needs no validation; the genuine risk is **mis-scoped deps** (a manifest-
    dev dep actually loaded by shipped runtime code, or a manifest-prod dep that
    is dead). To catch that:
    - A committed file `reachability-corpus-oracle.yaml` (CVE id → `reachable` |
      `unreachable` + one-line call-path rationale, **no** manifest-scope field),
      authored once by Henry against the production-call-path question only.
    - **The sample is weighted to the hard cases** — every transitive-dev-only dep
      Layer 2 marks, plus ≥2 heuristic prod-transitives (the jackson/tomcat class).
      All-agree on definitional devDependency cases proves nothing; the signal is
      disagreement on the transitive/heuristic cases.
    - Drop the "or a separate agent" option — an LLM oracle is non-deterministic
      and cannot gate.
    - **Hard gate:** if the oracle labels a CVE `reachable` that the scan observes
      `unreachable`, that is a Gate-3 false negative and **fails the run** — same
      severity as a scan-observed false negative.
    - **[R3]** Freeze the pre-feature label set as a committed
      `reachability-corpus-baseline.lock.yaml`; a CI/gate check asserts every
      pre-feature `expected_reachability` still matches the live YAML (the 42%→59%
      honest-decomposition claim depends on an enforced baseline, not a comment).

12. **[R3 — rewritten] Recall floor + all-findings number** (M) —
    `oss-corpus.ts` + `reachability-corpus.ts`.
    - Confirm `oss-corpus.ts` serializes `recall_pct` per repo and `avg_recall_pct`
      into `report.json`; if absent, add it (explicit sub-task).
    - Extend `RepoResultLike` / `CorpusReport` in `reachability-corpus.ts` with the
      recall fields.
    - Define the floor: the run fails (Gate 1 is not reported PASS) if
      `avg_recall_pct < 90` **or** any CVE carrying a Layer-3 marker has
      `observed === false`.
    - `printGateReport` prints `observedTotal` next to `ground_truth_total`, the
      gate computed over **all** observed findings per repo (labelled
      *informational, not gated* — it has no ground truth), and **[R3]** the
      full-weight number `Gate 1: X% (module-weighted) | Y% (unreachable-only)`
      where `Y = unreachableCount/observedTotal` (satisfies Success Criterion 5).
    - Unit test in the gate test file: a report with an unobserved Layer-3 CVE
      trips the floor.

13. **Dual-scope Gate-3 integration test** (S) — a PGLite integration test seeding
    two `project_dependencies` rows for one package (one `is_direct` devDependency,
    one transitive prod), both linked to a reachable PDV. **[R3]** Seed the dev row
    first in one assertion and the prod row first in a second — proving
    order-independence — and assert the resolved `project_dependency_id` equals the
    **prod** row's id (not merely that the tier is reachable). Exercises task 4 +
    the dev-scope branch together.

14. **Final corpus run + gate result** (M) — rebuild image; full
    `npm run test:reachability-corpus`. Acceptance: Gate 1 ≥ 75%, Gate 2 every
    ecosystem (npm/maven/cargo) > 0%, Gate 3 zero false negatives **and zero
    oracle-disagreement false negatives**, recall ≥ 90%. Record the per-CVE table,
    both gate numbers, and the all-findings number in STATUS.

### Layer 4 — Close-out (S)

15. **STATUS + memory + golden report** (S) — append a v2 STATUS section;
    refresh `reachability_corpus_state.md` + `active_sprint.md`; commit a golden
    `report.json` for offline gate re-evaluation.

16. **Full gate** (S) — depscanner `npm run build` + `npm run test` +
    `npm run test:fixtures` + reachability unit tests, all green.

## Testing & Validation Strategy

- **Unit (jest):** `collectCargoDevDeps`; `patchDevDependencies` transitive BFS
  (synthetic linear/diamond/unwired **+ a committed trimmed real cdxgen
  `sbom.json` fixture** with a positive propagation assertion); `isDevScoped`; the
  dev-scope `unreachable` branch; the precision-fix ancestor-closure
  (jackson/rustix ⟹ `module` via corpus observation; orphaned prod transitive ⟹
  `unreachable` via synthetic graph).
- **[R3] Offline source-tree harness** — a no-Docker integration harness running
  `parseSbom` + `patchDevDependencies` + the BFS against the committed
  `sbom.json` fixture, asserting propagation/precision outcomes directly. This
  moves the maven-graph and precision-fix verification off the slow non-deterministic
  Docker corpus; the Docker rerun is reserved for the final Gate-1/2/3 number.
- **Integration (PGLite):** the dual-scope Gate-3 test (task 13, both insert
  orders); the recall-floor unit test (task 12).
- **Snapshot:** `test:fixtures` must stay green. **[R3]** Add a *fast* (non-`slow`)
  snapshot fixture with a direct devDependency carrying a vulnerable transitive so
  the `module→unreachable` flip actually occurs and the mechanical benign-drift
  assertion is exercised every CI run. Benign-drift criterion: a delta is
  acceptable **only** for deps with `environment='dev'` moving `module→unreachable`;
  any `environment≠'dev'` dep moving to `unreachable` fails. Encode as a test
  assertion, not "eyeball it."
- **e2e:** the M4 corpus, rerun against the real Docker image at the end of
  Layers 2 and 3 (`DEPTEX_SKIP_OPTIONAL_SCANS=1`, VDB cache at `~/.deptex/vdb`).
- **Validation integrity:** the independent oracle (hard Gate-3 failure on
  disagreement), the enforced baseline lock, the recall floor, and the
  all-findings number.

## Risks & Open Questions

- **[R2/R3 resolved]** `source` overload, dual-scope nondeterminism, circular
  validation, moving refs — all closed (route through `environment`; task 4
  deterministic attachment; task 11 oracle + baseline lock; Layer 0 SHA pinning).
- **[R3 resolved] maven Gate 2** — task 0b checks graph trust *and* completeness;
  task 0c is the designed fallback (direct test-scope maven deps via Layer 1) if
  the cdxgen maven graph cannot carry transitive propagation. The arc no longer
  stalls on this.
- **[R3 resolved] `environment` monotonicity** — the sticky-carry-forward rule
  (Data Model) prevents `dev↔null` flapping on a flaky `directSetTrusted`.
- **Precision-fix correctness** is the highest-uncertainty change; task 8's
  acceptance is corpus-observed (jackson/rustix must land `module`) and verified
  at task 9 before Layer 3 labelling — a go/no-go, not a final-gate surprise.
- **`module` half-credit metric** — the gain here is full-weight `unreachable`;
  task 12 prints both the module-weighted and unreachable-only numbers.
- **golang / pypi, composer, gem** — out of scope (cdxgen shallow SBOMs / no
  pinnable vulnerable repo). Follow-ups.

## Dependencies

M1–M4 of `reachability-noise-reduction` (this branch); the cdxgen CycloneDX
`dependencies` graph; the `~/.deptex/vdb` dep-scan cache; the existing
`environment` column + `envWeight` machinery.

## Success Criteria

1. **Gate 1 ≥ 75%** corpus-wide noise reduction on the pinned, expanded corpus —
   reached from the honest ~63% post-precision-fix floor, not the 66% headline.
2. **Gate 2** — every ecosystem (npm/maven/cargo) > 0% `unreachable`; maven no
   longer dependent on a single over-aggressive verdict.
3. **Gate 3** — zero reachable→`unreachable` false negatives, including zero
   oracle-disagreement false negatives; dual-scope path covered by an integration
   test exercising both insertion orders.
4. **Recall ≥ 90%** on the corpus; every Layer-3-added CVE observed.
5. The gain is full-weight `unreachable` (dev-scope), not `module` half-credit —
   genuine `unreachable` rate ~42% → ~59%; both numbers printed by the gate.
6. `source` is never written by this feature; `project_dependencies` row identity
   is stable across re-scans; depscanner tsc + jest + `test:fixtures` green.
