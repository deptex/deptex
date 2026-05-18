# Reachability Noise Reduction — Implementation Plan

## Overview
Lift depscanner's corpus-wide reachability noise reduction from ~26% to a defensible
60–70% and make every supported ecosystem produce real classification signal (no repeat
of the gin/sinatra/fastapi 0%). The classifier architecture (`reachability.ts`
five-tier model) is sound; three specific mechanisms underperform and get fixed as one
arc: (M1) the SBOM dependency-graph fallback that flags every component `is_direct` and
structurally disables the `unreachable` tier; (M2) the `function` tier that fuzzy-matches
a *package name* instead of verifying the CVE's *vulnerable symbol*; (M3) the taint
engine's `depsByOsvId` resolution path that writes flows with `dependency_id=null` so
nothing ever reaches `confirmed`. (M4) builds a purpose-built hand-labelled corpus to
prove the number honestly. No new tables, no new routes — entirely pipeline-internal.

## Competitive Research & Design Rationale
Covered in depth in `.cursor/plans/feature-brief-reachability-noise-reduction.md`. Summary:
- **Socket** (acquired Coana, 2025): explicit 3-tier ladder — Dependency Reachability
  (~35% FP reduction), Precomputed Reachability (~80%), Full Application Reachability
  (~90%). Maps almost 1:1 onto Deptex's existing 5-tier model.
- **Endor Labs**: function-level call-graph, ~92% noise reduction.
- **Industry consensus** (Konvu, Cyber Defense Magazine): reachability is for
  *prioritization, not elimination* — exploitable vulns have been found behind
  "unreachable" labels.
- **Adopt:** the visible-tier model (already have it), conservative never-suppress
  posture, function-level symbol verification.
- **Differentiate:** nothing — this is a catch-up feature. Deptex's model design is at
  parity; execution is behind. The goal is an honest 60–70%, not an inflated 90%.

## Codebase Analysis

### Pipeline order (`depscanner/src/pipeline.ts`)
`clone` → `resolve` (`resolveDependencies()`, ~L101) → `sbom` (`runCdxgen()`, ~L166) →
`deps_synced` (`parseSbom()` from `sbom.ts`, upserts `project_dependencies`, ~L587) →
`usage_extraction` (`extractUsage()` + `storeUsageExtractionResults()`) →
`framework_detection` → `scanning` (`runDepScan()`, writes
`project_dependency_vulnerabilities`) → `taint_engine` (`runTaintEngine()`, ~L1489;
builds `depsByOsvId` at L1530-1644) → `reachability_levels`
(`updateReachabilityLevels()` + `computeImportCountsFromUsageSlices()`, ~L1796).

### Key findings (verified)
- **`sbom.ts:149-157`** — the all-direct fallback. When the CycloneDX `dependencies`
  graph traversal yields nothing (`allDeps.size === 0`), every component is marked
  `is_direct: true` and pushed to `directRefs`. This structurally disables the
  `unreachable` tier (`reachability.ts:743` requires `!meta.isDirect`). It fires
  per-repo unpredictably — the root cause of the bimodal 0%/59% behaviour.
- **`resolveDependencies()`** generates a lockfile for **npm, golang, cargo, gem,
  composer only** (`npm install`, `go mod download`, `cargo fetch`, `bundle install`,
  `composer install`). **Maven and PyPI do NOT** — `mvn dependency:resolve` populates
  the `.m2` cache and `pip install` writes site-packages, neither emits a lockfile.
  *(The feature brief's "resolve.ts already generates lockfiles for every ecosystem"
  is incorrect; M1 corrects for it.)*
- **`runCdxgen()`** invokes `npx @cyclonedx/cdxgen --path . -o sbom.json --profile
  research --deep [-t ECOSYSTEM]`. `--profile research --deep` is already the
  graph-wiring-friendly flag set.
- **`reachability.ts:625` `isDepUsed()`** — the `function` tier. Fuzzy-matches the
  *dependency name* against `project_usage_slices` strings (hyphen→dot, first-segment).
  Does not verify the CVE's specific vulnerable symbol. Effectively a "package is used"
  tier.
- **`reachability.ts:662`** — `confirmed` requires a `taintByDepOsv` entry keyed
  `${dependency_id}|${osv_id}`. Flows with `dependency_id=null` never populate it.
- **`pipeline.ts:1530-1644`** — `depsByOsvId` build. PDV rows are read, joined to
  `project_dependencies` then `dependencies` for ecosystem, `buildPurl()` is called, and
  the map is keyed on **`r.osv_id` (the raw PDV osv_id)**. The engine's CVE-targeted
  specs are keyed/loaded by **CVE id** (`detectedCves` expands GHSA→CVE via aliases).
  When a PDV's primary `osv_id` is a GHSA id, `depsByOsvId` is keyed `GHSA-xxxx` but the
  spec emits a flow with `osv_id=CVE-yyyy` → resolver miss → `dependency_id=null`.
  This alias-key mismatch is a prime M3 suspect.
- **`taint-engine/storage.ts` `writeFlows()`** — `dependency_id` comes entirely from the
  `resolveDep` callback; the default `fallbackUnresolvedResolveDep()` always returns
  `null`. Framework-*generic* specs (express.yaml etc.) carry no `osv_id` on their
  sinks, so their flows are `data_flow`-tier by design — `confirmed` requires a
  *CVE-targeted* spec to have been generated, validated, loaded, and matched.
- **No structured affected-symbol data** exists in OSV or dep-scan VDR output. The only
  per-CVE vulnerable-symbol signal in the pipeline is the AI-generated CVE-targeted
  FrameworkSpec `sink.pattern` field (`taint-engine/spec.ts` `FrameworkSink`).
- **No reachability-symbol DB column** exists. `project_dependency_vulnerabilities`
  already has `reachability_level text`, `reachability_details jsonb`, `is_reachable
  boolean`. `project_dependencies` already has `is_direct`, `files_importing_count`,
  `namespace`.

### Reusable code identified
- `sbom.ts` `parsePurl()` / `getBomRefToNameVersion()` — PURL + bom-ref helpers.
- `purl.ts` `buildPurl()`, `parsePurl()`, `resolvePurlToDependencyId()`.
- `reachability.ts` `usageMatchesDep()` / `PYPI_IMPORT_ALIASES` — name-variant matching,
  extend rather than reinvent for symbol matching.
- `taint-engine/cve-specs.ts` `loadCveSpecsForExtraction()` + `cveSpecResult` — already
  loaded in-pipeline just before `reachability_levels`; M2 threads the loaded sink set
  into the classifier in-memory (no DB round-trip).
- Existing fixture pattern under `depscanner/fixtures/` + `test/snapshot.ts`.

## Data Model
**No migrations.** Decision on brief Open Question Q1: the vulnerable-symbol data lives
only in the in-memory `cveSpecResult` already loaded for the taint-engine step. M2
threads that set into `updateReachabilityLevels()` as a parameter — no column, no
lookup table. Explainability (the brief's optional `reachability_reason`) is written
into the **existing** `reachability_details jsonb` column as a `reason` key. This keeps
the feature schema-free and avoids the two-phase-migration tax.

Latest migration on `main` is `phase28b_code_injection_vuln_class.sql`; no `phase29`
needed.

## API Design
**None.** Pipeline-internal. Existing vulnerability-detail routes already surface
`reachability_level` and `reachability_details`; the new `reachability_details.reason`
key flows through with no route change.

## Frontend Surface
**Minimal / optional.** Tier badges already render. The brief's "keep visible,
down-weighted" posture means no hide/filter UI. One optional polish task (M2, last):
surface `reachability_details.reason` as a tooltip on the existing reachability tier
badge in `VulnerabilityExpandableTable` / the org sidebar expanded content — read-only,
no new component, no state. Cut first if the arc runs long.

## Implementation Milestones

> Per `feedback_implement_no_milestone_pause` the implement loop runs M0→M4
> back-to-back. M0 is a measurement spike whose result is written into this plan before
> M1 code starts.

### M0 — cdxgen-vs-lockfile spike (S)
Resolves brief Open Question Q2: which ecosystems actually need graph-recovery fallback
vs. cdxgen alone. Until this runs, M1's per-ecosystem parser scope is an estimate.

Tasks:
1. Pick one representative repo per ecosystem (8 total — reuse the M4 corpus repos once
   M4's repo selection is done, or temporary throwaway clones).
2. Run the existing pipeline through the `sbom` step on each; dump the CycloneDX
   `dependencies` array and check: is it wired (non-empty, root node present)? Does
   `parseSbom()` hit the `allDeps.size === 0` fallback?
3. Write the result table (ecosystem → graph-wired? → fallback needed?) into a
   `## M0 Spike Result` section appended to this plan.
4. **Decision rule:** any ecosystem whose cdxgen graph is reliably wired needs no M1
   fallback parser; the rest get one. Maven/PyPI are pre-committed to the
   `mvn dependency:tree` / `pipdeptree` path regardless (Henry's call, see M1).

Acceptance: spike result table in the plan; M1 parser scope finalised.
Files: scratch script under `depscanner/scripts/` (delete after, or keep as
`reachability-graph-probe.ts`).

### M1 — Ecosystem-wide dependency-graph recovery (L)
Goal: every ecosystem produces a correct direct/transitive split so `is_direct` is
trustworthy and the `unreachable` tier can fire.

Tasks:
1. **`sbom.ts` — gate the all-direct fallback.** Replace the blanket
   `allDeps.size === 0 → mark everything direct` block with: still include every
   component (so no package is dropped), but **do not set `directRefs`** when the graph
   is unwired. Add a `graphRecovered: boolean` / `directSetTrusted: boolean` signal on
   the return value so downstream knows whether `is_direct` is real or unknown.
2. **New `depscanner/src/dependency-graph/` module** — per-ecosystem direct/transitive
   resolvers, invoked when cdxgen's graph is unwired (per M0 result):
   - **Lockfile parsers** for npm (`package-lock.json`), golang (`go.sum` + `go.mod`
     direct set), cargo (`Cargo.lock` + `Cargo.toml`), gem (`Gemfile.lock`), composer
     (`composer.lock`) — these lockfiles already exist post-`resolveDependencies()`.
   - **Maven**: extend `resolveDependencies()` to also run
     `mvn dependency:tree -DoutputType=text` (or `-Dtokens=whitespace`), capture stdout,
     parse the indented tree into a parent→child graph.
   - **PyPI**: extend `resolveDependencies()` to run `pipdeptree --json-tree` (add
     `pipdeptree` to the depscanner Dockerfile + `package.json`/pip deps) after
     `pip install`; parse the JSON tree. Fall back to parsing `requirements.txt` for the
     direct set only if `pipdeptree` is unavailable.
   - Each parser returns `{ directNames: Set<string>, edges: ParsedSbomRelationship[] }`
     in the same shape `parseSbom()` already produces.
3. **Wire into the `deps_synced` step.** After `parseSbom()`, if `directSetTrusted` is
   false, call the matching ecosystem resolver, reconcile its direct set against the
   parsed components (match on name/namespace), and overwrite `is_direct` accordingly.
   Reconciliation is name-based — log unmatched entries, don't fail.
4. **Fail-safe (brief edge case).** If the cdxgen graph is unwired AND the fallback
   parser crashes or finds nothing, leave `is_direct` at its parsed value but ensure the
   classifier still floors at `module` (never invents `unreachable` from an untrusted
   graph). Add a `graph_recovery` telemetry field to the step log:
   `cdxgen` / `lockfile` / `mvn_tree` / `pipdeptree` / `failed`.
5. Unit tests for each parser against committed lockfile/tree fixtures (small static
   sample files under `depscanner/src/dependency-graph/__tests__/fixtures/`).

Acceptance: on a repo where cdxgen returns an unwired graph, `project_dependencies`
shows a realistic direct/transitive split (not 100% direct); transitive-unused deps
become eligible for `unreachable`.
Files: `depscanner/src/sbom.ts`, new `depscanner/src/dependency-graph/` (index +
per-ecosystem parsers + tests), `depscanner/src/pipeline.ts` (`resolve` +
`deps_synced` steps), `depscanner/Dockerfile` (`pipdeptree`),
`depscanner/package.json`.

### M2 — Function-tier vulnerable-symbol matching (M)
Goal: `function` tier means "the CVE's vulnerable symbol is present in usage", not
"the package name appears somewhere".

Tasks:
1. **Thread the loaded CVE specs into the classifier.** `updateReachabilityLevels()`
   already takes `UpdateReachabilityOptions`. Add `cveSpecSinks?: Map<string,
   string[]>` — osv_id → list of vulnerable symbol tokens (the callee name extracted
   from each `FrameworkSink.pattern`, e.g. `yaml.load(*)` → `yaml.load` / `load`).
   `pipeline.ts` already holds `cveSpecResult` just before the `reachability_levels`
   step; build the map there and pass it.
2. **Symbol-token extraction helper** in `reachability.ts`: from a `sink.pattern`,
   strip the `(*)` arg placeholder and produce match tokens (full dotted name + last
   segment). Reuse `usageMatchesDep()`'s lower/dotted/alias normalisation.
3. **New classifier branch** (between the existing `taint`/`data_flow` branches and the
   `isDepUsed()` fallback): when a PDV has an `osv_id` with an entry in `cveSpecSinks`:
   - If any symbol token appears in `project_usage_slices`
     (`resolved_method`/`target_name`/`target_type`) → `function` tier, with
     `reachability_details.reason = 'vulnerable symbol <X> found in usage'`.
   - If the dep is imported (`files_importing_count > 0`) but **no** symbol token is
     found, AND usage extraction produced output for the run → demote to `unreachable`
     with `reachability_details.reason = 'vulnerable symbol <X> not on any call path'`.
   - If usage extraction produced no output (the fail-safe condition) → floor at
     `module`. **Never** mark `unreachable` on empty usage data.
4. **Long-tail fallback (brief decision 4).** When a PDV's `osv_id` has *no* CVE spec
   (the AI generator never produced one), keep the current `isDepUsed()` name-match
   `function`/`module` behaviour unchanged. Do not down-rank below what's known.
5. **Determinism.** The branch is pure given (usage slices, spec sinks) — no AI call,
   no new cost. Verify the classifier stays deterministic.
6. Unit tests: symbol-present → `function`; symbol-absent + imported + usage-present →
   `unreachable`; symbol-absent + no usage output → `module`; no-spec → unchanged
   name-match behaviour.
7. **Optional polish (cut first):** surface `reachability_details.reason` as a tooltip
   on the reachability tier badge in `VulnerabilityExpandableTable` and the org sidebar
   expanded content. Read-only, no new component.

Acceptance: a corpus CVE whose vulnerable symbol is genuinely absent drops from
`module`/`function` to `unreachable`; a CVE whose symbol is present stays `function`;
the false-negative gate (M4) holds.
Files: `depscanner/src/reachability.ts`, `depscanner/src/pipeline.ts`, optional
`frontend/src/components/.../VulnerabilityExpandableTable.tsx` +
`VulnerabilityOrgSidebarExpandedContent.tsx`.

### M3 — Confirmed-tier real-repo fix (L — riskiest, natural cut-line)
Goal: the taint engine actually promotes real-repo vulns to `confirmed`. **Diagnostic
first, then fix** — the exact bug set is not fully known until M3 runs against a real
repo with a known CVE-targeted spec.

Tasks:
1. **Diagnostic pass.** Run a depscanner scan against an M4 corpus repo that has a
   known-reachable CVE with a CVE-targeted spec. Instrument and capture: does
   `depsByOsvId` populate? are flows written with non-null `dependency_id`? does the
   flow's `osv_id` match the PDV's `osv_id` key? Write findings into a
   `## M3 Diagnostic` section of this plan.
2. **Fix the alias-key mismatch** (`pipeline.ts:1634`). `depsByOsvId` is keyed on the
   raw PDV `osv_id`; CVE-targeted specs emit flows keyed on the CVE id. Key
   `depsByOsvId` by **every** CVE-shaped id for the PDV (primary `osv_id` + CVE-shaped
   `aliases`), mirroring how `detectedCves` is already expanded. Each alias points at
   the same `ResolvedDep`.
3. **Fix any null-`dependency_id` path surfaced by the diagnostic** — e.g. PDV rows
   missing `project_dependency_id`, `dependencies` ecosystem lookup failing, or
   `buildPurl()` returning null. Make each a logged warn, not a silent null.
4. **Verify the classifier join.** `updateReachabilityLevels()` keys `taintByDepOsv` on
   `${dependency_id}|${osv_id}` and matches PDVs by `pdv.osv_id`. Confirm a PDV whose
   primary id is GHSA still matches a flow whose `osv_id` is the CVE alias — if not,
   extend the match to the PDV's `aliases` here too.
5. Integration test (PGLite): a seeded repo + CVE-targeted spec produces a
   `project_reachable_flows` row with non-null `dependency_id` and the PDV classifies
   as `confirmed`.

Acceptance (stretch goal per brief): a non-zero number of corpus findings reach
`confirmed`/`data_flow`. If M3 proves intractable within the arc, it is the documented
cut-line — M1+M2 alone should clear the 60% gate.
Files: `depscanner/src/pipeline.ts`, `depscanner/src/reachability.ts`,
`depscanner/src/taint-engine/storage.ts` (if the resolver path needs it).

### M4 — Purpose-built reachability corpus + acceptance gates (L)
Goal: an honest benchmark. 8 repos (one per ecosystem), ~8–12 hand-labelled CVEs each
(~80–100 total — Henry's locked size).

Tasks:
1. **Repo selection.** Pick one real, moderately-sized OSS repo per ecosystem
   (npm/pypi/maven/golang/gem/composer/cargo/nuget) with a known set of dependency
   CVEs. Prefer repos with a clear mix of reachable and unreachable cases. These double
   as the M0 spike repos.
2. **Ground-truth YAML** at `depscanner/scripts/reachability-corpus/ground-truth.yaml`:
   per repo, per CVE — `osv_id`, `expected: reachable | unreachable`, a one-line
   `rationale`, and the labeller's note. Hand-label by reading the repo's actual
   imports/call sites. Document the labelling method in a sibling README.
3. **Benchmark runner** `depscanner/scripts/reachability-corpus/run.ts` (npm script
   `test:reachability-corpus`): scan each repo, read back `reachability_level` per CVE,
   compute (a) corpus-wide noise reduction = (unreachable + module-weighted) / total,
   (b) per-ecosystem unreachable %, (c) the false-negative list — any CVE labelled
   `reachable` that came back `unreachable`.
4. **Acceptance gates** — runner exits non-zero unless all three hold:
   - corpus-wide noise reduction **≥ 60%**;
   - every ecosystem **> 0%** unreachable;
   - **zero** known-reachable CVEs misclassified as `unreachable`.
5. Wire the runner into CI as a non-blocking informational job first (it needs network
   + Docker); promote to blocking only once stable.
6. Iterate M1/M2 thresholds against the corpus until the gates pass.

Acceptance: `npm run test:reachability-corpus` passes all three gates.
Files: new `depscanner/scripts/reachability-corpus/` (ground-truth.yaml, run.ts,
README, repo manifest), `depscanner/package.json`, `.github/workflows/` (informational
job).

## Testing & Validation Strategy
- **Unit:** per-ecosystem dependency-graph parsers (M1), symbol-token extraction +
  classifier branch (M2). Run via existing jest setup in `depscanner/src/__tests__/`.
- **Integration (PGLite):** M3 confirmed-tier promotion end-to-end; M1 graph-recovery on
  an unwired-cdxgen fixture.
- **Snapshot:** regenerate `depscanner/fixtures/*/snapshots/` via `npm run
  test:fixtures` — `is_direct` and `reachability_level` values will shift; review the
  diff deliberately, don't blind-`--update`.
- **Corpus (M4):** the three acceptance gates are the headline validation.
- **Regression:** the existing fixture snapshots + `npm run test:taint-engine-all`
  preflight must stay green. Watch the `taint_engine` circuit breaker — M3 changes the
  resolver path.
- **Performance:** `mvn dependency:tree` and `pipdeptree` add a subprocess to the
  `resolve` step. Confirm no material scan wall-time increase (brief NFR) — measure on
  the M0 spike repos.

## Risks & Open Questions
- **R1 (high):** M3 may uncover more than the alias-key bug — the diagnostic is
  deliberately first. Mitigated by M3 being the documented cut-line; M1+M2 carry the
  60% gate alone.
- **R2 (med):** marking `unreachable` from symbol-absence (M2) risks false negatives if
  usage extraction is incomplete for an ecosystem. Mitigated by the "no usage output →
  floor at `module`" rule and the M4 false-negative gate.
- **R3 (med):** `pipdeptree` / `mvn dependency:tree` availability in the depscanner
  Docker image — M1 adds `pipdeptree`; Maven is already present. Fallback to
  manifest-only direct detection if a tool is missing.
- **R4 (low):** corpus labelling is the most manual, error-prone task — a wrong label
  poisons a gate. Mitigated by the rationale field + README method doc + small size.
- **Resolved:** Q1 (data model) → no migration, in-memory spec threading +
  `reachability_details.reason`. Q2 → M0 spike. Q3 → 8 repos / ~80–100 CVEs (Henry).
  Maven/PyPI graph → generate a real graph via `mvn dependency:tree` + `pipdeptree`
  (Henry).

## Dependencies
- `worktree-depscanner-hardening` — already merged to `main` (`f4251e2`).
- Existing: cdxgen + dep-scan in the pipeline; `resolveDependencies()`; the tree-sitter
  usage extractor; the cross-file taint engine + `cve-specs.ts` loader; the AI
  rule-generator (CVE-targeted FrameworkSpec source).
- Branch fresh off `main` per `feedback_one_branch_no_new_branches` /
  `feedback_sync_main_often`.

## M4 Execution — REMAINING (the actual validation, not just the harness)

M1–M3 code + the M4 harness are committed on `worktree-reachability-noise-reduction`
(4 commits off main, tsc clean, 928 unit tests pass). NOT DONE: the corpus run +
measured result. **Do not `/push-changes` until the gates produce a real number.**

1. Rebuild the Docker image from this branch: `cd depscanner && npm run docker:build`.
2. **Directional run first** — scan the 0%-ecosystem repos via the existing
   `scripts/oss-corpus.yaml` (gin/golang, fastapi/pypi, sinatra/gem) plus a baseline
   (express/npm, spring/maven). Compare the `reachability_level` distribution against
   main. Confirm M1's `is_direct` recovery actually moves gin/sinatra/fastapi off 0%
   unreachable. If it doesn't, debug M1 before continuing.
3. Populate `scripts/reachability-corpus.yaml` — one real repo per ecosystem (8 total),
   hand-label ~8–12 CVEs each reachable/unreachable per the YAML header's method.
4. Run `npm run test:reachability-corpus`; record the 3-gate result.
5. Iterate M1/M2 thresholds against the corpus until the gates pass — the M2
   symbol-absent→unreachable branch is the documented tunable knob.
6. Then `/push-changes`.

Also pending: `npm run test:fixtures:update` (Docker) — M1 shifts `is_direct` on the
python/java/go fixtures, so their snapshots need regenerating + committing.

## Success Criteria
All three gates pass on the M4 purpose-built corpus:
1. **≥ 60%** corpus-wide noise reduction.
2. Every one of the 8 ecosystems scores **> 0%** unreachable.
3. **Zero** known-reachable CVEs misclassified as `unreachable`.
Stretch: a non-zero count of corpus findings reach `confirmed`/`data_flow`, proving the
M3 taint-engine real-repo fix landed.
```
