# Reachability Noise Reduction — Feature Brief

## Problem Statement
Deptex's reachability classifier produces only ~26% noise reduction corpus-wide, versus
80–90% published by Socket and Endor Labs. Worse, the result is bimodal: express (npm)
hit 45% unreachable and spring-petclinic (maven) 59%, but gin (golang), sinatra (gem),
and fastapi (pypi) all came back **0% unreachable** — every dependency CVE landed at
`module` tier. Separately, zero corpus findings reached `confirmed`/`data_flow` tier:
the taint engine passes 78% of synthetic fixtures but never fired on a real repo. The
classifier architecture is sound; specific mechanisms underperform. This feature lifts
corpus-wide noise reduction to a defensible 60–70% and makes every supported ecosystem
produce real classification signal.

## Current State in Deptex
- **Classifier:** `depscanner/src/reachability.ts:413` `updateReachabilityLevels()` assigns
  five tiers — `confirmed`(1.0) / `data_flow`(0.9) / `function`(0.7) / `module`(0.5) /
  `unreachable`(0.0). Weights feed depscore.
- **`unreachable` is structurally gated** (`reachability.ts:772`): requires
  `usageAnalysisProducedOutput && !meta.isDirect && meta.filesImporting === 0`. If a
  dependency is flagged `is_direct`, `unreachable` can never apply to it.
- **Root cause of the 0%s — VERIFIED:** `depscanner/src/sbom.ts:155-165`. When cdxgen's
  CycloneDX `dependencies` graph comes back unwired (the code comment explicitly names
  pypi/maven), the fallback marks **every component `is_direct: true`**. That
  structurally disables `unreachable` for the whole scan. It fires unpredictably per
  repo — which is why maven scored 59% on one repo and other ecosystems scored 0%.
- **`function` tier is mislabeled:** it requires only that the dependency *name* appears
  in any usage slice via aggressive fuzzy matching (`isDepUsed()`, `reachability.ts:649`).
  It does not verify the CVE's *specific vulnerable symbol* is on a call path. It is
  effectively a "package is used" tier.
- **`confirmed` tier:** requires a taint flow keyed on `${dependencyId}|${osv_id}`
  (`reachability.ts:602`). Express produced 70 reachable flows but promoted zero vulns —
  the suspected break is the `depsByOsvId` CVE→dependency resolution map being empty, so
  flows write with `dependency_id=null` and the classifier excludes them.
- **Usage extraction:** all 8 language modules in `depscanner/src/tree-sitter-extractor/`
  extract both imports and call sites uniformly — there is **no extraction-capability
  asymmetry**. The gap is in the dependency-graph metadata and the classifier rules, not
  the parsers.
- **Fail-safe:** when usage extraction crashes/empties, the classifier floors verdicts
  at `module` so real vulns are never hidden (`reachability.ts:629`). This stays.

## Competitive Landscape
### Socket (acquired Coana, Apr 2025)
- Explicit 3-tier fidelity ladder: Tier 3 *Dependency Reachability* (package imported,
  ~35% FP reduction), Tier 2 *Precomputed Reachability* (function-level inside the
  dependency, ~80%), Tier 1 *Full Application Reachability* (app→vulnerable function,
  ~90%). Binary reachable/unreachable verdict + which tier produced it.
- Source: https://docs.socket.dev/docs/reachability-analysis
- Maps almost 1:1 onto Deptex's existing 5-tier model — table-stakes, not novel.

### Endor Labs
- Function-level call-graph reachability, 40+ languages; claims ~92% average noise
  reduction, "<9.5% of vulns reachable."
- Source: https://www.endorlabs.com/learn/introducing-full-stack-reachability-container-scanning-that-actually-reduces-noise

### Snyk / Debricked / Pixee / Deepfactor / Konvu
- All ship reachability prioritization; Snyk's is narrower. Industry consensus
  (Konvu, Cyber Defense Magazine): use reachability for **prioritization, not
  elimination** — exploitable vulns have been found behind "unreachable" labels.
- Sources: https://konvu.com/blog/reachability-analysis ·
  https://www.cyberdefensemagazine.com/reachability-and-exploitability/

## Landscape Synthesis
- **Table-stakes:** package-level + function-level reachability with a visible tier.
  Every serious SCA has it.
- **Frontier:** application→dependency confirmed dataflow (Socket Tier 1 / Endor
  function-level). Deptex's `confirmed` tier targets this but doesn't fire on real repos.
- **Whitespace:** none here — this is a catch-up feature. Deptex's architecture is
  already right; execution is behind.
- **Deptex position:** behind on the corpus number (26% vs 80–90%), at parity on model
  design.
- **Feasibility verdict:** known-tractable. Hard edges everyone hits — dynamic dispatch,
  reflection, DI frameworks force over-approximation. Top risks: (1) false negatives if
  classification is too aggressive — mitigated by never-suppress + the fail-safe floor;
  (2) the dependency-graph fix needs per-ecosystem lockfile parsing; (3) vulnerable-symbol
  data quality — OSV/GHSA don't always name the affected function.

## User Stories
- As a security engineer, I want unreachable dependency CVEs down-weighted so my queue
  surfaces the vulnerabilities that actually matter.
- As an org admin, I want consistent reachability signal across all our repos
  regardless of ecosystem, not 45% on Node and 0% on Go.
- As a security engineer, I want a finding marked `confirmed` only when there is a real
  proven call path, so I can trust the top of the queue.

## Locked Scope Decisions
1. **Target: honest 60–70% corpus-wide; never suppress.** Unreachable findings stay
   visible with depscore weight 0.0. Reason: prioritization-not-elimination is the
   industry safety consensus; a verifiable conservative claim beats an inflated one.
2. **Both levers + confirmed tier ship as one arc.** Ecosystem coverage, function-tier
   precision, and taint-engine-on-real-repos are one coherent feature. Reason: Henry's
   call — a single coherent landing over three trickled features.
3. **Dependency-graph recovery: cdxgen-first, lockfile-fallback.** Try to get cdxgen to
   emit a wired CycloneDX `dependencies` graph (resolve.ts already generates lockfiles
   for every ecosystem); where cdxgen still returns unwired, parse the lockfile directly
   per-ecosystem. Reason: lockfiles are deterministic ground truth; cdxgen tuning alone
   is unreliable across 8 ecosystems. A pre-implement spike measures which ecosystems
   need the fallback.
4. **Vulnerable-symbol source: structured data + reuse AI spec sinks.** Use OSV/dep-scan
   structured affected-symbol data where present; for the rest, reuse the AI
   framework-spec sinks, which already name the vulnerable symbol per CVE. Reason:
   lowest new AI cost; the data largely already exists in the pipeline.
5. **Language scope: all 8** (JS/TS, Python, Java, Go, Ruby, PHP, Rust, C#). Rust/C#
   have no corpus repos so their gains are unmeasured but the classifier work is uniform.
6. **Confirmed-tier real-repo fix is in scope** — diagnose and fix why the taint engine's
   `depsByOsvId` resolution / flow→vuln join fails on real repos. This is the riskiest
   milestone and the natural cut-line if the arc runs long.
7. **Validation: build a purpose-built reachability corpus** — curated repos with
   hand-labelled reachable/unreachable CVEs per ecosystem. Reason: the existing
   oss-corpus ground-truth is admittedly noisy (stale CVEs, project-self CVEs); an honest
   number needs an honest benchmark.
8. **Rollout: ship directly, no flag.** Strict accuracy improvement; scans are
   per-project so depscores shift gradually as projects re-scan. Reason: Henry's call.
9. **Branch: land `worktree-depscanner-hardening` first, then branch fresh off main.**
   Reason: keeps the hardening PR and this feature as separate, reviewable units; avoids
   one enormous mixed PR.

## Data Model
- **No new tables expected.** `project_dependencies` already has `is_direct` and
  `files_importing_count`. Likely changes: a column to carry the CVE's vulnerable
  symbol(s) onto the vuln/PDV row (or a small lookup), and possibly a per-PDV
  `reachability_reason` for explainability. Final shape is `/plan-feature`'s job.
- The purpose-built corpus is repo fixtures + a YAML ground-truth file under
  `depscanner/scripts/` — not DB.

## API Endpoints
None expected — this is pipeline-internal. Existing vulnerability-detail routes already
surface `reachability_level`.

## Frontend Surface
Minimal. Tier badges already render (`EntryPointBadge`, reachability tier display in
`VulnerabilityExpandableTable` / `VersionSidebar`). "Keep visible, down-weighted" means
no new hide/filter UI. A `reachability_reason` tooltip is a possible nice-to-have for
`/plan-feature` to size.

## User Flows
Pipeline-internal — no interactive flow. On each scan: SBOM parse recovers the true
direct/transitive split → usage extraction (unchanged) → classifier assigns tiers using
the corrected graph + vulnerable-symbol matching → taint flows promote to confirmed →
depscore reflects weights. User sees corrected tiers on the next scan.

## Edge Cases & Failure-Mode Policy
- **cdxgen graph unwired AND lockfile unparseable:** floor at `module` (never
  `unreachable`) — same fail-safe philosophy as today. Soft-fail, logged.
- **Vulnerable symbol unknown for a CVE:** fall back to current package-name
  `function`-tier behavior; do not down-rank below what we know. Soft-fail.
- **Lockfile parser crash:** non-fatal; classifier proceeds with whatever graph exists.
- **Dynamic dispatch / reflection:** accepted over-approximation — bias toward
  `module`/reachable, never invent `unreachable`.
- **False-negative gate:** a known-reachable CVE must never be marked `unreachable`.
  This is an acceptance gate, not just a runtime policy.

## Non-Functional Requirements
- No material increase in scan wall-time. Lockfile parsing is cheap; the spike confirms.
- AI cost: bounded by reusing existing AI spec sinks — no new per-CVE AI pass beyond
  what the rule generator already does.
- Classifier stays deterministic given the same inputs.

## RBAC Requirements
None new — pipeline-internal, no user-facing actions.

## Dependencies
- `worktree-depscanner-hardening` (~155 commits) must merge to main first.
- Existing: cdxgen + dep-scan in the pipeline; the AI rule-generator / framework specs;
  the tree-sitter usage extractor; the taint engine.

## Success Criteria
All three gates must pass on the new purpose-built reachability corpus:
1. **≥60% corpus-wide noise reduction** (unreachable + module-weighted vs raw findings).
2. **Per-ecosystem floor:** every one of the 8 ecosystems scores **>0% unreachable** —
   no repeat of the gin/sinatra/fastapi 0%.
3. **Zero known-reachable CVEs misclassified as `unreachable`** (false-negative gate).
- Stretch: a non-zero number of corpus findings reach `confirmed`/`data_flow` tier,
  proving the taint-engine real-repo fix landed.

## Open Questions
- **Q1 (can defer to /implement):** exact data-model change for carrying the vulnerable
  symbol — new column on PDV vs lookup table. Decide during /plan-feature.
- **Q2 (blocks /plan-feature partially):** the pre-implement spike must quantify which
  ecosystems actually need lockfile-fallback parsing vs cdxgen alone — this sizes the
  parser work. Run the spike first thing in /plan-feature.
- **Q3 (informational):** corpus size — how many repos/CVEs per ecosystem makes the 60%
  number statistically credible. Size during /plan-feature.

## Recommended Next Step
`/plan-feature reachability-noise-reduction` — open with the cdxgen-vs-lockfile spike
(Q2) so the dependency-graph milestone is correctly sized, then sequence: (M1) dependency
-graph recovery, (M2) function-tier symbol matching, (M3) confirmed-tier real-repo fix,
(M4) purpose-built corpus + acceptance gates.
