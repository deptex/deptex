# Arc 1 — Lockfile Dev-Closure Demotion (PLAN)

**Goal:** reliably mark the transitive **dev-only** dependency closure `environment='dev'` so the reachability classifier + depscore stop surfacing build/test-only CVEs. Targets the ~30 dev/test-transitive `unreachable`-labelled findings that are the corpus's noise-leak (handlebars/minimatch/nanoid/ejs/marked/serialize-javascript/on-headers/simple-git/undici/…). This is a **precision / noise-leak** play in the SAFE direction (over-showing → hide), gated by a hard safety invariant so it never becomes a silence-FN.

## The reframing that makes this small + safe (from the sbom.ts recon)

The engine already has a dev-closure mechanism — `patchDevDependencies()` pass 2b (`sbom.ts:360-408`) does a BFS over cdxgen's `relationships` edge graph from dev roots. **Its only flaw is reliability:** cdxgen's edge graph is frequently unwired (→ pass skips), and it excludes Maven. But we do NOT need a graph traversal for most ecosystems, because **the package manager already resolved the dev-closure into the lockfile:**

**TWO parser families (confirmed against the real corpus lockfiles, 2026-07-02):**

**Family A — SUBTRACTION** (the lockfile already carries fully-resolved dev + prod sections; `devOnly = devNames \ prodNames`, prod-wins automatic, no traversal):
| Ecosystem | Lockfile | Dev section | Prod section |
|---|---|---|---|
| composer | `composer.lock` | `packages-dev[].name` | `packages[].name` |
| pypi (pipenv) | `Pipfile.lock` | `develop{}` keys | `default{}` keys |
| npm | `package-lock.json` | `packages[].dev===true` (npm pre-resolved) | `dev!==true` |

**Family B — ROOTS + BFS** (the lock has EDGES but no per-package group; the group/dev roots live in the manifest; `devOnly = BFS(devRoots) \ BFS(prodRoots)`, prod-reachable subtracted = prod-wins):
| Ecosystem | Roots from | Edges from |
|---|---|---|
| pypi (poetry) | `pyproject.toml` `[tool.poetry.group.*]` dev groups vs main deps | `poetry.lock` `[package.dependencies]` |
| ruby | `Gemfile` group blocks (`:development`/`:test`) | `Gemfile.lock` `specs:` nested deps |

> **Why poetry is Family B, not A:** saleor's poetry.lock (poetry ≥1.5, mid-2023) has **NO `category` and NO `groups` field per `[[package]]`** — poetry dropped `category` in 1.5. So the lock alone can't separate dev from prod; only the manifest groups + the lock's `[package.dependencies]` edges can (BFS). Verified against saleor 3.14's lock.

Both families share the SAME safety core — `devOnly` excludes anything prod-reachable. go/cargo are skipped (go has no dev concept; Cargo.lock carries no dev distinction — Cargo.toml `[dev-dependencies]` is direct-only, already handled by `patchDevDependencies` pass 1).

**Corpus coverage:** Family A → paperless-ngx (Pipfile.lock ✓ has default/develop), symfony-demo (composer.lock). Family B → saleor (poetry.lock ✓ 4914 lines, edges present), discourse + mastodon (Gemfile.lock ✓ 566/857 lines). All target apps confirmed to COMMIT their lockfiles.

**Sequencing recommendation:** ship Family A first (dead-simple subtraction, highest confidence, warms up the hook + deps-sync interaction on paperless/symfony-demo), then Family B (BFS, bounded + visited-set, covers the bigger apps saleor/discourse/mastodon).

**So Arc 1 = "preserve/compute the lockfile's already-resolved dev set, additively, before deps-sync sets `environment`."** The composer + ruby transitive resolvers already PARSE these lockfiles (`transitive-resolvers/composer.ts:54-106` reads `packages-dev`; the rubygems resolver reads Gemfile.lock) — they just discard the dev signal today.

## Design

### New module `depscanner/src/dev-closure.ts` (pure, unit-testable)
- `computeLockfileDevClosure(workspaceRoot, ecosystem): { devOnly: Set<string>, recognized: boolean, reason: string }`
  - Dispatches per ecosystem to a small pure parser that returns `{ prodNames: Set, devNames: Set }`, then `devOnly = devNames \ prodNames` (normalized names — lowercased; npm scoped names kept whole; composer `vendor/pkg`; python PEP503-normalized; gem names as-is).
  - **Fail-safe:** any parse error / missing lockfile / empty prod+dev → `{ devOnly: ∅, recognized: false }`. Never throws. When not recognized, the caller changes nothing.
  - composer/pypi/npm: pure set subtraction on the lockfile's own sections (no network, no cdxgen).
  - ruby: parse Gemfile group blocks → dev-root gem names; parse Gemfile.lock `specs:` into a name→deps edge map; `devReach = BFS(devRoots)`, `prodReach = BFS(prodRoots)`, `devOnly = devReach \ prodReach`. Bounded (cap nodes/edges; truncation → recognized=false).
- Each parser is its own function with its own unit tests.

### Hook point
Within `doSbom`, **after** `patchDevDependencies()` (`sbom.ts:380`) and after the transitive resolvers merged their deps — i.e. the `dependencies[]` array + `workspaceRoot` are both final, but BEFORE `doDepsSync` (`pipeline.ts:105`) reads `d.devScoped`/`d.lockfileDev` to set `environment`. Concretely: call `applyLockfileDevClosure(dependencies, workspaceRoot, ecosystem)` at the tail of the sbom step; for every dep whose normalized name ∈ `devOnly` AND that is **not already prod** (`d.source !== 'dependencies'` and not already `environment`-prod-bound), set `d.devScoped = true`. **Additive only** — mirrors the existing `lockfileDev` doctrine (`deps-sync.ts:158-163`): never clears a flag, never downgrades a prod dep.

### Interaction with deps-sync (`deps-sync.ts:164-171`)
The `environment` expression is `source==='dependencies' ? prod : (source==='devDependencies' || devScoped) ? dev : lockfileDev ? dev : null`. Our `devScoped=true` flows through the `devScoped → 'dev'` branch. **Prod always wins** because `source==='dependencies'` is checked FIRST — we never set devScoped on a prod-sourced dep, and even if we did, the prod branch short-circuits. No change to deps-sync needed.

### What `environment='dev'` then does (from recon, for the safety analysis)
- depscore 0.4× taper (`pipeline-steps/reachability.ts:75`),
- excluded from the transitive-of-reachable floor seeds (`reachability.ts:1134-1135`),
- feeds the EXPLICIT_IMPORT_ECOSYSTEMS heuristic-unreachable path (a dev dep with 0 first-party importers → `unreachable`),
- the framework models' dev-only demotion reads MANIFEST groups directly (not `environment`), so Arc 1's TRANSITIVE closure is strictly additive to what they already catch.

## Safety analysis (the crux — a wrong demotion is a silence-FN)
1. **Prod-wins invariant:** `devOnly = devNames \ prodNames`. A package used at prod scope anywhere is in `prodNames` → excluded. The package managers compute `packages`/`default`/`main` to already include everything prod needs, so the subtraction is correct-by-construction, not a heuristic.
2. **Property (unit-tested):** adding any name to `prodNames` can only SHRINK `devOnly` (monotonic). Adding a prod edge/root can never grow the demotion set.
3. **Additive only:** we only ever set `devScoped=true`; a dep already prod (source==='dependencies') is untouched, and the deps-sync prod branch short-circuits regardless.
4. **Fail-safe:** missing/unparseable/truncated lockfile → `recognized=false` → change nothing (today's behavior). No lockfile committed (some libraries) → no-op (those need Arc 2 registry resolution — explicitly out of scope).
5. **No network, no cdxgen dependency** for composer/pypi/npm — pure lockfile reads, deterministic.
6. **Ruby BFS bound:** cap nodes/edges; on truncation → recognized=false (refuse). A cycle-safe visited-set BFS.

## Validation plan
- **Unit tests** (`dev-closure.test.ts`): per-ecosystem parsers on synthetic lockfiles; the prod-wins subtraction (a dep in both dev+prod → NOT devOnly); the monotonicity property; fail-safe on malformed/missing input; ruby BFS (dev-root→transitive is dev-only; a gem also reachable from a prod root is NOT).
- **tsc + full reachability jest green** at every commit.
- **E2e (foreground-single rescans on a rebuilt image):** saleor (poetry.lock), paperless-ngx (Pipfile.lock), symfony-demo (composer.lock), discourse + mastodon (Gemfile.lock). Expect: dev-transitive CVEs move module/shown → dev-tapered/unreachable (noise-leak ↓).
- **corpus-diff tripwire (pre vs post image) — the gate:** every transition must be adjudicated. **ZERO visible→silenced that ground truth labels reachable** (0 new silence-FN). module→unreachable on a dev-transitive is the intended win.
- **Rescore vs the 557-label ground truth:** noise-leak (14.12%) should DROP; silence precision should hold/improve; Gate-3 stays clean; baseline-lock + oracle PASS.

## Scope / non-goals
- IN: composer, pypi (pipenv + poetry), npm (verify existing lockfileDev is adequate; strengthen only if the closure subtraction finds gaps), ruby (Gemfile+lock BFS).
- OUT: go (no dev concept), cargo (Cargo.lock has no dev distinction; direct dev-deps already handled), lockfile-less library repos (express/fastify if they ship no committed lock → Arc 2 registry resolution), maven (no lockfile; `<scope>test</scope>` direct-only already handled by pass 1).

## Open questions for REVIEW
1. Is the additive-devScoped hook in doSbom cleaner than a dedicated pipeline step? (recon says doSbom-tail is the natural point; a separate step would re-read deps from ctx.)
2. Should npm be touched at all, or is `collectNpmLockfileDevSet` already complete? (Verify: does it do the prod-wins subtraction, or just read `dev===true`? npm's `dev` flag IS the resolved answer, so likely already correct — maybe npm is a no-op for Arc 1.)
3. Ruby BFS: is the Gemfile.lock `specs:` indentation parse robust enough, or reuse the existing `parseGemDirectSet` (parsers.ts:146-181) machinery?
4. Do the target apps actually have committed lockfiles at the scanned pins? (Validate before over-investing — check saleor/paperless/symfony-demo/discourse/mastodon run dirs.)

## REVIEW findings (adversarial subagents)

### Verified load-bearing fact (grounds all safety findings)
`reachability.ts:1449-1456`: when a dep is `devScoped` AND no taint flow was found, the classifier HARD-SETS `level='unreachable'` (verdict `dev_scope_unreachable`) and SKIPS the import/module-floor ladder below it. So a wrongly-dev-marked dep is HIDDEN even if it has first-party importers — only an independent taint flow survives. **The subtraction/BFS completeness is the ONLY safety guard for transitives** (the deps-sync `source==='dependencies'` short-circuit protects only DIRECT prod deps; every transitive is `source:'transitive'`). Safety bar is therefore high.

### Safety reviewer — VERDICT: REVISE. Blockers + must-fixes to fold in before implementing:
- **F1 (BLOCKER) poetry dev-group predicate:** poetry group names carry NO dev/prod semantics — a group can be prod (`worker`/`celery`/`production`, installed via `poetry install --with`). Treating ALL `[tool.poetry.group.*]` as dev roots would BFS a prod subtree into `devOnly` → silence-FN. FIX: dev-group ALLOWLIST (`dev`,`test`,`tests`,`lint`,`docs`,`typing`,`style`,`ci`,`linting`,`dev-dependencies`); any other/ambiguous group → treat as PROD (don't demote). Fixture: a non-dev poetry group's subtree is NOT demoted.
- **F2 (BLOCKER) composer full-name matching:** the SBOM splits composer deps into bare `name` + `namespace`; `composer.lock` names are full `vendor/name`. Match on reconstructed `${namespace}/${name}` (lowercased, as reachability.ts:1485) on BOTH closure build + caller — never bare name (cross-vendor collision silences a prod pkg). Fixture: two same-named pkgs different vendors, one dev/one prod → only dev-vendor demoted.
- **F3 (MUST) edge-graph completeness refusal:** a SILENTLY incomplete `specs:`/`[package.dependencies]` parse that drops a PROD edge (indentation quirk) → node lands in `devReach\prodReach` → silence-FN. FIX: invariant — every package listed in the lock MUST be in `prodReach ∪ devReach`; any unreached listed package ⇒ edge map incomplete ⇒ `recognized=false` (refuse). Reuse `parseGemDirectSet` (parsers.ts:146-181) over a fresh indentation parser.
- **F4 (MUST) correct the safety claim:** the plan's "prod wins via deps-sync short-circuit" guards only DIRECT deps; transitives have NO backstop. Reword safety #3; the subtraction's COMPLETENESS is the sole guard. Belt-and-suspenders: never `devScoped` a dep sharing a `dependency_version_edges` prod-reachable parent (mirror `transitive_of_reachable`, reachability.ts:1140+).
- **F5 (MUST) one canonical normalizer** `canon(ecosystem,name)` applied to devNames, prodNames, AND the caller match. Python = full PEP503 (`re.sub(/[-_.]+/,'-').toLowerCase()`, strip `[extras]`) — current code only `.toLowerCase()`s; asymmetry leaves a prod name un-subtracted. composer = lowercased `vendor/name`; npm = scoped name whole.
- **F6 (MUST) pipenv `develop` is human-authored, not a computed closure:** a runtime dep mis-put in `[dev-packages]` (not also in `default`) → silenced despite prod imports. FIX: for pipenv, only demote packages with ZERO first-party importers (`files_importing_count===0`; pypi is EXPLICIT_IMPORT so the tree-sitter signal exists). Same guard worth applying to poetry.
- **F7 (MUST) second-app validation per ecosystem** ([[feedback_second_app_validation]]): a 2nd poetry app with a non-dev optional group, a pipenv app with a mis-declared runtime dep, a composer app with a cross-vendor same-name pair. Gate must assert on TRANSITIVE prod deps specifically, not just aggregate count.
- **F8 (SHOULD)** exclude `FRAMEWORK_RUNTIME_PACKAGES` (reachability.ts:675) from the transitive dev closure (a framework model's non-taint heuristic could be overridden by a dev hard-hide).
- **F9 (SHOULD)** composer `replace`/`provide`: don't demote a name that appears as a `provide`/`replace` target in `packages[]`.
- **F10 (NIT)** name-keyed demotion assumes one version per name; assert/handle.
- **Credit:** npm is a SAFE NO-OP (`collectNpmLockfileDevSet` trusts strict `dev:true` = dev-everywhere; drop npm from Arc 1). composer arrays are disjoint + prod-preferred = safest arm (given F2). Family-A-before-B sequencing is the right risk order.

### Ops/correctness reviewer — VERDICT: REVISE. Findings:
- **B1 (BLOCKER→resolved-by-design) no TOML parser + poetry `groups` check:** depscanner ships js-yaml only, NO TOML dep → poetry.lock parsing is hand-rolled line-scan (risky: `[package.dependencies]` has 4 value shapes — inline string, inline table, array-of-tables, extras/markers). MITIGATION: poetry parser MUST first check for a per-package `groups = [...]` field (poetry lock ≥2.1) → if present, trivial Family-A subtraction (no edge BFS). **VERIFIED: saleor's lock is v2.0 with NO groups field → genuinely needs BFS**, so design for both: `groups` present → subtraction; absent → BFS via pyproject roots + `[package.dependencies]` edges, with prod-edge PARSE-COMPLETENESS (not hang-bounds) as the safety property.
- **M1 (MUST) per-ecosystem name-match key** (= safety F2/F5): composer match `${dep.namespace}/${dep.name}`.toLowerCase() (SBOM stores bare name + separate namespace; lock keys are `vendor/pkg` → bare match silently NO-OPs or cross-vendor-collides); pypi `normalizePypiName` both sides (SBOM may be `PyYAML`); ruby lowercase both (rubygems.ts:99 doesn't lowercase). Spec the exact key per ecosystem.
- **M2 (MUST) REUSE the two existing ROOT parsers** — genuinely-new work is ONLY the lock EDGE map: `parseGemfileDevGems` (reachability-rails-preconditions.ts:660 — handles block groups AND inline `gem 'x', group: :test` kwargs + prod-wins removal) for ruby dev roots; `parsePyprojectToml` (reachability-django-preconditions.ts:586 — extracts prod+dev sets from `[tool.poetry.dependencies]`/`[tool.poetry.group.*]`/PEP621 with `DEV_GROUP_NAMES` allowlist + **"unknown group → prod" default = SOLVES safety-F1 already**) for poetry roots. Export both (currently module-private) and consume them.
- **M3 (MUST) Gemfile.lock EDGE parser traps:** (a) a no-version-constraint nested dep is a BARE `      thor` (no parens) — the existing `parseGemfileLock` regex is `(`-anchored and DROPS it → dropped prod edge → silence-FN; (b) strip multi-constraint suffix `rack (~> 2.0, >= 2.0.8)` to name; (c) scope to GEM/GIT/PATH specs blocks, skip PLUGIN/DEPENDENCIES/PLATFORMS; (d) platform-suffixed version `nokogiri (1.13.0-x86_64-linux)`. Extend the rubygems.ts:71-113 specs state machine (it captures only the 4-space parent, discards the 6-space edges we now need).
- **S1 (SHOULD) cross-run flip-flop:** deps-sync sticky-dev only fires when `sbomGraphWired===false`; if Arc 1 returns recognized=false on run N+1 WHILE cdxgen graph is wired, environment flips dev→null → finding re-surfaces. SAFE direction (over-show). Document as accepted OR extend stickiness.
- **S2 (SHOULD) DROP npm** — `collectNpmLockfileDevSet` already reads resolved `dev:true` (prod-wins). Explicit no-op. (Both reviewers agree.)
- **S3 (SHOULD) byte caps** — reuse `safeRead`+`MAX_CONFIG_BYTES`; recognized=false above cap. State clearly bounds address hang/OOM, NOT the silent-edge-drop silence-FN (that's the completeness invariant F3/M3).
- **S4 (SHOULD) document:** `collectDevDependencyNames` covers only npm/pypi/maven/cargo — NOT composer/gem — so DIRECT composer `require-dev`/dev-group gems are `source='dependencies'→prod` and Arc 1's hook (`source!=='dependencies'`) skips them; direct dev tools stay with the framework-model demotion. Arc 1 moves ONLY transitive dev-only.
- **N1 (NIT) test matrix:** trimmed REAL locks (byte-copied from saleor/discourse/mastodon/paperless/symfony-demo), every poetry dep-value shape, Gemfile.lock GIT/PATH + no-paren dep + platform-suffix, composer vendor/name reconstruction, pypi PyYAML normalization, prod-wins overlap, + ONE pipeline/deps-sync-level test asserting environment='dev' flows end-to-end for a transitive dev-only dep.

### Scope reviewer — VERDICT: REVISE, over-scoped. Findings (EMPIRICAL, from the golden report):
- **BLOCKER: the motivating "~30 dev-transitive noise-leaks" are express+fastify NPM deps that are (a) out-of-scope AND (b) ALREADY `unreachable`.** The golden report shows all 31 (handlebars×6/minimatch×3/serialize-javascript×2/marked×2/nanoid/ejs/js-yaml/on-headers/undici/simple-git) already observed `unreachable` — demoted by the EXISTING import-absence heuristic (reachability.ts:1118-1143; npm∈EXPLICIT_IMPORT_ECOSYSTEMS), not by any dev-closure. I lifted memorable names from the SYNTHETIC corpus yaml and mispresented them as the OSS-corpus 36. The headline payoff is invalid.
- **MUST: in-scope apps have ~0 dev-transitive labels → validation unfalsifiable.** symfony-demo + mlflow have empty ground_truth_cves; discourse/mastodon unreachables are feature-gated framework CVEs (already demoted by the Rails model), not dev-scope. Nothing labelled in the scoped ecosystems for Arc 1 to move.
- **MUST: the real overlap is the IMPORT-ABSENCE heuristic, not pass 2b.** For npm/composer/pypi an UNIMPORTED dev-transitive is ALREADY `unreachable` with no dev signal. Arc 1's only marginal value = demoting dev-only transitives that ARE first-party-imported — and the framework models already patched that for DIRECT dev deps. So the genuine additive case = transitive closure of IMPORTED dev roots, and ONLY in **ruby** (the one in-scope ecosystem NOT in EXPLICIT_IMPORT_ECOSYSTEMS → import-absence never fires there). **Residual ≈ 5, ruby-concentrated, not 30.**
- **SHOULD: drop npm** (no-op 3 ways). **SHOULD: cheaper 80/20** — composer's dev signal is already parsed+discarded in composer.ts:95 (a ~10-line resolver tweak, not a new module); ruby genuinely needs the Gemfile-group BFS; pipenv/poetry are speculative (paperless not in corpus, mlflow empty). Don't build a 5-ecosystem module in 2 PRs.
- **Credit:** safety design (prod-wins subtraction, monotonic, additive, fail-safe) is sound; the `environment='dev'→unreachable` claim was verified correctly.
- **VERDICT: do the smaller thing** — re-measure the 36 OSS noise-leaks by ecosystem/mechanism FIRST; the honest surviving scope is "composer resolver tweak + ruby Gemfile-group dev-closure," gated on landing ≥1 dev-transitive label to score against.

## REVIEW SYNTHESIS + DECISION (all 3 = REVISE)
Consensus: the reframing is elegant and the safety design is sound, but **the arc as scoped is largely redundant** — the import-absence heuristic already demotes unimported dev-transitives for npm/composer/pypi, and the true additive residual is small + ruby-concentrated + currently UNMEASURABLE (no labelled dev-transitive CVEs in the scoped ecosystems). **Gate before ANY code (reviewers' unanimous #1 ask): re-measure the actual noise-leak by ecosystem/mechanism** → then decide between (a) the minimal ruby-only dev-closure + composer resolver tweak, or (b) DEFER Arc 1 for a higher-value arc (Arc 2 dep-source graphs / Arc 5 symbol scoping also target the same 14.12% noise-leak with more reach). See ledger for the re-measurement result + decision.

## RE-MEASUREMENT RESULT + FINAL DECISION: DEFER Arc 1 (2026-07-02)
Enumerated the actual noise-leak (labelled-`unreachable`, observed-shown) across the 557-label corpus: **87 cases — golang 33, gem 53, cargo 1, and ZERO in npm/composer/pypi.** This confirms the reviewers: the EXPLICIT_IMPORT import-absence heuristic already zeroes the noise-leak for the very ecosystems Arc 1 targeted. **AND — decisively — none of the 87 are dev-transitive-closure cases.** They are:
- **golang (33):** feature-gated / subpackage-not-imported / go-git `//go:build gogit` / x509 / WebFlux — belong to the **Go model demotions + Arc 2 (dep-source import graphs)**.
- **gem (53):** Rails feature-gated (ActiveStorage engine commented out, no HTTP-token-auth, Rack::Session::Pool unused, JRuby-only, Windows-only, puma-under-unicorn) + a few **Rails OVER-promotions** (puma PROXY-protocol 47736/47737 → data_flow; config-gated rails-html-sanitizer 23518/23519/23520 → data_flow) — belong to **Rails-model feature-precondition extensions + promotion excludes** (the Arc-0c playbook).
- **cargo (1):** bat CVE-2024-12224.

**Arc 1 (lockfile dev-closure) would fix 0 of the 87. DEFERRED.** The review process (3 adversarial reviewers + the re-measurement they demanded) killed a low-value feature before any code and redirected to what actually moves the metric.

**PIVOT (new highest-value work): close the measured 87-case noise-leak by extending the Rails + Go models** — same ground-truth-driven feature-precondition/promotion-exclude fixes as Arc 0c (Go idna, Rails puma, Rails CommonLogger, Spring FORM-auth), now with the 557-label corpus to validate every fix. Biggest cluster = gem (53) with ground truth already in place. This is a far better ROI than a dev-closure module that fixes nothing measurable.

## Progress
- [x] PLAN (this doc)
- [x] REVIEW (3 adversarial subagents — ALL REVISE)
- [x] RE-MEASURE noise-leak by ecosystem/mechanism → 87 cases, golang33/gem53/cargo1, ZERO dev-transitive
- [x] DECIDE → **DEFER Arc 1** (fixes 0 of 87); pivot to Rails/Go model noise-leak reduction
- [n/a] IMPLEMENT / VALIDATE — Arc 1 not built
- [ ] FIX plan per review
- [ ] IMPLEMENT (dev-closure.ts + hook + tests)
- [ ] VALIDATE (rescans + tripwire + rescore)
- [ ] RECORD (ledger + memory)
