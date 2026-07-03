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

## Progress
- [x] PLAN (this doc)
- [ ] REVIEW (≥3 adversarial subagents)
- [ ] FIX plan per review
- [ ] IMPLEMENT (dev-closure.ts + hook + tests)
- [ ] VALIDATE (rescans + tripwire + rescore)
- [ ] RECORD (ledger + memory)
