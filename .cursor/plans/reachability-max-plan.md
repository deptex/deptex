# REACHABILITY-MAX — Master Plan (autonomous, Henry-authorized 2026-07-02)

**Directive (verbatim intent):** Henry: "fully let you go crazy right now … make the plans for these, review these plans, fix the plans, then implement the plans, run whatever tests … keep waking yourself up on a loop until this is done. you can stop to ask me questions if needed." Scope = the improvement levers **1, 2, 3, 4, 5, 7** (everything except #6 DAST-correlation) + the validation backbone from `depscanner-stress-test.plan.md`. **No PR yet — Henry explicitly said "screw it", keep committing locally** (ONE PR at the very end remains the rule). Never push. Worktree `corpus-noise-reduction`.

**The numbers being improved:** provable-unreachable share (52.78% → up) · silence precision (75% → up) · app-shaped silence-FN (42.86% → down) · confirmed tier (→ up). Raw %-silenced is NOT the target (corpus-composition artifact).

**Standing doctrine (unchanged):** fail-safe demotion (prove absence or refuse) · two-app validation for every per-repo-signal model ([[feedback_second_app_validation]]) · corpus-integrity (never label from the model's own output) · checkpoint commit per verified step · revert `depscanner/src/lib/encryption.ts` before every commit · ledger every iteration.

**Per-arc process (Henry's prescribed cycle):**
1. **PLAN** — write `.cursor/plans/arc-<n>-<slug>.plan.md` (design, files, safety analysis, validation plan).
2. **REVIEW** — adversarial review subagents (≥3 lenses: correctness/safety-FN-risk, scope/overfit, ops/perf). Every MUST-FIX addressed or explicitly refuted in the plan doc.
3. **FIX** the plan per review.
4. **IMPLEMENT** — checkpoint commits, tsc + jest green at every commit.
5. **VALIDATE** — unit tests · two-app validation where applicable · full-corpus rescore · gates (1/3/baseline-lock/oracle) · **corpus-diff tripwire vs previous image (Arc 0 tool): ZERO unexplained visible→silenced transitions**.
6. **RECORD** — ledger iteration + memory anchor update; then next arc.

---

## Arc 0 — TRIPWIRE + EVIDENCE BASE (protects everything after it)
- **0a. `scripts/corpus-diff.ts`** — diff two corpus scans (runs dirs or assembled reports) per-finding: **ALARM on any visible→silenced transition** (function/data_flow/confirmed → module/unreachable); REVIEW-level report for module→unreachable (confidence change, product-invisible) and new/gone findings (VDB volatility); exit 1 on alarms. Run on every image bump from now on.
- **0b. Label the 6 unlabelled corpus apps** (stress-plan A1): per-repo triage subagents with file:line-grounded verdicts + adversarial verify (2-of-3 refuters kill a label) → `ground_truth_cves` in the corpus yaml. Grows the labelled set 36 → ~150+; precision/FN become statistically real. Can proceed incrementally alongside later arcs (one repo per session-slice).
- **0c. Java/Spring + PHP/Symfony second-app retrofit** (stress-plan C1) — the 2 models that predate the two-app method. Pick a 2nd real Spring Boot app + a 2nd Symfony app, scan, verify flips-for-the-right-reasons, fix what it catches (it caught bugs both prior times).
- **Exit:** diff tool exists + wired into the scan procedure; ≥2 repos newly labelled; both retrofits scanned + verdicts triaged.

## Arc 1 — LOCKFILE DEV-CLOSURE DEMOTION — ⛔ DEFERRED 2026-07-02 (plan→review→re-measure killed it)
> **DECISION: deferred as low-value.** PLAN written + 3 adversarial reviews (all REVISE) + the re-measurement they demanded proved it fixes ~0 of the real noise-leak. The 87-case measured noise-leak (labelled-unreachable-but-shown across the 557-label corpus) is golang 33 / gem 53 / cargo 1, ZERO in npm/composer/pypi (import-absence already handles those), and NONE are dev-transitive-closure — they're feature-gated (Go subpackage/build-tag, Rails ActiveStorage/JRuby/Windows/session) + a few Rails over-promotions. Full analysis: `.cursor/plans/arc-1-lockfile-dev-closure.plan.md`. **Superseded by Arc 1' below.** (Original design retained in the plan doc for reference — the dev-closure infra already exists via cdxgen `devScoped` + npm `lockfileDev`; the true residual is a handful of ruby imported-dev-transitives with no corpus coverage to validate.)

## Arc 1' — CLOSE THE MEASURED NOISE-LEAK via Rails/Go model extensions (NEW, replaces Arc 1)
The re-measurement's real target: 87 labelled-unreachable-but-shown findings, fixable with the proven Arc-0c ground-truth playbook (feature-precondition demotions + promotion excludes), validated against the 557-label corpus.
- **gem (53, biggest cluster, ground truth in hand):** Rails feature-precondition rows for ActiveStorage-engine-commented-out, no-HTTP-token-auth, Rack::Session::Pool-unused, JRuby-only, Windows-only, actionmailer-block_format-unused, etc.; + promotion EXCLUDES for the over-promoted puma-PROXY-protocol (47736/47737) and config-gated rails-html-sanitizer (23518/23519/23520) CVEs.
- **golang (33):** Go-model demotions for go-git `//go:build gogit` (build-tag-aware — needs a signal), x509-not-configured, WebFlux-not-servlet; several overlap Arc 2 (dep-source import graphs prove transitive-absence).
- **cargo (1):** bat single case.
- Each fix = ground-truth-driven, fail-safe, unit-tested, rebuild+rescan+tripwire, incremental noise-leak reduction. Run the corpus-diff tripwire every image bump; 0 new silence-FN.

## Arc 1 (original) — LOCKFILE DEV-CLOSURE DEMOTION (deferred; kept for reference)
> **Grounding (read before planning, 2026-07-02):** the engine ALREADY has a dev-scope spine — `project_dependencies.environment ∈ {prod,dev,null}` set in `deps-sync.ts:164`, fed by cdxgen's `d.devScoped` transitive propagation + npm's `d.lockfileDev` (package-lock `"dev":true`) fallback; the reachability classifier + depscore already consume `environment==='dev'` (envWeight 0.4). So Arc 1 is NOT greenfield. The REAL gap is reliability: the code comment at `deps-sync.ts:158-163` admits cdxgen's dev propagation "frequently leaves a build/test-only transitive un-devScoped", and only npm has a lockfile fallback. **Arc 1 = a reliable per-ecosystem lockfile-graph dev-closure computed independently of cdxgen** (compute the set of packages reachable ONLY from dev roots, flip their `environment` to 'dev' before the reachability step), so poetry/Pipfile/composer/Gemfile/cargo get npm-quality dev-closure. It composes with — does not replace — the framework models' direct-dev demotion.
- Today only *directly-declared* dev deps reliably demote in non-npm ecosystems (the framework models read direct Gemfile/pyproject/composer groups; the rexml-via-rubocop trap is why they stay direct-only). Lockfiles carry the full edge graph: prove "reachable ONLY from dev roots" → demote the whole dev closure.
- **Per-ecosystem sources:** package-lock.json (`dev: true` flags + edges) · poetry.lock (`category`/groups + deps) · composer.lock (packages vs packages-dev — partially done, extend to closure) · Gemfile.lock (groups NOT in lock — combine Gemfile groups with lock edge graph) · Pipfile.lock (`develop` section) · go.mod (no dev concept — skip) · cargo (dev-dependencies in Cargo.toml + Cargo.lock edges).
- **Safety analysis is the crux:** a package reachable from BOTH a dev root and a prod root must NEVER demote (graph reachability from prod roots wins). Truncated/unparseable lock → refuse everything. Property test: adding any prod edge can only ever REDUCE the demotion set.
- **Validate:** 2 real apps per ecosystem implemented (reuse corpus apps: express/fastify npm, saleor poetry, paperless Pipfile, symfony-demo composer, discourse/mastodon gem), corpus rescore, tripwire clean.

## Arc 2 — DEPENDENCY-SOURCE IMPORT GRAPHS (lever 1; biggest win, biggest build)
> **Motivating examples already found (Arc 0 labelling, 2026-07-02):** (a) caddy CVE-2024-24786 protobuf — cel-go's `object.go` calls `protojson` transitively from caddy's first-party celmatcher, invisible to first-party import grep (labelled unreachable → corrected to module). (b) x/net/idna compiles into gitea via `certmagic` and into caddy's h2 client transport, so the first-party-absence demotion was unsound and had to be REMOVED — Arc 2 restores it with a real transitive proof. (c) The Go model's `unlessDeps`-free subpackage gates and the Django model's hard-coded `unlessDeps` lists (weasyprint→fontTools, captcha→ImageFont, paramiko→crypto-ssh) all become computed facts once dependency sources are scanned.

- Extend the submodule gates from first-party-only to TRANSITIVE proof: fetch dependency *sources* (npm: pacote — already a dependency for backfill-trees; pypi: sdist/wheel from PyPI; gem: .gem from rubygems; go: module proxy zip), extract THEIR import edges (the same comment-stripped extractors, per-ecosystem), and answer "does ANY package on a prod path import submodule X?"
- Kills the conservative refusals (`unlessDeps` hard-lists like weasyprint→fontTools, captcha→ImageFont become computed facts) and unlocks Go-quality proofs in Python/Ruby.
- **Scoping guards:** bounded fetch (top-N deps by relevance to open gates, size caps, registry-tarball cache under the existing Redis/disk cache patterns) · offline/no-network scan degrades to today's behavior (refuse, don't guess) · never fetch for ecosystems without a gate in play.
- **PLAN + REVIEW mandatory before code** — this arc touches network, caching, and the fail-safe doctrine at once.
- **Validate:** the weasyprint/fontTools and captcha/ImageFont cases flip from hard-coded to computed on saleor/paperless; corpus rescore; tripwire clean; scan wall-time budget respected (≤+20% per repo).

## Arc 3 — RESIDUAL-FN FIXES (lever 7; moves the north star directly)
- **3a. Express library-shape (5 FNs):** qs/body-parser/path-to-regexp×2/cookie are `module` when express is scanned standalone but labelled `function` — the label assumes a consuming app. Options to evaluate in the arc plan: (i) library-mode detection → score against a synthetic consuming harness, (ii) re-label with a consuming-app fixture repo (corpus change, not engine), (iii) npm-server always-on model covers them (defer to Arc 4b). Decide in PLAN with the corpus-integrity lens — do NOT relabel to flatter the metric.
- **3b. Petclinic trio (22735 SSE / 22731 actuator / 40477 thymeleaf):** coarse-oracle-vs-precise-engine cases parked earlier; re-triage against the current engine, either fix the engine (feature-presence promotion) or document the oracle correction with evidence.
- **Exit:** app-shaped silence-FN < 42.86% on the same labelled set, or each residual explicitly adjudicated with file:line evidence.

## Arc 4 — NEW ECOSYSTEM MODELS (lever 3; the proven playbook × 5)
Order by (real-user impact × triage cost): **4a Flask/FastAPI** (reuses the Django gatherer infra — manifests/imports identical, different promote set) → **4b npm-server** (Koa/Nest/Fastify; likely absorbs the express library-shape FNs) → **4c Laravel** (new gatherer, composer infra exists) → **4d cargo** (server crates: actix/axum/rocket) → **4e nuget/ASP.NET** (biggest new-infra cost, last).
- Each: pick dev app → scan → subagent triage of every module finding → model (promote small + high-precision, demote provable) → **two-app validation** → corpus +2 repos → rescore + tripwire.
- Each model is its own PLAN→REVIEW→IMPLEMENT cycle (they're a session-arc each; Django took one).

## Arc 5 — ADVISORY-SYMBOL SCOPING (lever 5; generalizes the models)
- **5a. OSV structured data first (cheap):** Go advisories carry `ecosystem_specific.imports` (affected packages/symbols!) — consume it directly instead of summary regexes; check equivalents for PyPI (`affected[].ecosystem_specific`)/others. This alone may replace half the hand-written patterns with authoritative data.
- **5b. Patch-diff mining (build):** for a CVE with a known fix commit/range, diff the patched files → affected symbols → gate on "does any (transitively-proven, per Arc 2) import/call path touch those symbols". Start as an offline enrichment pipeline writing per-CVE symbol hints to a table the classifier reads; per-ecosystem rollout behind the fail-safe doctrine (no hint → today's behavior).
- **Validate:** re-run the 9-app corpus with symbol gates on; measure how many hand-written rule rows become redundant (deleted rows = maintenance win); tripwire clean.

## Arc 6 — PER-CVE TAINT SPECS (lever 4; the confirmed tier)
- Target the highest-depscore stuck-`module` CVEs across corpus apps (actionpack open-redirect, activerecord serialize-RCE were the named examples; re-rank against current corpus).
- Each spec: framework-models YAML source/sink/sanitizer entry + fixture + `taint-engine:validate` + a corpus app where it fires (module→confirmed WITH a flow) and one where it correctly does NOT.
- Batch of ~5-10 specs, then reassess ROI vs Arc 5's mined symbols.

---

## Loop mechanics
- **Heartbeat:** ScheduleWakeup (~30min) re-enters the loop if a turn ends idle; background scans re-invoke on completion. Prompt: read THIS file + the ledger → `git log` → continue at the current arc/checkpoint.
- **Compaction recovery:** this file (sequencing) + `reachability-loop-LEDGER.md` (journal) + memory anchor `corpus_noise_reduction_state.md` (pt14 carries this directive) + worktree git log.
- **Ask-Henry triggers (otherwise don't stop):** any corpus re-labelling that could look like grading our own homework (3a option ii) · any new external infra cost (registry fetch volume in Arc 2 beyond cache-friendly) · PR timing · anything destructive.
- **Done =** Arcs 0–6 implemented+validated or explicitly parked with reasons in the ledger; final full-corpus rescore + numbers table; then ask Henry about the PR.

## Progress
- [x] Arc 0a corpus-diff tripwire — `scripts/corpus-diff.ts` (`a7dcd0a1`), validated on real pre/post-Django saleor runs (18 reviews / 5 promotions / 0 alarms)
- [x] Arc 0b labels — 4/6 apps landed (caddy 43 + gitea 60 + mastodon 137 + discourse 157 = 448 CVEs total, adversarially verified). saleor/paperless-ngx remain unlabelled (pypi, measurement-only). 5 engine fixes + 1 Gate-3 silence-FN caught & fixed. Real number: precision 77.94%, app-shaped FN 45.6%/361.
- [ ] Arc 0c Java/PHP 2nd-app retrofit
- [ ] Arc 1 lockfile dev-closure
- [ ] Arc 2 dependency-source import graphs
- [ ] Arc 3 residual FNs
- [ ] Arc 4a Flask/FastAPI · [ ] 4b npm-server · [ ] 4c Laravel · [ ] 4d cargo · [ ] 4e nuget
- [ ] Arc 5 advisory-symbol scoping
- [ ] Arc 6 taint specs batch
