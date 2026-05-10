# Depscanner Hardening Report

**Started:** 2026-05-08
**Status:** In flight (Day 1)
**Last updated:** 2026-05-08 — wave 1 mostly harvested (6/7); fix-agent #1 in flight
**Worktree:** `worktree-depscanner-hardening` @ origin/main `c44d070`

---

> **Living document.** Sections fill in as the marathon progresses. The end-of-marathon snapshot becomes the canonical depscanner reference.

---

## Executive summary

Day 1: pipeline map produced, error-logging audit found 1 P0 + 6 P1 swallow patterns (fix-agent #1 in flight), validation-coverage audit on rule-generation found 2 *additional* P0s (rule-gen monthly budget cap was non-functional in prod; prompt-injection signal is silenced) and 6 more P1s. Three of four competitive research preflights returned. Bottom line: depscanner is architecturally novel on two axes (AI-generated per-org CVE rules, integrated fix agent) but has measurable gaps on framework-spec breadth (Java/non-npm), enterprise table-stakes (custom IaC rules, OpenVEX consumption), and DAST CI/API-import ergonomics. (Historical note: an earlier pass framed BYOK economics as a third axis; BYOK was retired in `phase29_drop_byok.sql` — see commit `6705149`. All AI now runs on the platform key.)

---

## What the depscanner does today

The depscanner is Deptex's unified scanner worker. It runs as a single coroutine (`runPipeline` in `depscanner/src/pipeline.ts`) on Fly.io for production scans (Supabase storage backend) and on the local CLI for developer scans (PGLite storage backend). All storage access goes through a single `Storage` abstraction so the same code path runs in both modes.

### Pipeline stages (15)

| # | Stage | LogStep | Fatal? | Timeout | What it does |
|---|-------|---------|--------|---------|--------------|
| 1 | Clone | `cloning` → `clone` | yes | 15min, 3 retries | git clone or accept local workspace |
| 2 | Dependency resolution | `resolve` | no | 5–10min | npm/mvn/go/pip/cargo/gem/composer install |
| 3 | SBOM generation | `sbom` | yes | 15min, 3 retries | cdxgen `--profile research --deep` → CycloneDX |
| 4 | Dependency sync | `deps_sync` | yes | 5min | parse SBOM, upsert deps + edges, queue populate jobs |
| 5 | Usage extraction (tree-sitter) | `usage_extraction` → `framework_detection` | no | 5min | 8-language AST imports + framework entry points |
| 6 | Vuln scan (dep-scan + EPD) | `vuln_scan`, `depscan` | no | 180min | dep-scan CVE detection, classify reachability, recompute depscores |
| 7 | AI rule generation | `rule_generation` | no | 240s/CVE | per-CVE Semgrep rule via platform key (Anthropic/OpenAI/Google), validate, upsert |
| 8 | Cross-file taint engine | `taint_engine` | **HARD-FAIL** | 30min | Forward-propagation taint w/ FrameworkSpecs; emits `project_reachable_flows` |
| 9 | Reachability classification | (in `vuln_scan` line) | no | — | fuse taint flows + atom + semgrep into PDV `reachability_level` |
| 10 | EPD contextual scoring | `epd` | conditional | — | Execution-Path-Dominance; AI verifier as fallback |
| 11 | IaC + container | `iac_scan` | no | per-scanner | Checkov + Trivy config + Trivy image |
| 12 | Malicious-package | `malicious_scan` | no | — | feed lookup + GuardDog source analysis |
| 13 | Semgrep SAST | `semgrep` | no | 20min | semgrep `--config auto` |
| 14 | TruffleHog secrets | `trufflehog` | no | 10min | filesystem secret scan |
| 15 | Finalize | `finalize`, `uploading` | yes | 10min | atomic `finalize_extraction` RPC: removed_at + carry-forward + lifecycle events + SLA + active_extraction_run_id flip |

### Key architectural facts

- **Single coroutine, no `PipelineState` object.** Pipeline state lives in mutable locals. No resumability. Intentional for Fly.io scale-to-zero.
- **`finalize_extraction` RPC is the sole atomic boundary.** All mid-pipeline writes are provisional.
- **Taint engine HARD-FAILS.** Unlike all other soft-fail stages.
- **Async decoupling via QStash:** `populate-dependencies` + `backfill-dependency-trees`.
- **Local CLI mode** (`DEPTEX_CLI_MODE=1`) bypasses async population.
- **Heartbeat = 60s; stuck-detection = 5min; recovery cron reaps orphans 24h+.**
- **`extraction_run_id`** = keystone identifier across all per-run tables.

### Storage / AI / Telemetry

- `Storage` abstraction = `SupabaseStorage` (prod) ‖ `PGLiteStorage` (CLI). Same call sites both modes.
- AI: rule generation, FP filter, EPD verifier, spec inference all via platform keys read from worker env (`ANTHROPIC_API_KEY` / `OPENAI_API_KEY` / `GOOGLE_AI_API_KEY`). Cost cap enforced at per-org `monthly_budget_usd` (Redis-tracked) + per-CVE `max_wait_seconds`. (Historical: BYOK + `organization_ai_providers` retired in `phase29_drop_byok.sql` / commit `6705149`.)
- Telemetry: 3 layers — `extraction_logs` (per-step stream + Realtime sub), `extraction_step_errors` (ops triage sink, backed by `/admin/extraction-failures`), `project_repositories.error` (user-facing string). Plus per-stage telemetry on `scan_jobs` row.

---

## Findings & fixes

### P0 — Critical (3 findings)

| # | File:Line | Issue | Status |
|---|-----------|-------|--------|
| 1 | `rule-generation-step.ts:968` | `scan_jobs` telemetry upsert silently fails via `log.warn` (canonical pre-PR-#39 swallow pattern). | 🛠️ fix-agent #1 in flight |
| 2 | `rule-generation-step.ts` (whole module) | `ai_usage_logs` writes for `feature='rule_generation'` are **completely missing** — no insert site exists in any depscanner code. The monthly rule-gen budget cap reads from a column nothing populates → **the cap is non-functional in prod, runaway platform-key bills possible**. (Originally framed as a "BYOK" cost risk; post-`6705149` BYOK rip-out, the same code now bills our platform key, so the runaway-bill risk falls on Deptex.) | ⏸️ queued for fix-agent #2 |
| 3 | `rule-generation-step.ts:818-829` + `rule-generator/index.ts:384-398` | `prompt_injection_suspect` results return `rule:undefined`, get dropped at the persistence guard (line 869-871). Security signal lives only in worker stdout — no DB row, no `extraction_step_errors` entry, invisible in any UI. | ⏸️ queued for fix-agent #2 |

### P1 — High (12 findings)

**From error-logging audit (fix-agent #1 scope):**

| # | File:Line | Issue | Status |
|---|-----------|-------|--------|
| 4 | `with-timeout.ts:114-119` | `logStepError()`'s own insert failure → console only. Supabase outage = lost errors. | 🛠️ in flight |
| 5 | `pipeline.ts:583` | SBOM storage upload silently swallowed; downstream tools see "ready" with missing SBOM. | 🛠️ in flight |
| 6 | `pipeline.ts:843, 868, 878` | tree-sitter parse / usage-store / entry-point-write `log.warn` only, NOT persisted (asymmetric vs timeout path at line 884). | 🛠️ in flight |
| 7 | `pipeline.ts:2110` | Semgrep JSON parse error in empty catch — findings silently dropped. | 🛠️ in flight |
| 8 | `pipeline.ts:2456` | finalize RPC sync error → `log.error` only (vs async-throw path which IS persisted). Atomic-commit-critical. | 🛠️ in flight |
| 9 | `rule-generation-step.ts:892` | `persistGeneratedRule()` upsert failure in empty catch — generated rules lost mid-flight. | 🛠️ in flight |

**From validation-coverage audit (queued for fix-agent #2):**

| # | File:Line | Issue | Status |
|---|-----------|-------|--------|
| 10 | `rule-generation-step.ts:573-583` | `loadOrgExistingRuleCves` fails OPEN on Supabase error (returns empty Set → re-generate every CVE → platform-key cost amplifier). Should fail-closed like `readRuleGenMonthlySpend`. | ⏸️ queued |
| 11 | Sink-broadness guard | `isBroadSinkPattern` rejection is bundled into zod's `invalid_schema` — no structured `validation_breakdown.broad_pattern_attempts` counter. Can't see "models keep emitting too-broad sinks for CVE-X". | ⏸️ queued |
| 12 | `rule-generation-step.ts:866-871` | Pre-attempt failures (`no_advisory`, `no_fix_commit`, `fetch_failed`, `vuln_class_out_of_scope`) silently dropped — should persist stub rows so org-settings UI can render "we tried CVE-X; uncoverable because: X". | ⏸️ queued |
| 13 | `rule-generation-step.ts:445-451` | Aggregate provider-error warn (`≥25%` failures) lives only in worker stdout — should write `extraction_step_errors` row with `code='provider_outage_suspect'`. | ⏸️ queued |
| 14 | `validate.ts:142-167` | When `persistedSpecToEngineSpec` throws, the breakdown returns `schema_pass:true` but Gates 2/3 didn't execute — telemetry signal misleading. | ⏸️ queued (P3 actually but bundled) |
| 15 | Pattern syntax not pre-validated | `semgrep --validate` grammar gate retired with Phase 5; replacement engine pattern-compile validation is missing. Malformed `pattern:` strings reach Gate 2 and silently no-op. | ⏸️ queued |

### P2 — Medium

| # | File:Line | Issue | Status |
|---|-----------|-------|--------|
| ✅ | `validate.ts:142-167` (P2-B from validation audit) | Pattern syntax not pre-validated at the engine level — Phase 5 retired `semgrep --validate` grammar gate; replacement was missing. Malformed `pattern:` strings reach Gate 2 and silently no-op. | ✅ SHIPPED in `cbecc39` — new `pattern-syntax.ts` structural sanity check + ValidationBreakdown.pattern_compile_pass field. Validates 1,092 bundled patterns; rejects unbalanced delimiters / control chars / embedded newlines. 1889/1889 jest pass. |

### P3 — Low

| # | File:Line | Issue | Status |
|---|-----------|-------|--------|
| 16 | `framework-models/*.yaml` (~5% of patterns) | **Side-finding from pattern-syntax fix:** ~5% of bundled framework-spec patterns appear UNMATCHABLE by the engine's actual DSL. | ✅ RESOLVED in framework-pattern audit (Day 2 tick 7, 7th marathon commit). **Audit of all 1,633 bundled patterns: 0 confirmed-dead.** Every suspect shape is live via a per-language IR code path the structural validator doesn't trace: Java `new ProcessBuilder` (`java/ir.ts:313` `object_creation_expression`), C# `[FromBody]` (`csharp/ir.ts:725-744` attribute decorator IR), Rust `req.uri().path()` (`rust/ir.ts:984-1004` receiver-method composition), Rust `::` patterns (`rust/ir.ts:800` verbatim), Ruby backtick literals (tree-sitter preserved). 7 `redundant-with-prefix` Ruby sources kept as authorial documentation. **Critical guidance: do NOT tighten the pattern-syntax validator** — would regress 246+ Rust `::`, 8 Java `new TypeName`, 7 C# attribute sources, 4 Ruby backtick sinks. Reproducible audit script + per-pattern JSON committed at `docs/framework-pattern-audit.{md,json}` + `depscanner/scripts/framework-pattern-audit.ts`. |

### Verified non-issues

- **`extraction_job_id` stale-rename suspicion** — false alarm. Column deliberately kept that name in `extraction_step_errors`; FK correctly references `scan_jobs(id)`. Code (`with-timeout.ts:103`) is in sync.

---

## Test coverage

### Existing infrastructure
- Jest unit tests (`npm test`)
- **Snapshot fixture runner** (`npm run test:fixtures` → `test/snapshot.ts`) — the contributor-grade regression surface
- 88-CVE Qwen benchmark harness (cost-capped iteration)
- Reachability rules parameterized smoke
- CVE-targeted taint fixtures (`scripts/taint-engine-cve-targeted-fixtures.ts`)
- Cross-language Gate 2 jest wrapper

### Test coverage gaps identified (validation audit)

20 missing test cases identified — top priorities:
- **TG-1** (P0): `ai_usage_logs` insert happens after a successful generation (would have caught P0-A)
- **TG-2** (P0): `prompt_injection_suspect` produces a DB row (currently only asserts that `parseAndValidate` throws — not that runtime persists)
- **TG-3** (P1): Layer C provider-error retry actually retries on transient errors; no test exercises lines 319-432 of rule-generation-step.ts
- **TG-5** (P1): `loadOrgExistingRuleCves` failing open is INTENDED or not — no test pins behavior
- **TG-9** (P2): Engine `spec_load` failure in `validateRule` (line 142-167)
- **TG-10** (P2): `vuln_class_out_of_scope` does NOT trigger Layer B retry — no test pins this
- **TG-12** (P2): Pattern-syntax-failure (e.g. unbalanced paren) propagates through engine
- **TG-19** (P2): `withOsvIdsSubstituted` is the SOLE assignment site (osv-id-on-sink injection contract)

### Snapshot infra fixes (Day 1 tick 4 — `2048b77`)

PR 1 of the contributor-test-infra-plan roadmap shipped:
- **`finalize_summary` plumbed through CLI** — `pipeline.ts` now captures `finalize_extraction` RPC's jsonb return into a new `RunPipelineResult` interface; `cli/scan.ts` passes it to `writeOutputs()`. Production worker (`src/index.ts:44`) discards the return as before — no production change needed. CLI now produces non-null `summary.json.finalize_summary` for the first time.
- **Volatile-field ignore list** — `epss_score`, `cvss_score`, `cisa_kev`, `published_at` added to `DEFAULT_IGNORE_FIELDS` in `test/snapshot.ts`. Fixes daily contributor-regen drift.
- **Semgrep silent-pass mystery RESOLVED** — see below.

### Semgrep snapshot silent-pass — investigation result (Day 1 tick 4)

The audit had flagged that `semgrep.json` is missing from every fixture's `snapshots/` dir but the runner reads `outputs = readdirSync(resultDir).filter(.json)` and should emit "new file (not in snapshot dir)" mismatches. Investigation confirmed: **the audit was correct, and the suite WOULD fail today if it ran.** Re-reading `test/snapshot.ts:268-322` carefully showed no per-fixture allow-list, no glob exclusion, no early-skip. The diff loop is exactly as it appears.

**Resolution: the suite is latent.** It's gated by `npm run docker:build` per the runner header (`snapshot.ts:24` — "Prereq: the CLI image must be built first"); invoked via `bin/deptex-scan` which is the Docker wrapper. On contributor / CI systems without the Docker image built, the suite never executes. The audit surveyed committed snapshot dirs without actually running the suite to observe the failure.

Secondary corroboration: `cli/output.ts:105` unconditionally writes `semgrep.json` regardless of finding count, so even fixtures with 0 semgrep findings would produce a `semgrep.json` in result-dir and trip the "new file" check.

**Henry's decision needed (open question):**
1. **Commit `semgrep.json` snapshots** via Docker `--update` (also `generated_rules.json` + `rule_generation_telemetry.json` if those appear). This is the right answer if the goal is "snapshots reflect the full output surface."
2. **Change the runner** to emit "new file" as a warning OR gate diffs to `snapshotDir`-driven iteration (`for (const file of readdirSync(snapshotDir))`). Trade-off: spurious new outputs go undetected.

Recommendation in agent's report: option 1 — semgrep findings should be deterministic on these fixtures, not legitimately volatile.

### Snapshot coverage gaps (Day 1 snapshot-coverage audit)

The snapshot fixture runner (`npm run test:fixtures` → `test/snapshot.ts`) is the contributor-grade regression surface. The audit found it has decent breadth on top-level vuln fields BUT major holes on the load-bearing fields and infrastructure-level latent bugs:

**Critical infrastructure bugs:**
- **`reachable_flows.json = []` in EVERY fixture** — the entire taint-engine output (60% of depscanner) has zero snapshot coverage. `flow_signature_hash`, `sanitizer_line`, `osv_id` round-trip, `entry_point_tag`, `flow_length`, `reachability_source` — none pinned anywhere.
- **`semgrep.json` is silently absent from every `snapshots/` dir** but `output.ts:105` writes it on every run. Runner reads `outputs = readdirSync(resultDir)` and demands matching expected files (`snapshot.ts:303-306`). Either every fixture run with `semgrep_count > 0` (test-npm/python/java/go all qualify) is currently FAILING the snapshot suite, OR the suite has been silently passing on Semgrep gaps. Latent failure to investigate.
- **`generated_rules.json` + `rule_generation_telemetry.json` never produced** by any fixture (no fixture triggers AI rule generation). The new `validation_log.terminal_reason` field fix-agent #2 added (`rule-generator/validate.ts:113`) has zero snapshot coverage.
- **`finalize_summary` always `null`** — `cli/scan.ts:138-147` doesn't pass `finalizeSummary` to `writeOutputs()`. Field is wired through `WriteOutputsOptions` but dead-wired by the caller. Vulnerability_updates / SLA / lifecycle event regressions are invisible.

**Pinned-but-degenerate values (false confidence):**
- `vulns.json[].reachability_level` is always `"module"` everywhere — a regression to blanket `"module"` would PASS
- `vulns.json[].is_reachable` is always `true` — same degenerate
- EPD fields (`epd_factor`, `entry_point_classification`, `contextual_depscore`, etc.) all `null` or `"pending"` — classifier branches invisible
- Suppression / risk-accept fields pinned `false`/`null` but never `true`/populated

**Volatility hazards:**
- `epss_score` / `cvss_score` / `cisa_kev` / `published_at` NOT in `DEFAULT_IGNORE_FIELDS` — fetched live in pipeline → contributor running the suite a day after committed snapshots WILL diff-fail. Fix: either add to ignore list, OR stub EPSS/NVD fetch in local-mode behind `DEPTEX_OFFLINE=1`.

**Coverage matrix gaps:**
- 4 of 8 supported tree-sitter languages (ruby, rust, php, csharp) have ZERO fixtures
- 34 framework detectors documented; only 1 (gin in test-go) is exercised
- Vuln classes: SQLi/XSS/path-traversal/SSRF/open-redirect/proto-pollution all have 0 end-to-end flow coverage
- `secrets.json: []` in test-npm despite `summary.json: { secrets_count: 1 }` — contradiction worth a follow-up

**Contributor regen UX problems:**
- No `npm run test:fixtures:update` script alias — must remember `tsx test/snapshot.ts --update`
- No `--diff-only` / `--print-changed` dry-run flag — `--update` is silently destructive
- Diff truncates at 10 lines silently — large fixture diffs (~1000 leaf paths) get hidden behind "...and N more"
- Pre-req `npm run docker:build` has no automated freshness check
- Workspace-rename recovery (`snapshot.ts:150-160`) leaves `snapshots/` in tmpdir on crash with no recovery doc
- No CI guard surfaces snapshot drift visibly

**Speed:** test-empty + test-minimal-npm = 1-2 min (default). With `--include-slow` = 12-25 min (Docker bind mounts on Windows are slow). Editing one framework spec still pays full cdxgen + dep-scan cost per fixture.

### Contributor-grade regression flow

Goal: an OSS contributor changes one framework spec and proves in <2 min locally that nothing else broke.

**Plan written:** `docs/contributor-test-infra-plan.md` (Day 1 tick 3, ~470 lines, 7-PR roadmap totalling ~10-13 dev-days). Key design decisions made in the plan:

- **Reachable fixture (PR 3):** lodash CVE-2021-23337 on Express (NOT Spring — JS path is faster validation). Reuses the engine's `js-lodash-template-injection` fixture shape with a real Express handler. Honest effort estimate: M-L (2-5 days) given 4 named risks: (a) engine emits zero flows on the new fixture, (b) dep-scan VDR may miss the CVE, (c) Express middleware extraction is unverified for this handler shape, (d) `flow_signature_hash` instability across reruns.
- **Volatility (PR 1.3):** filter EPSS/CVSS/cisa_kev/published_at via `DEFAULT_IGNORE_FIELDS`, **NOT** stub via `DEPTEX_OFFLINE=1`. Rationale: stubbing introduces a stale-mock failure mode the snapshot suite can't catch.
- **Semgrep snapshots (PR 1.2):** commit `[]` snapshots, **NOT** allow-list. Allow-list hides Semgrep version-bump signal; commit makes it explicit. Open caveat: the runner appears to silently pass on missing `semgrep.json` today — cannot be reconciled from reading alone, needs investigation in PR 1.
- **Speed (PR 5):** `--tag=express` targeted fixture selection, **NOT** cdxgen output caching (rejected: invalidation surface too risky), **NOT** in-process mock mode (rejected: skips CLI integration boundary).
- **CI (PR 7):** hard-fail on snapshot drift in CI + PR-comment via `actions/github-script`. Today's CI only runs type-check + preflight (`.github/workflows/test.yml:63-91`).
- **`finalize_summary` plumbing (PR 1.1):** `pipeline.ts:2501-2516` discards the RPC's `data` return; `finalize_extraction` is `RETURNS jsonb` per `schema.sql:3519`. ~12 LOC across 3 files.

**7-PR roadmap, smallest-first:**
1. PR 1 — snapshot infra surgical fixes (3.1-3.3 bundled): plumb `finalize_summary`, commit semgrep.json snapshots + investigate the silent-pass, EPSS/CVSS volatility filter
2. PR 2 — regen UX: `npm run test:fixtures:update` + `--diff-only` + raised diff cap + workspace-rename recovery doc + Docker freshness check
3. PR 3 — the reachable fixture (lodash CVE-2021-23337 on Express)
4. PR 4 — pre-push checklist + CONTRIBUTING.md depscanner section
5. PR 5 — `--tag=` targeted selection + per-fixture metadata
6. PR 6 — minimum fixtures for ruby / rust / php / csharp
7. PR 7 — CI hard-fail + PR comment

**8 open questions queued for Henry's first check-in** (full list in `docs/contributor-test-infra-plan.md` Section 10): stub-vs-filter call, first reachable-fixture language choice, hard-fail vs commit-status during CI burn-in, image-freshness check scope, tag taxonomy flat-vs-hierarchical, snapshot-park location, Docker prebuild auto-vs-error, `finalize_summary` ignore-paths set.

---

## Framework + language coverage

### Coverage matrix
| Language | Framework | Spec? | Fixture? | Tests pass? | Notes |
|----------|-----------|-------|----------|-------------|-------|
(filled by coverage track in wave 2)

### Gaps closed during the marathon

---

## Real-corpus benchmark numbers

### Corpus selection
15–30 representative OSS repos across npm/pypi/maven/gem/golang.

### Per-section recall / precision / cost / time
### Noise rate (false-positive rate of confirmed-tier findings)

### Comparison to 2026-05-05 88-CVE baseline
Pre-marathon: npm 62%, pypi 9%, gem/golang/maven 0% (global 26.1%).

---

## Documentation

### Long-form depscanner doc — `docs/depscanner.md`
(authored as marathon progresses; per-section "how it works" + "future work")

### CONTRIBUTING.md updates
"Before you push" checklist · how to run snapshot suite · how to regen snapshots · how to add a framework spec · how to add a CVE-targeted spec · how to add a new language module.

### Failure-mode taxonomy
Enumerated `classifyError` codes, what each means, what triggers it, where it surfaces.

---

## Refactors performed

(only sections that genuinely needed it — what was the smell, what was changed, why; no churn-for-churn)

### ✅ All 3 refactors SHIPPED (Day 3, 2026-05-09 afternoon)

| # | Commit | Subject | Outcome |
|---|--------|---------|---------|
| 3 | `d77704e` | PipelineStageRunner consolidation | 12/15 pipeline steps converted to shared `runStage()`; 3 left inline (taint_engine, epd, sbom_upload — documented). +379/-288 LOC. |
| 1 | `2ab09a9` | pipeline.ts decomposition | **2535 → 176 LOC.** 15 step modules at `depscanner/src/pipeline-steps/` (clone, resolve, sbom, deps-sync, usage-extraction, asset-tier, dep-scan, rule-generation, taint-engine, reachability, iac-container, malicious, semgrep, trufflehog, finalize). Plus inline bug fix surfaced by refactor (missing `updateStep('deps_synced')` between SBOM and deps_sync). |
| 2 | `4d910a7` | rule-generation-step → CveGenerationCoordinator | **1130 → 53 LOC** (pure facade). 8 helper modules + coordinator class at `depscanner/src/cve-generation/`. `RateLimitGate` class replaces a mutable closure. |

All zero behavior delta. All gates green throughout — backend jest 1909 → 1914 (+5 from snapshot bootstrap tests, 0 regressions).

### Targets identified (Day 1 refactor-scan)

The Day 1 refactor-scan recon agent flagged **3 priority-1 targets** with concrete decomposition seams. Sequencing recommendation: tackle small/low-risk first to unblock the larger ones.

1. **`pipeline.ts:411–2507` — Monolithic `runPipeline()`** (15 stages in one coroutine). Decompose into named stage handlers (`stageClone()`, `stageSbom()`, `stageTaintEngine()`, etc.) sharing a `PipelineContext` object, dispatched by a `StageRegistry`. Effort: M (~3-4 days). Risk: Med.

2. **`rule-generation-step.ts:148–500` — Fractured step orchestration after the recent surgical fixes** (5+ concerns embedded; per-CVE retry loop is a 90-line nested blob). Extract a `CveGenerationCoordinator` class with methods for `loadSettings()`, `applyTriggerPolicy()`, `runBudgetGate()`, `generateBatch()`, `persistResults()`. Effort: M-L (~4-5 days). Risk: Med-High (file just patched twice — refactor risks subtle regressions).

3. **Timeout + error-handling boilerplate** (41 call sites in pipeline.ts, plus duplicated subprocess spawn pattern in `trivy.ts`/`checkov.ts`). Wrap in a `PipelineStageRunner` class that internalizes `withTimeout` + `logStepError` + `classifyError` + heartbeat. Effort: S-M (~2 days). Risk: Low (mechanical wrapping).

**Cross-cutting smells (lower priority):**
- Error classification duplication (`classifyError` + `logStepError` repeated ~47 times) — folds into target #3
- Subprocess heartbeat duplication (4 sites) — extends `runScannerSubprocess()` to dep-scan + semgrep
- Batch query + upsert pattern (5 verbatim copies in `deps_sync`) — `BatchUpsertHelper` class; nice-to-have for future

**Defensible-but-aging (defer):**
- `scanners/orchestrator.ts:101–300` — kill-switch + credential-fetching coupling. Sustained Redis outage silently disables container scanning.
- `taint-engine/fp-filter.ts` (1053 lines) — god-module with HTTP retries + classification logic mixed. Defensible while filter is in pilot rollout.

**NOT refactor targets** (called out so future agents don't burn cycles):
- `rule-generator/` modules (4 files, ~100 lines each) — well-factored, leave alone
- `taint-engine/propagate-core.ts` + language drivers — proper boundary already in place; "split it" temptation is a trap
- `cli/` modules — small + focused, good state

---

## Competitive analysis

### CVE reachability — vs Snyk, Endor Labs, Aikido, Socket/Coana, GHAS, Semgrep, Mend, Sonatype, Veracode, Apiiro, Checkmarx

**Where we are.** Architecturally MORE languages than any single commercial competitor advertises function-level reachability for (8 vs Snyk's 1, Coana's 6, Endor's marketed-not-published). Per-org AI-generated CVE-targeted Semgrep rules + integrated fix agent (Aegis) are NOT shipped by anyone else publicly. **But our 88-CVE benchmark is 26.1% global (npm 62%, pypi 9%, gem/golang/maven 0%) and that's our central problem. Bottleneck is FrameworkSpec coverage outside npm, not engine quality.** (Historical: a previous version of this section listed BYOK economics as a third differentiator. BYOK retired in `phase29_drop_byok.sql` — pricing strategy is now pure platform-key SaaS; that lever is gone.)

**Themes — what's missing on our side (ranked by deal-blocking leverage):**
1. **Framework coverage breadth** (HIGH — recall floor) — Java/JVM and Python framework gaps block enterprise demos
2. **Reflection / dynamic-feature handling** (HIGH — Java-heavy customers) — Coana explicitly handles this; we don't
3. **Enterprise compliance posture** (MEDIUM-HIGH) — SOC 2 Type 2, SAML/SCIM, FedRAMP-readiness
4. **Pre-scanned CVE-flow library** (MEDIUM — speed + trust) — Endor's pre-computed reachability
5. **Curated vulnerability database beyond GHSA** (MEDIUM)
6. **Cross-scanner unified reachability** (MEDIUM — Aikido pattern)
7. **Public CVE-corpus benchmark** (MEDIUM — but rare in market — opportunity)
8. **Big-customer logos** (BRAND) — pre-revenue gap

**Where we can lead — bets:**

*Quick wins (≤1 month):*
1. **Publish the 88-CVE benchmark.** Nobody does this. Even at 26.1%, "first SCA vendor to publish recall against a public CVE corpus" + roadmap to 50%+ owns the methodology-transparency narrative. **Highest-leverage marketing move.**
2. **AI-generated CVE rules as the headline.** No competitor has this — Endor curates manually, Semgrep curates manually, others have nothing.
3. ~~**BYOK pricing differentiator.**~~ (Retired 2026-05-09 in `6705149` — Henry committed to platform-key-only pricing. The TCO-win-via-BYOK angle is no longer ours; competing on per-seat economics directly is now the lane.)
4. **Reachability tier transparency.** Our 5 tiers (`confirmed`/`data_flow`/`function`/`module`/`unreachable`) > Endor's binary > Socket's tiers in honesty.

*Long moats (6+ months):*
1. **Open-core engine.** Coana/Endor/Snyk are all closed. Open-sourcing the taint engine + framework specs creates a contribution flywheel for the framework-coverage problem (Theme 1) closed competitors can't match.
2. **Aegis fix integration.** All competitors stop at "we found the reachable vuln." We can plan-then-PR.
3. **Per-org rule learning loop.** AI rule generation is one-shot today (15-20% ceiling per `ai_rule_generation_ceiling.md`); feedback retry could push to 40-60%.
4. **Java-framework spec catch-up sprint.** Spring/Quarkus/Micronaut/Vert.x/Hibernate. 8-week sprint moves us from 0% → 40%+ on Java.
5. **Public scoreboard.** Quarterly recall against the 88-CVE corpus + invite competitors to submit. Asymmetry favors us.

**Public benchmark claims to know:** Endor "97% noise reduction" (third-party citation, no methodology). Snyk "various AI techniques" (no number). Socket/Coana "up to 90% FP elimination" (vendor). Aikido "95% fewer alerts" (vendor). Semgrep's 1614→31 Dependabot study (~2% reachable; the most-cited public number). JFrog "78% non-applicable on top DockerHub images" (the rare cite with methodology).

### IaC + container — vs Snyk, Wiz, Aikido, Aqua/Trivy, Anchore, Prisma, Sysdig, Lacework, Tenable, KICS, JFrog, Endor, Chainguard, GitLab

**Where we are.** Competent OSS-baseline scanner with smart caching. Trivy + Checkov 3.2.420 + Trivy image + crane HEAD-only digest probe + GHCR via GitHub App. IaC v2 Phase 1 shipped. **Phase 2 OS reachability plan (DT_NEEDED + dlopen + OpenVEX + shell-presence Tier B) is on paper — none of M0–M12 shipped.** No runtime sensor; no eBPF; no app-code-into-OS-package call graph; no "package not loaded" filter.

**Themes — what's missing:**
1. **Custom IaC rules — table stakes we haven't shipped.** Snyk, Wiz, KICS, Tenable, Bridgecrew all let customers write custom Rego. We ship vanilla Checkov + Trivy with no per-org rule extension. **Most common "you're missing X" head-to-head finding.** Cheap to fix because Checkov already has a custom-rules mechanism.
2. **OpenVEX consumption (not just generation).** Anchore, Wiz (via Docker Hardened Images), Trivy 0.51+, Microsoft Azure Linux all consume vendor-asserted VEX. We don't. **Highest-leverage suppression mechanism that doesn't require runtime tracking.** Phase 2 plan includes it; ship it.
3. **Base-image upgrade recommendation.** Snyk's bread-and-butter. JFrog + Anchore have versions. Trivy gives us the data; missing = Dockerfile-rewrite advisor + Aegis fix integration. **Quick win + Aegis differentiator.**
4. **Drift detection.** Snyk/Bridgecrew/Tenable have it. Lower priority — high cost-to-build.
5. **OS-package reachability.** Sysdig + Lacework (agent), Endor (instrumented + Oct-2025 pre-computed), Prisma (Binaries column), Wiz (eBPF). We have Phase 2 plan, nothing shipped. JFrog's 78% non-applicable benchmark is the bar.
6. **Per-CVE applicability scanners (JFrog model).** Custom analyzer per CVE family. Our reachability rule packs are conceptually identical — extend to OS CVEs.

**Where we can lead — bets:**

*Quick wins:*
1. **Ship custom IaC rules.** Checkov has the mechanism; expose via `iac_policy_code` (parallel to `package_policy_code`). Closes table-stakes gap. Effort: small. **Ship before Phase 2 OS reachability.**
2. **OpenVEX ingestion.** Trivy already supports VEX. Need (a) ingest VEX files attached to images, (b) ingest VEX from known publishers (Chainguard, Docker Hardened Images, Microsoft Azure Linux, Anchore). **Highest-leverage agentless win.**
3. **Aegis-driven base-image upgrade PRs.** Snyk *recommends*; we *fix*. Wire Aegis Fix Agent to take Trivy's base-image-upgrade output → auto-PR Dockerfile change. **No CNAPP plays this — they're built for ops, not dev.**

*Long moats:*
4. **Static OS reachability via DT_NEEDED + dlopen.** The Phase 2 plan. Differentiation pitch: agentless (Sysdig/Lacework/Wiz/Endor instrumented all need a sensor), reproducible (DT_NEEDED is deterministic from binary), auditable (regulator can re-derive). Honest about limits: catches direct/transitive linked sharedlib only; dlopen + Python imports + Ruby native gems + JNI are gaps. Shell-presence Tier B is the hedge ("we don't know — but the package can't be reached at all if there's no shell to invoke it"). **Defensible Tier B story no other vendor publishes.**
5. **Per-CVE applicability rule packs for OS CVEs.** Same shape as our SCA reachability rules. JFrog charges for this; we do it in the open.
6. **Open OpenVEX publishing.** If we PUBLISH OpenVEX statements per-org for false-positives our analysis suppresses, we become an OpenVEX publisher in our own right. Chainguard / Microsoft / Anchore-tier positioning.

**Skeptic's note.** Vendor noise-reduction figures (78% / 90% / 95%) all use different denominators; methodology rarely reproduces. Don't compete on a single number. **Compete on methodology transparency** — publish per-CVE outcomes, exposed rules, the shell-presence Tier B logic.

**Plan landed (2026-05-09 tick 9):** `docs/iac-custom-rules-plan.md` — 437-line, 6-PR design plan for `iac_policy_code` (parallel to `package_policy_code`). Trivy + Checkov findings flow through the existing flow-code-sandbox (isolated-vm) for user-authored decision logic. **~95% infra reuse** — engine, validator, SSRF-fetch, helpers, change-history table, RBAC, Monaco editor, Test/Save flow all reused; ~280 LOC new TS + ~25 LOC SQL + ~250 LOC frontend (mostly mirrored). Three additive columns + one new org-level table is all the schema work — IaC v1/v2-P1 surface is layer-on ready (`upsertIaCFindings` is the natural splice point). 8 starter rules drafted (block public S3, KMS-RDS, K8s privileged, public-LB scope, Trivy INFO downgrade, CIS-AWS, github_actions review, tier-1 severity escalation). PRs 1-5 = customer-visible in ~5-6 dev-days; PR 6 = re-eval-on-edit. **Zero conflict with v2 P2 reachability moat** — different table (`project_iac_findings` vs `project_container_findings`), different pipeline stage; can ship in parallel. Cross-cutting note: `framework='dockerfile'` IaC findings (misconfigs) distinct from container-image OS-CVE findings v2 P2 decorates. 6 open questions for Henry (decision vocabulary 2 vs 3-state, severity_override placement, PR 6 timing, project-level overrides, dockerfile/v2-P2 overlap, compliance bench reservation).

### DAST — vs StackHawk, Snyk DAST/Probely, Veracode, Acunetix/Invicti, Burp Suite Enterprise, Detectify, Bright Security, Aikido, Black Duck, Nuclei/PDCP, secureCodeBox

**Where we are.** ZAP wrapped via Automation Framework, sha256-pinned pscanrules-Alpha+Beta baked in (PR #27, 2026-05-05). v2.1c (Nuclei) reserved in CHECK constraint, plan written, not shipped. Cross-link from DAST findings to SCA `project_dependency_vulnerabilities` exists via `crossLinkFinding` BUT does **not yet flip `reachability_level='confirmed'`** — that runtime-tier-flip is the v2.1c differentiator. Auth: form / JWT / cookie only. **No OAuth client-credentials, no SAML, no MFA, no SSO redirect, no recorded login.** **No API spec import** (no OpenAPI, GraphQL, Postman, RAML, gRPC). **No CI integration** (no CLI, no GitHub Action, no PR-comment, no SARIF, no fail-the-build threshold).

**Themes — what's missing (ranked by leverage):**
1. **API spec import (OpenAPI + GraphQL introspection)** — HIGHEST. Every competitor has it. ZAP automation framework already supports `openapi:` / `graphql:` jobs natively. ~1 week of work.
2. **CI integration** — GitHub Action + PR comment + fail-build threshold + SARIF. StackHawk's entire moat is YAML-in-repo + PR comments — we cannot leave that uncontested.
3. **OAuth client-credentials + OIDC redirect handling** — modern APIs need this. Small-diff.
4. **Recorded login / browser-driven auth** — Burp's 2025.10 recorded-login editor sets the bar. Our v2.1d.
5. **AI-driven endpoint discovery from source code** — StackHawk's HawkAI. **CRITICAL INSIGHT: we already extract `project_entry_points` via tree-sitter. Synthesizing an OpenAPI spec from those = HawkAI parity without an LLM.**
6. **Proof-based scanning / payload re-validation** — Bright + Invicti's claim. ~1 sprint.
7. **SARIF output + GitHub code-scanning surface** — free wins. Free interop.

**Where we can lead — bets:**

*Two distinct moats:*

**Moat 1 (in flight): Cross-link DAST evidence to SCA tiering — finish v2.1c.** No competitor flips SCA `reachability_level` based on DAST evidence. Requires (a) tree-sitter framework-aware extraction (have), (b) per-CVE reachability rule corpus (have, 100+ packs), (c) cross-link URL→handler→purl→PDV (have), (d) CVE-aware DAST engine (Nuclei). Stack of four; competitors would need to acquire/build every layer. **Ship v2.1c as planned + tier-flip from ZAP findings, refresh-on-rescan, KEV partial index, runtime-evidence detail panel.**

**Moat 2 (greenfield): Playwright-HAR recorded auth — v2.1d.** Burp's 2025 implementation runs in their proprietary browser harness — not reusable. ZAP's HAR import is clunky. **Bet:** ship v2.1d as a Playwright-trace upload flow:
1. User runs `npx @deptex/dast-record https://app.example.com` locally — opens Playwright codegen, records login, exports `auth.har` + `storageState.json`, uploads via existing dast-credentials AES-GCM surface.
2. Worker mounts HAR + storage-state into headless Playwright, replays login redirects (handles SAML, OIDC, MFA-via-pre-recorded-token), captures cookies/tokens.
3. Hands to ZAP/Nuclei via existing cookie/JWT replacer.
4. Re-validates session at scan-start via `loggedInRegex` (matches Burp's pre-scan auth check pattern).

Why this leapfrogs Burp: open-source recordable (Playwright codegen) > proprietary recorder; HAR + storageState = standard browser-debug format; reuses our existing encryption-at-rest; storage-state-replay handles MFA without an in-flow solver. Pairs with SCA cross-link: behind-login findings now flip SCA tiers too.

*Quick wins to bundle:*
- **OpenAPI URL ingestion** — add `api_spec` to ScanRequestBody, emit ZAP `openapi` job. Ships with v2.1c.5 cleanly.
- **GitHub Action stub** — thin shell that POSTs to `/scan` + polls + SARIF download.
- **OAuth client-credentials auth strategy** — fourth `kind`. Trivial.
- **SARIF output format** — maps from finding shape to SARIF 2.1.0. Free interop.
- **Endpoint discovery from `project_entry_points` → synthetic OpenAPI** — HawkAI parity without an LLM. **High-leverage; we already have the data.**

*Actively NOT chase:* SAML/SSO redirect-as-first-class (covered by recorded-HAR moat); IAST agent (out of scope for open-core); proof-based by re-exploiting (high-effort, marginal gain over cross-link tier-flip); crowdsource payload network (no community yet); AI template generator (PDCP owns it).

**Plan landed (2026-05-09 tick 8):** `docs/dast-openapi-plan.md` — 380-line, 6-PR design plan for synthesizing OpenAPI 3.1 from existing `project_entry_points` rows and feeding it to ZAP's native `openapi:` AF job. Architectural findings from the read pass: (a) existing v2.1a/b DAST scaffolding is highly reusable — OpenAPI is purely additive, one new AF job between `replacer` and `spider` plus a synthesizer module; (b) `'api'` scan profile is already in the type union, silently aliased to `'auto'` (`pipeline.ts:760`) — plan promotes it to first-class; (c) `project_entry_points` already provides everything needed (`route_pattern`, `http_method`, `handler_name`, `classification`, `auth_mechanism`, `metadata`) plus 30 framework-rules detectors; (d) zero new tables — one additive column migration on `project_dast_targets`; (e) `zap-api-scan.py` and AF `openapi:` job already in depscanner Docker image (`Dockerfile:140-170`); (f) deterministic cross-link via sidecar `endpoint_to_handler.json` eliminates today's URL-encoding/trailing-slash false-negative class. 6 open questions for Henry (OpenAPI 3.1 vs 3.0; empty-entry-points fallback; spec-source precedence; operationId collision strategy; websocket handling; whether to publish synthesized spec back to customer).

### Malicious packages — vs Socket, Phylum/Veracode, Aikido, Endor, JFrog Curation, Snyk, GuardDog upstream, OSSF, deps.dev, SafeDep, Mend, Bytesafe

**Where we are.** Honest one-liner: **we are an SCA tool that runs GuardDog post-clone, not a real-time malware detector.** GuardDog 2.9.0 wrapped in isolated venv; malicious-v2 implemented (5 milestones + 2 e2e bug fixes); branch tip `1861b2c` on `worktree-malicious-packages-v2` (not yet merged). Phase 6 cross-file taint engine + Phase 5 Autogrep give us strong post-install reachability — adjacent to malicious-pkg detection, not central. We scan on **new dependency ingestion** (post-clone, post-commit). We do NOT watch the npm/PyPI publish firehose. By the time a customer's lockfile bumps, the package is already on disk in CI. No sandbox; no install-script behavior monitoring; no registry-side block; no public threat feed.

**Themes — what's missing (ranked by leverage):**
1. **Real-time publish-feed ingestion** — HIGHEST. Socket flags Axios in 6 minutes; Aikido medians 5min; we wait for SBOM ingestion. npm has public registry-changes feed (`https://replicate.npmjs.com/_changes`); PyPI has BigQuery + RSS. Without this, every other malicious-pkg feature is reactive.
2. **Cooldown policy** — HIGH leverage, LOW cost. Endor + Bytesafe + JFrog all ship. ~1-week build for us. Block deps published <N hours ago at the policy-engine layer (we already evaluate policy code at populate-dependencies). 48h default, configurable per-org.
3. **Sandbox dynamic analysis at install time** — Phylum + Snyk + SafeDep run installs in eBPF-traced sandboxes. We can do this in our depscanner Fly machines (Firecracker + syscall tracing).
4. **GitHub App "block before merge"** — Already have the App; adding `check_run` that fails on malicious verdicts is incremental.
5. **Public threat-feed brand asset** — Aikido's AGPL feed; Socket's X feed. We could publish verdicts to a `deptex/malicious-packages` repo in OSV format → feeds OSSF aggregate, builds research credibility.
6. **Browser extension / IDE plugin** — Socket Chrome ext annotates npmjs.com.
7. **Registry-side firewall proxy** — Socket Firewall / Bytesafe / JFrog Curation. Heavy build; defer until #1-4 ship.
8. **AI-agent / MCP integration** — SafeDep MCP, Endor Cursor hooks, Aikido Endpoint. Aegis already speaks MCP-adjacent.
9. **Behavioral signal: install-script monitoring** — even without eBPF, parsing `package.json` `scripts.preinstall/postinstall/install` and `setup.py` for IOCs is cheap.
10. **Maintainer-reputation graph** — Phylum + Endor leverage maintainer history.

**Where we can lead — bets:**

*Wedge 1 (most differentiated): Reachability-aware malicious-package verdicts.* Today Socket flags `chalk` as compromised → every dep tree containing `chalk` lights up red. **We can do better:** combine the malicious verdict with our Phase 6 cross-file taint engine to say *"chalk is compromised AND the malicious code path is reachable from your `payments/checkout.ts` HTTP handler — deploy block"* vs *"chalk is compromised but only used by a dev-only test helper — cooldown OK."* Socket's reachability is shallow; Endor doesn't pivot reachability onto malicious-pkg verdicts. **Pitch writes itself: "Socket tells you 50 packages are compromised. We tell you which 3 actually expose your production app today."**

*Wedge 2: Aegis-driven autonomous remediation.* Socket + Endor surface findings. We have Aegis Fix Agent — when malicious package detected, Aegis can autonomously open a PR that swaps to last-known-good version, re-runs reachability, ships the fix. No competitor has this end-to-end.

*Wedge 3: Per-org Autogrep tuned to org dependency idiom.* Phase 5 Autogrep generates org-specific rules. Apply same machinery to malicious-pkg detection — an org importing crypto SDKs cares more about credential exfil patterns. Socket/Endor have one global ruleset.

*Wedge 4: Open-core threat feed with per-CVE explainability.* Aikido's feed is AGPL but verdict-only. We could publish verdicts WITH the actual reachability rule that flagged it — making each entry forensically reviewable. Positions us in OSSF / GuardDog upstream as research partner, not downstream consumer.

*Wedge 5: Cooldown × reachability × maintainer-signature composite policy.* Endor's cooldown is purely time-based. Combining cooldown × reachability × maintainer signature is a 3-factor policy nobody else ships — exactly what our policy-code engine was designed for.

**What NOT to chase:** real-time-latency-arms-race vs Socket (we'll be 2nd or 3rd at best); registry MITM firewall before #1-4 ship; dynamic-analysis sandbox before publish-feed ingestion (we'd be running sandbox on packages everyone else already classified).

**Public benchmark numbers to know:** Socket 6-min Axios detection, 99% precision / 97% F1 on 5,115-package SocketAI corpus, ~500 packages in Sep 2025 npm phishing campaign, 175 in Oct 2025 "Beamglea" credential harvest. Aikido 5-min median, 100k packages/day, 778,500+ malicious tracked since 2019. Snyk 1,000+ flagged in 2025 mid-year, 3,600+ in 2024. Sonatype 2026 State of Supply Chain: 454,600 new malicious packages in 2025; 1.233M cumulative. OpenSSF feed median lag ~10 days (per Aikido's published comparison).

---

## Future-work backlog

(items found during the marathon that didn't fit the timebox; ranked by leverage)

- **DAST OAuth client-credentials auth strategy** (S, high-leverage) — fourth `kind` in `auth-config.ts`
- **DAST OpenAPI/GraphQL spec import** (M, highest-leverage DAST gap) — ZAP automation already supports the jobs natively
- **DAST GitHub Action + PR comment** (M) — closes biggest CI gap vs StackHawk
- **DAST endpoint discovery from `project_entry_points`** (S, novel) — synthetic OpenAPI from data we already have; HawkAI parity without LLM
- **DAST SARIF output** (S, free interop)
- **DAST Playwright-HAR recorded auth** (L, moat-class) — v2.1d as designed
- **IaC custom rules** (S, table stakes) — expose Checkov custom-rules via `iac_policy_code`
- **IaC OpenVEX consumption** (M, highest-leverage agentless win) — ingest VEX from Chainguard / Docker Hardened Images / Microsoft Azure Linux / Anchore
- **IaC base-image upgrade Aegis-driven PRs** (M) — Aegis differentiator no CNAPP plays
- **Phase 2 OS reachability (DT_NEEDED + dlopen + OpenVEX + shell-presence Tier B)** (L, moat) — already planned
- **CVE reachability — Java framework spec sprint** (L, recall floor) — Spring/Quarkus/Micronaut/Vert.x/Hibernate
- **CVE reachability — pypi framework spec depth** (M) — Django/Flask/FastAPI sink expansion
- **Public 88-CVE scoreboard** (S, marketing moat) — full plan at `docs/88-cve-scoreboard-plan.md`. 8-PR roadmap, ~3-5 eng days + ~$1 API + 1 Henry day to first publish. Existing harness (`depscanner/test/iterate/runner.ts:90-110`) already emits most scoreboard-shape fields; this is a thin wrapper. Recommended: markdown-in-repo (skip Pages), monthly cron, contributor-supplies-own-DeepInfra-key reproducibility, 5-path PR-comment-only filter. Headline: *"We're publishing the first reproducible reachability benchmark. We score 26.1%."* 7 open questions queued (Section 11). (Plan still uses the word "BYOK" for contributor-key reproduction — that's a *contributor* key for running the benchmark, not the retired customer-BYOK product feature.)
- **AI rule generation feedback retry loop** (L) — 15-20% one-shot ceiling → 40-60% with retry
- **Reachability tier transparency public docs** (S) — our 5-tier vocabulary > Endor binary

---

## Tokens + cost

### Subagent spend (Anthropic) — Day 1 wave 1
- Pipeline structural recon: ~88k tokens
- Error-logging surface audit: ~88k tokens
- Validation coverage audit: ~153k tokens
- Competitive — CVE reachability: ~56k tokens
- Competitive — IaC + container: ~67k tokens
- Competitive — DAST: ~80k tokens
- Competitive — malicious packages: still running

Wave-1 running cost (approximate Anthropic subagent total): ~530k tokens.

### DeepInfra Qwen spend
None yet (no live AI rule gen runs on the corpus).

### Per-section breakdown

(populated as track-completions land)

---

## Final PR

### Diff summary
### Risk assessment
### Rollout / verification plan
