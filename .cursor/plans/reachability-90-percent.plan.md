# Plan: Lift 88-CVE iterate recall 59% → ~72% (stretch ~75%)

**Branch:** new worktree off `worktree-depscanner-hardening` (current tip `413ef48`, PR-ready).
**Status:** twice-revised after `/review-plan` REWORK verdicts. All P0s resolved; 9 surgical patches applied in this revision.
**Companion doc:** `depscanner/docs/path-to-90-percent-recall.md` (per-CVE classification).
**Previous reviews:** `.cursor/plans/review-reachability-90-percent.md` (round 2; round 1 superseded).

---

## Goal

Push 88-CVE iterate-harness recall from **52/88 = 59.1%** toward a **realistic 70-72% landing zone** (stretch 75%) through five phases targeting three levers: engine feature gaps, bundled-spec gaps where the AI can't fix shape, and non-taint detection. Spring4Shell, Go struct-field-init, and version-only credit tier are explicitly **deferred**.

## Non-goals

- Optimising iterate at expense of real code (Phase 1.3 lands a 5-fixture real-CVE corpus as a parallel gate).
- Frontend, Aegis, Aider, DAST, IaC.
- New ecosystems.
- Reworking rule-generator schema or FP-filter triple regime.
- Property-path matching (Spring4Shell, 2f).
- Go struct-field-init (2e).
- New `reachability_level` enum values (3.4).
- DoS-family vuln_class enum additions.

## Success criteria

- 88-CVE iterate ≥ **70%** at 3-trial averaging (current 59.1% single-run; stretch 74%).
- 5-fixture real-CVE corpus ≥ **baseline + 10pp** (threshold derived in 1.3a, NOT a fixed number).
- Per-ecosystem baseline.json + automated diff-gate.
- Preflight grows 14 → 18 stages.
- Total spend ≤ **$10** (decomposed: $1 baseline + $2 per-step iterate + $1 prompt-eval + $1 final 3-trial + $5 contingency).

## Phases

### Phase 1 — Methodology + benchmarks (1-1.5 days)

**1.0 Variance probe.** Run **3 (not 2)** back-to-back single-trial 88-CVE iterates on tip `413ef48`. Compute per-CVE and global stddev. Decision rule:
- If global stddev ≤ 1.5pp AND max per-eco stddev ≤ 3pp → single-trial default is safe; `--trials=3` opt-in only.
- Else → `--trials=3` becomes default for intra-phase reruns. Re-baseline.
- Commit raw per-CVE pass/fail matrix to `bench-iterate/variance-probe/<date>.json`.

**1.1 3-trial averaging in `iterate.ts` as an opt-in flag (`--trials=3`).**

⚠ **NOT a simple flag flip.** runner.ts:174 has a retry loop with semantics "retry on parse_failed with revision feedback; first success short-circuits." This must be wrapped in an OUTER trial loop that:
- Runs `processCveCandidate()` N times with distinct seeds even when each validates.
- Records per-trial status to `report.json.perCve[i].trials: [...]`.
- Emits majority verdict (≥2/3 pass = CVE pass) + per-CVE stddev.
- Plumbs `seed` parameter through `callProviderAndParse` → `generate.ts` (today none of those expose a seed knob).

LOC estimate: **~150-200 in runner.ts + cli.ts + generate.ts**, not a flag. Unit tests in `iterate/__tests__/`: all-pass, all-fail, 2-of-3, 1-of-3, trial-count-mismatch, thrown-trial counted as fail, --trials=N where N<3 errors typed, ordering determinism (snapshot).

**1.2 Per-CVE diagnostic dump — BUILD, not reuse.**

`TaintTrace` is a data-only interface in `taint-engine/flow.ts:76`. No serialiser exists today. This sub-step ADDS:
- `serializeTrace(trace: TaintTrace): TraceJson` next to TaintTrace in `flow.ts`.
- `DropReason` union (start as free-text `string` with an enum-promotion jest test that walks taint-engine sources for `dropReason:` literals; promote to enum once the natural categories emerge from Phase 2 reruns).
- `serializeDiagnosticRecord(funcState, drops, sinks): DiagRecord` in `propagate-core.ts`.
- Per-language analogues call into the shared serialiser.

Flush format: NDJSON (one record per dropped step) at `bench-iterate/<variant>/<timestamp>/diag/<cve>.ndjson` when `DEBUG_TRACE=1`. **Convention match:** path mirrors existing `bench-iterate/<variant>/<timestamp>/report.json` namespace. Tiny `read-ndjson.ts` helper if Phase 4 consumes it.

LOC estimate: ~30-50.

**1.3a Real-CVE corpus — author + measure baseline.**

5 fixtures, one per ecosystem (npm, pypi, maven, golang, gem) at `test/customer-app-fixtures/<cve>/{vuln,safe}/`. **Naming:** `customer-app-fixtures` (NOT `real-cve-fixtures`) to distinguish from existing `cve-targeted-flow-fixtures/`. Each fixture is:
- N≥3 self-contained vendored source files (entry + ≥1 intermediate + sink-importing module).
- The cross-file taint edge MUST be exercised (otherwise it's a unit fixture in disguise).
- No network at test time. No Docker. No npm install — vendored only.
- Wall-clock budget for `npm run test:customer-app` ≤ 30s on CI.

Run engine on tip `413ef48` against the 5 fixtures. Commit baseline at `test/customer-app-fixtures/baseline-413ef48.json` with `{cve, status: confirmed|data_flow|module|unreachable, n_files}`.

**1.3b Threshold derived from measurement.**

Threshold = `baseline_pct + 10pp`, with floor at 60% and ceiling at 100%. NOT a fixed 70%. If baseline is 40%, target 50%; if 80%, target 90%. Commit threshold in `test/customer-app-fixtures/threshold.json`. Gates Phase 5 alongside iterate.

**Test cadence:** `npm run test:customer-app` runs per-commit only if wall-clock ≤30s; if exceeded, demote to per-wave with a smaller hermetic smoke subset on per-commit.

### Phase 2 — Engine features (2-3 days, ~5-6 CVEs realistic)

Wave A:

| Step | Files | LOC (floor) | CVEs | Per-language fixture matrix |
|---|---|---|---|---|
| 2a — JS single-assignment const resolver as a propagate-core primitive | `propagate-core.ts`, `non-taint-detector.ts` | ~50-100 (hard replan trigger at **150**, no contingency multiplier — drop the prior 2-3x framing) | jsonwebtoken 22-23539, follow-redirects 24-28849 | ≥3 pos + ≥2 neg in `test/taint-engine/javascript/const-resolver/`. Each fixture's README enumerates the syntactic variant it exercises (declaration, assignment, destructured rest). 2c/2d MUST consume the same resolver — locked in propagate-core as a **second** Map `localOrigin = new Map<string, string>()` (NOT widening the TaintTrace map value, which would touch all 8 per-language propagators). |
| 2b — Python kwarg-aware sink matching audit | `python/{propagate,ir}.ts` | ~30-60 (replan at 90) | urllib3 20-26137 | ≥3 pos + ≥2 neg in `test/taint-engine/python/kwarg-sinks/` |

Wave B:

| Step | Files | LOC (floor) | CVEs | Test matrix |
|---|---|---|---|---|
| 2c — Computed-key full taint write | `ir.ts` | ~40-80 (replan at 120) | lodash 26-4800 | ≥3 pos + ≥2 neg in `test/taint-engine/javascript/computed-key/` |
| 2d — Method-chain on awaited results | `ir.ts` | ~60-120 (replan at 180; **named as the contingency cut lever if Wave A overshoots**) | axios 26-40175, 26-34043 | ≥3 pos + ≥2 neg in `test/taint-engine/javascript/method-chain-await/`. Note correlated risk: both target CVEs are axios — TAM=1 with diversity loss, score at +0.65 not +1.3. |

Per step:
1. Capture failing AI fixture from prior iterate run into `test/cve-targeted-fixtures/<cve>/{vuln,safe}/`.
2. Author per-language fixture matrix (each directory has a README listing variants covered).
3. Implement engine change.
4. Add **one preflight stage per primitive** to `scripts/taint-engine-preflight.ts` (14 → 18 stages total — named in advance: `js-const-resolver`, `py-kwarg-sinks`, `computed-key-write`, `method-chain-await`).
5. Per-commit gate: preflight + all 8 per-language jest + cve-targeted-fixtures + customer-app (if budget allows). Wall-clock target: ≤90s local, ≤3min CI.
6. Iterate rerun **per wave** (Wave A end, Wave B end), single-trial, attribution via Phase 1.2 diag dumps.

### Phase 3 — Non-taint regime + targeted vuln_class enum (1.5-2.5 days, ~2-3 CVEs realistic)

**3.0 (NEW — PREREQUISITE) FrameworkSpec schema mirror extension.**

Before any detector files land. The schema has FOUR concurrent declarations that must all accept the new primitives (`unsafe_regex_patterns: string[]` and `insecure_defaults: { pattern, forbidden_value_shapes }`):
- `spec.ts:131-140` — add optional fields to `FrameworkSpec` interface.
- `spec-loader.ts:61+` — extend `loadSpec` / `loadSpecFromJson` to load (today unknown keys silently ignored).
- `framework-spec-schema.ts:115-122` — extend zod schema; selectively relax `.strict()` for the new fields OR add them explicitly.
- `prompt-builder.ts` — surface the new primitives in the AI prompt's allowed-fields list.

All 23 bundled YAMLs default the new fields to empty array (no per-file authoring required). Phase 3.0 must land as ONE commit before 3.1/3.2/3.3. Without 3.0, Gate 2 round-trip in validate.ts will REJECT every spec the AI emits with the new primitives.

LOC estimate: ~30-50 across the 4 mirror sites.

**3.1 Targeted enum addition.** Only `weak_default` enters `ALL_VULN_CLASSES` (matches the new insecure_default detector). `redos` already exists. DoS-family stays `vuln_class_out_of_scope` per spec.ts:40-43. Migration `phase28d_extend_vuln_class_enum` via MCP for `weak_default` ONLY — AND extends `taint_engine_settings.vuln_classes_enabled` DEFAULT to include it (otherwise freshly-provisioned settings exclude). Update spec.ts:40-43 doc-comment same commit. Tests: PGLite round-trip, AI-validator unit test, frontend filter dropdown vitest.

**3.2 NEW FILE `taint-engine/regex-literal-detector.ts`.**

Hand-authored fixture suite at `test/detectors/regex-literal/`: ≥10 pos + ≥10 neg fixtures (shape correctness gate).

**Precision gate** against a pinned negative corpus, distinct from the shape fixtures:
- Snapshot: `malicious-v2` known-clean repo set, pinned at commit `<SHA-TO-FILL>`.
- Size: N≥500 files.
- Manifest: `test/detectors/regex-literal/fp-corpus.manifest.json` with `{commit, files: [...]}`.
- Precision threshold: ≥90% (TP / (TP+FP)) before detector votes in iterate.
- Run via `npm run test:detector-precision regex-literal`.

Targets: debug 17-16137, jinja2 urlize 20-28493.

**Gate-0 (per skeptic):** dry-run the AI on ≥1 target CVE with the new prompt sidebar (Phase 4.2) BEFORE merging the detector. If the AI doesn't emit `unsafe_regex_patterns` in the spec, the detector's iterate contribution is 0 — surface that early.

**3.3 NEW FILE `taint-engine/insecure-default-detector.ts`.** Same test scope as 3.2 (≥10 pos + ≥10 neg + pinned FP corpus of N≥500 + ≥90% precision gate + Gate-0 dry-run). Targets: requests 24-35195, flask 23-30861.

**3.4 ~~Version-only credit tier~~ CUT.** Filed for `scoring-tiers.plan.md` if pursued.

### Phase 4 — Spec library + AI prompt tuning (1-1.5 days, ~2-3 CVEs realistic)

**4.1 — Bundled YAMLs + reclassification, folded together.** ~~Phase 4.0 spike folded in.~~

Procedure for each of the 6 candidate CVEs (actionpack 22-23633, ruby-git 24-32465, pillow 24-26130, cryptography 23-49083, x-net-html 23-3978, spring-security 22-22978):
1. Read Phase 1.2 NDJSON diag dump for that CVE.
2. Classify in-place: **bucket G** (no spec — write a YAML) OR **bucket I** (spec exists, AI emits non-matching sink — add to few-shots in 4.2).
3. Record classification in `bench-iterate/cve-bucket-classification.json` keyed by osv_id: `{osv_id, bucket, primitive, justification}`. Single artifact, schema'd via Zod.

4.1 ships a single commit containing all bucket-G YAMLs (expected 2-4 after classification — committed count tracks the actual finding, not "~3 hardcoded") with their Gate-2 fixture pairs under `test/taint-engine/fixtures/<spec>/{vuln,safe}/`.

**4.2 Rule-generator prompt sidebar.** Add a "shapes the engine matches" section to the existing system prompt assembled by `prompt-builder.ts`. 4-5 canonical examples per language (positional vs kwarg, struct-init vs call, method-chain). New few-shots land in **existing `rule-generator/few-shot-examples.ts`** (NOT a new directory). Reclassified bucket-I CVEs from 4.1 get fixture pairs added here. Tag new few-shots with the engine-shape they exemplify so `selectFrameworkSpecFewShots` can pick them; selector stays ecosystem-keyed but shape-tagged few-shots ride along.

**4.3 ~~Standalone 12-CVE prompt-eval~~ — REPLACED.** Use per-ecosystem sub-aggregate of the existing 88-CVE single-trial iterate as the prompt-change regression gate. After each prompt edit in 4.2:
- Rerun 88-CVE single-trial (~$0.33).
- Compute per-eco recall.
- Gate: any ecosystem drops more than `max(5pp, 2*observed_stddev_from_1.0)` → revert prompt.

This eliminates the standalone harness and 12-CVE corpus maintenance while gating on the actual signal. Noise floor is already measured in Phase 1.0.

### Phase 5 — Push to ceiling + lock (1 day)

**5.1** Final 3-trial 88-CVE iterate.
**5.2** Final `npm run test:customer-app` against 1.3a fixtures.
**5.3** Commit baseline at `bench-iterate/baselines/<date>.json` with schema: `{date, commit, n_trials, global_pct, global_stddev, per_eco: { <eco>: { pct, stddev } }, drop_reasons: { <reason>: count }}`. Author `bench-iterate/scripts/diff-baseline.ts` that takes `(baseline, current)` and exits non-zero on threshold breach with a per-CVE table. Jest test for `diff-baseline.ts` covers threshold math (pp boundaries, eco-missing, NaN). CI workflow `.github/workflows/reachability-baseline.yml` — manual-trigger + weekly cron — calls `diff-baseline.ts` as its final step. Threshold: global > `max(2pp, 2*baseline.global_stddev)` OR any eco > `max(3pp, 2*per_eco_stddev)`.
**5.4** Update `docs/path-to-90-percent-recall.md` final-state table.
**5.5** Open PR.

## Cumulative projection (bottom-up, per-CVE, with credit factor)

Built from the 36 currently-failing CVEs. Each CVE attached to one primary lever. Credit factor split by lever class (engine: 0.65; spec library: 0.7; prompt: 0.4 — per skeptic's coupling argument).

| Lever | TAM | Credit | Wins |
|---|---|---|---|
| 2a JS const resolver (engine) | 2 | 0.65 | +1.3 |
| 2b Python kwarg audit (engine) | 1 | 0.65 | +0.65 |
| 2c Computed-key (engine) | 1 | 0.65 | +0.65 |
| 2d Method-chain await (engine) | 1 (TAM=2 but correlated axios risk) | 0.65 | +0.65 |
| 3.2 ReDoS detector (regime + prompt coupling) | 2 | 0.4 | +0.8 |
| 3.3 Insecure-default detector (regime + prompt coupling) | 2 | 0.4 | +0.8 |
| 4.1 bucket-G YAMLs (spec) | 2-4 | 0.7 | +1.4 to +2.8 |
| 4.2 bucket-I prompt fix (prompt) | 2-4 | 0.4 | +0.8 to +1.6 |
| **Sum** | **13-17** | — | **+7.05 to +9.25** |

**Realistic: 52 + 7 = 59/88 → ~67%. Stretch (all levers at upper bound + variance): 52 + 9 = 61/88 → ~69%.**

Wait — this projection now FAILS even the lowered 70% success criterion. Options:

1. **Accept ~67-69% as the honest target** (lower success criterion to ≥66% with stretch ≥70%).
2. **Add back one of the deferred items** (2e Go or 2f Spring4Shell or some bundled YAML wave B) to give margin.
3. **Bet that some credit factors are too pessimistic** — the 0.4 for detectors+prompt may be too low if Gate-0 dry-runs (3.2/3.3) pass.

**Recommended:** Lower success criterion to **≥66% realistic / ≥70% stretch**, run Phase 1.0 + 2a, then re-project mid-flight with actual per-step delta. If after Wave A we're tracking above projection, hold the line. If below, this plan is the **honest floor** and the next plan brings back deferred items.

Hard ceiling on this corpus without 2e/2f/3.4 work: **~85%** (per `docs/path-to-90-percent-recall.md`). Hard floor (uncoverable): ~92%, i.e. 6-8 CVEs floor.

## Open questions — RESOLVED

1. ~~Bucket K version-only~~ CUT 3.4.
2. ~~2f Spring4Shell~~ Deferred to `phase28-spring4shell-propertypath.plan.md`.
3. ~~Second benchmark~~ Yes, 1.3 customer-app-fixtures.
4. ~~$5 cap~~ **$10 honest decomposed budget**, not $20 as in prior draft.

## Risks

- **R1** Iterate ≠ real-world — mitigated by 1.3 customer-app + 5.3 CI baseline.
- **R2** Prompt-tuning fragile — mitigated by 4.2 per-eco sub-aggregate gate (replaces 4.3 standalone).
- **R3/R4** DROPPED (2f, 3.4 cut).
- **R5** Fixture-matrix authoring serial cost ~2 days for a solo iterator. No parallelization claim retracted; budget the time honestly.
- **R6** Customer-app fixtures may surface engine bugs not on iterate — accepted, budget ≤2 days incidental fixes.
- **R7** (NEW) Detector wins (3.2/3.3) require AI to emit matching primitives — Gate-0 dry-run per detector catches this early, but the +0.4 credit factor may still be optimistic if AI shape compliance is below ~50%. Decision: measure after 3.2 lands; if shape-compliance <50%, drop 3.3 from this plan.

## Test cadence (explicit)

After **every commit** in Phase 2/3/4:
- Full preflight (14 → 18 stages as primitives ship).
- All 8 per-language jest in `test/taint-engine/`.
- `npm run test:cve-targeted`.
- `npm run test:customer-app` (if wall-clock ≤30s — else demote to per-wave).
- Wall-clock budget: ≤90s local, ≤3min CI. If exceeded, split into pre-commit fast gate + pre-push full gate.

After **every wave** in Phase 2 / per-phase in 3/4:
- 88-CVE iterate at **single trial**.

Only at Phase 1.0 baseline / Phase 5.1 final lock:
- 88-CVE iterate at **3 trials**.

## Out of scope (explicit)

- Schema changes to `framework_models` or `rule_generation_cache`.
- FP-filter triple regime.
- New ecosystems.
- Aegis or Aider integration of new vuln classes.
- Phase 2e, 2f, 3.4.
- DoS-family vuln_class enum additions.
- New `prompt/few-shots/*.json` directory (use `few-shot-examples.ts`).
- Standalone 12-CVE prompt-eval harness (use per-eco sub-aggregate of 88-CVE).

## Cleanup

- Delete stale `.cursor/plans/triage-2026-05-12.json` and `triage-2026-05-12-post-abcd.json` once Phase 5 baseline lands.
- This plan supersedes both prior `reachability-90-percent.plan.md` drafts.
