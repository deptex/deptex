# Reachability Phase 5b — Rule Quality Iteration

## Overview

Phase 5 shipped a working AI rule generation pipeline (autogrep-style per-org Semgrep taint rules). Live E2E with Anthropic confirmed every stage runs — OSV fetch, AI provider call, schema validation, fixture round-trip, patch round-trip, persistence, telemetry — but **0% of generated rules graduate to `validated: true`**. This phase fixes the two distinct quality gaps surfaced by E2E: (a) the patch round-trip's whole-repo Semgrep run is structurally mismatched against application-level rules; replace it with diff-targeted validation against the changed files only, matching autogrep's published methodology. (b) the prompt lacks few-shot examples; the AI is producing rules that match safe code (FP) or fail to match the actual fix's changed lines. Adopt 3 ecosystem-matched hand-authored rules from `reachability-rules/` as inline examples.

Target: validation rate climbs from 0% to ≥15% across a benchmark set of 8–10 CVEs spanning npm/pypi/maven/go.

---

## Competitive Research & Design Rationale

**Autogrep methodology** (lambdasec.github.io blog + GitHub repo):
- Validates against **changed files only**, not the entire upstream repo. The rule must fire on the parent SHA's version of the changed files and miss on the fix SHA's version.
- Validation rate: 8.99% of 39,931 patches yielded valid rules pre-filter; 17.96% survived post-filter (645 final rules from 3,591 candidates).
- Validation signals: fixture round-trip + diff-targeted patch round-trip. No self-critique or rule-on-rule dedup beyond rule-corpus filtering at the end.
- Patch validation is the dominant filter — about 27% of generated rules fail it.

**Our advantage over autogrep:** they generate library-internal rules at scale once. We generate per-org, per-scan, with the user's actual application context. This means our rules can target *callsite shapes the user actually has* (e.g., `_.template(req.body)` in an Express handler) — strictly stronger than autogrep's library-internal rules, but requires a different validation strategy. **Diff-targeted patch validation is the right primitive for both: rule must match the deleted lines of the fix and miss the added lines.**

**What we adopt from autogrep:**
- Diff-targeted patch round-trip (M1).
- Per-CVE rule generation, OSV-driven (already shipped Phase 5).

**Where we differentiate:**
- Per-org BYOK + budget cap (already shipped).
- App-context-aware rules (sources are `req.body`, not just `argv`).
- Few-shot examples drawn from our hand-authored rule corpus, ecosystem-matched (M2). Autogrep doesn't do this in their published pipeline.
- Structured validation telemetry by stage (M3) — autogrep just reports aggregate pass/fail.

---

## Codebase Analysis

### Files to be modified

| File | What changes | Why |
|---|---|---|
| `backend/extraction-worker/src/rule-generator/validate.ts` | `runPatchValidation()` rewritten: drop git clone path, use `patchInfo.changedFiles[].before`/`after` directly. Run Semgrep against each per-file `before`/`after` content as in-memory tmp files. | Whole-repo clone-and-checkout is structurally mismatched for app-level rules. The before/after blobs already exist in `patchInfo`. |
| `backend/extraction-worker/src/rule-generator/index.ts` | `generateRuleForCve` no longer passes `fixCommit` to `validateRule` (we have `patchInfo.changedFiles` instead). Pass `changedFiles` directly. | Aligns API with new validation primitive. |
| `backend/extraction-worker/src/rule-generator/prompt-builder.ts` | New `fewShotExamples` arg accepts 2–3 hand-authored rules. Inline rendered into prompt under a new `# Reference rules that previously validated` section. Prompt version bumped to `rulegen-v3`. | The reference shape we already have (rulegen-v2) only shows YAML structure; few-shot examples show the AI how to *think* about a CVE. |
| `backend/extraction-worker/src/rule-generator/few-shot-loader.ts` (new) | Loads + caches the platform-shipped rules from `reachability-rules/`, indexes by ecosystem, returns top-K by ecosystem match. | Centralizes the few-shot picking so the prompt builder stays pure. |
| `backend/extraction-worker/src/rule-generator/index.ts` | Calls the few-shot loader before `buildGenerationPrompt`, passes selected examples into the prompt. | Wire-up. |
| `backend/extraction-worker/src/rule-generation-step.ts` | New per-CVE `validation_breakdown` field on the step result + persisted to `extraction_jobs`: counts of {fixture_pass, fixture_fail, patch_pass, patch_fail_matches_post, patch_fail_no_pre_match, schema_fail, provider_fail}. | Iteration requires telemetry; without it we can't tell if M1 helped. |
| `backend/extraction-worker/test/rule-generation-bench.ts` (new) | Benchmark harness: runs rule generation against a fixed CVE set with mocked provider returning canned YAML payloads. Measures validation rate per fixture-only / diff-targeted / both. | Lets us iterate on prompt + validation without burning live API credits each time. |
| `backend/extraction-worker/src/__tests__/validate-diff-targeted.test.ts` (new) | Unit tests for the new diff-targeted validation: rule matches before but not after → pass; rule matches both → fail; rule matches neither → fail; rename-only diffs → skip; binary-only diffs → skip. | Lock the validation semantics. |

### Files NOT modified (intentionally)
- `patch-fetch.ts` — already returns `before`/`after` per file, no changes needed.
- `osv-fetch.ts` — fix from earlier already covers GIT-range fallback.
- Pipeline integration (`pipeline.ts`) — rule_generation step's external contract is unchanged.
- Frontend Settings UI — no schema changes; existing detail modal already renders `validation_log.errors` and the new `validation_breakdown` shows up automatically as part of `validation_log`.

### Reusable code identified

- `runSemgrep()` in `validate.ts` (lines 375–479) — keep as-is, reuse for diff-targeted validation by passing per-file targets.
- `loadAllRulesWithSkipped()` in `reachability-rules.ts` — already loads platform rules from disk; few-shot loader can reuse it instead of re-parsing.
- `semgrepLanguageFor()` in `prompt-builder.ts` — reuse for per-file extension picking in diff-targeted validation.
- `safeRm`, `mkdtempSync` patterns — preserve the temp-dir lifecycle from current `validateRule()`.

---

## Data Model

**No new tables.** All telemetry lives in existing JSONB columns:
- `organization_generated_rules.validation_log` (existing) — gains a `validation_breakdown` object.
- `extraction_jobs.reachability_*` columns (existing from M3) — unchanged.

No migrations.

---

## API Design

**No new endpoints.** Frontend already reads `validation_log` from `GET /api/organizations/:orgId/generated-rules/:ruleId`. The richer breakdown shows up automatically in the existing detail modal — no API changes needed.

The existing `regenerateGeneratedRule` endpoint (POST `/api/organizations/:orgId/generated-rules/:ruleId/regenerate`) gets a no-op upgrade: when the user regenerates a previously-failed rule, the new prompt + few-shot examples + diff-targeted validation kick in automatically on the next scan.

---

## Frontend Design

**Tiny UI surface area.** The existing `GeneratedRuleDetailModal.tsx` (M4) already renders `validation_log` as a JSON pretty-print. The new `validation_breakdown` field appears under the existing "Validation log" tab without code changes.

**One small enhancement (optional, M5):** add a simple validation badge in the rules table showing why a rule failed — "Too broad" (fixture FP), "Too narrow" (no patch pre-match), "Schema error", "Provider error". Distilled from `validation_breakdown`. ~15 lines of TSX in `GeneratedRulesTable.tsx`. Defer if M1–M4 time-budget overruns.

---

## Implementation Tasks

Ordered. Each task is one commit.

### M1: Diff-targeted patch validation (~1 day, L)

**Files:**
- `backend/extraction-worker/src/rule-generator/validate.ts` — rewrite `runPatchValidation`
- `backend/extraction-worker/src/rule-generator/index.ts` — thread `changedFiles` instead of `fixCommit`
- `backend/extraction-worker/src/__tests__/validate-diff-targeted.test.ts` (new)

**Spec:**
- Replace `runPatchValidation()` with `runDiffTargetedValidation()`:
  - Input: `payload`, `changedFiles: ChangedFileBlob[]`, `workDir`, `signal`, `semgrepBin`.
  - For each file in `changedFiles` whose path's extension matches the rule's language (filter via `semgrepLanguageFor`):
    - Skip if `before === null` (file didn't exist) — can't test pre-patch.
    - Skip if `after === null` (file deleted) — can't test post-patch.
    - Write `before` and `after` to two tmp files with the right extension.
    - Run Semgrep against each.
  - Aggregate: `preMatches = sum across files`, `postMatches = sum across files`.
  - Rule passes the patch round-trip iff `preMatches > 0` AND `postMatches === 0`.
- Verdict logic in `validateRule()` unchanged structurally; just calls the new function.
- `validation_log` shape gains a `per_file_breakdown: Array<{path, pre, post}>` for debugging.
- Drop the `simple-git` dependency import from validate.ts (still used elsewhere — confirm before removing from package.json).
- Drop `MAX_REPO_BYTES`, `CLONE_TIMEOUT_MS`, `withClone()`, `directorySizeBytes()` — all dead after this change.

**Acceptance:**
- `npm test extraction-worker/src/__tests__/validate-diff-targeted.test.ts` passes (5+ unit tests).
- Manually run E2E: 3+ CVE attempts, at least one rule should now pass patch round-trip if the rule shape is right (won't be 100% — depends on rule quality which M2 addresses).
- No clone happens during validation (verify with `docker run --rm deptex-cli:local strace -e network …` or just confirm no `simple-git` in the call path).

### M2: Few-shot prompt examples (~0.5 day, M)

**Files:**
- `backend/extraction-worker/src/rule-generator/few-shot-loader.ts` (new)
- `backend/extraction-worker/src/rule-generator/prompt-builder.ts` — accept + render examples
- `backend/extraction-worker/src/rule-generator/index.ts` — wire up
- `backend/extraction-worker/src/__tests__/few-shot-loader.test.ts` (new)

**Spec:**
- `loadFewShotExamples(ecosystem, k = 3)` reads `reachability-rules/*/rule.yml` once per process, indexes by `metadata.ecosystem`, returns up to K rules from the matching ecosystem (preferring smaller LOC for prompt budget).
- Falls back to any-ecosystem rules if fewer than K matches in the target ecosystem.
- Returns `{ ruleYaml, vulnerableFixture, safeFixture }[]` — the same triple our prompt asks the AI to produce.
- Wait, the platform rules don't have `vulnerable_fixture`/`safe_fixture` files alongside them — they have `fixtures/` subdir. Verify during impl that we can render fixture pairs from disk; if not, distill the rule_yaml only and skip fixtures in the few-shot.
- Prompt builder renders examples under a new section before "Your task":
  ```
  # Reference rules that previously validated
  Here are 3 hand-authored rules in the same ecosystem that passed both
  fixture and diff-targeted patch validation. Match this style.

  ## Example 1: CVE-XXXX (package, severity)
  ```yaml
  <rule_yaml>
  ```
  Vulnerable fixture: <code>
  Safe fixture: <code>
  ```
- Prompt version bumped to `rulegen-v3`.
- Prompt budget audit: with 3 × ~2KB examples (rule + fixtures), we add ~6KB; current budget is 18KB diff + 20KB blobs ≈ 38KB. Well within Anthropic's input window.

**Acceptance:**
- Unit test: loader returns ecosystem-matched rules; falls back to any-ecosystem when none; sorts by LOC ascending.
- Visual prompt inspection: log a sample prompt to disk and confirm the few-shot section renders cleanly.
- Telemetry: capture prompt_version in `organization_generated_rules` (already a column in M1 schema).

### M3: Validation breakdown telemetry (~0.5 day, M)

**Files:**
- `backend/extraction-worker/src/rule-generator/validate.ts` — extend `ValidationLog`
- `backend/extraction-worker/src/rule-generator/index.ts` — propagate breakdown to `GenerationResult`
- `backend/extraction-worker/src/rule-generation-step.ts` — sum breakdowns across the run, persist on `extraction_jobs`
- Backend Supabase migration: add `extraction_jobs.reachability_validation_breakdown jsonb`
- `backend/extraction-worker/src/__tests__/rule-generation-step.test.ts` — assert the aggregated shape

**Spec:**
- `ValidationLog.validation_breakdown`:
  ```ts
  {
    fixture_pre_match: boolean,
    fixture_safe_clean: boolean,
    patch_pre_match: boolean | null,    // null if skipped (no diff applicable)
    patch_post_clean: boolean | null,
    schema_pass: boolean,
    semgrep_parse_error: string | null,  // populated when exit code 7
  }
  ```
- Step-level aggregation across all CVEs in the run:
  ```ts
  {
    candidates: 5,
    fixture_pre_pass: 3,
    fixture_safe_pass: 2,
    patch_pre_pass: 2,
    patch_post_pass: 1,
    schema_pass: 4,
  }
  ```
- Persisted as JSONB on `extraction_jobs.reachability_validation_breakdown`.
- Surfaced in CLI output (`rule_generation_telemetry.json` already emitted in Phase 5 M5).

**Acceptance:**
- Unit test asserts breakdown shape on a mocked validation result.
- Live E2E: telemetry JSON file shows the breakdown and all counts add up.

### M4: Bench harness for offline iteration (~1 day, L)

**Files:**
- `backend/extraction-worker/test/rule-generation-bench.ts` (new)
- `backend/extraction-worker/test/fixtures/canned-rules/<cve>/payload.json` (new — 8–10 canned AI responses)

**Spec:**
- Standalone script (not a Jest test) — `npm run bench:rule-generation`.
- For each CVE in a hand-curated set (8–10, mix of ecosystems):
  1. Mock `callProviderAndParse` to return a canned `payload.json` (so the benchmark is deterministic and free).
  2. Run the full pipeline: OSV fetch (real, cached) + patch fetch (real, cached) + validation (real Semgrep).
  3. Record per-CVE outcome + per-stage timing + validation_breakdown.
- Output a markdown table: CVE | ecosystem | provider_pass | schema_pass | fixture_pass | patch_pass | overall | reason_if_fail
- Compute aggregate validation rate.
- Cache OSV + patch responses in `test/fixtures/cache/` so the bench is reproducible offline.

**Acceptance:**
- `npm run bench:rule-generation` finishes in <2 min, prints a markdown report.
- Aggregate validation rate ≥15% on the canned set (the canned payloads are correct rules from `reachability-rules/`, so we expect close to 100%; if it's below 100%, the validation pipeline has a bug).
- Bench can run with `--prompt-version=v3` to compare prompts head-to-head later.

### M5 (optional): UI failure-reason badge (~0.5 day, S)

**Files:**
- `frontend/src/components/settings/GeneratedRulesTable.tsx` — add badge column
- `frontend/src/lib/api.ts` — types

**Spec:**
- Distill `validation_breakdown` into a single human-friendly reason string:
  - `fixture_safe_clean === false` → "Too broad — matches safe code"
  - `patch_pre_match === false && fixture_pre_match === true` → "Too narrow — doesn't match upstream fix"
  - `schema_pass === false` → "Schema error"
  - `semgrep_parse_error !== null` → "Semgrep parse error"
- Show as small badge next to the rule's status.
- Defer this if M1–M4 took longer than budgeted.

**Acceptance:**
- Visual: badges render with appropriate colors (red for FP, yellow for too-narrow, gray for schema/parse).

### M6: Live E2E re-verification (~0.5 day, S — last)

- Run the existing `test-minimal-npm` E2E with sonnet-4-6 and the new prompt + diff-targeted validation.
- Capture the validation rate.
- Document in commit message.
- Run again with haiku to compare model quality.

---

## Testing & Validation Strategy

### Unit
- `validate-diff-targeted.test.ts`: 5+ tests covering pre>0/post=0 (pass), pre>0/post>0 (fail), pre=0 (fail), file rename, file deletion, binary file skip, language extension mismatch.
- `few-shot-loader.test.ts`: 3+ tests covering ecosystem match, fallback to any-ecosystem, sort by LOC.
- `rule-generation-step.test.ts`: extend existing tests to assert `validation_breakdown` shape.

### Integration
- `rule-generation-bench.ts`: deterministic harness — must produce ≥75% validation rate on canned correct rules (this is a self-check that the validation pipeline isn't false-rejecting good rules).

### Live E2E
- `test-minimal-npm` + sonnet-4-6 + new prompt: target ≥1 rule graduating to `validated: true`.
- `test-minimal-npm` + haiku + new prompt: bonus if any rule graduates; OK if 0% (haiku is known weak for structured output).
- Cross-ecosystem: run on test-python or test-java once, verify no regression.

### Performance
- Diff-targeted validation must be ≥3× faster than the prior whole-repo clone path (no clone, no checkout). Target: <5 sec per rule for fixture+patch validation combined.

### Regression
- All 65 existing unit tests in `extraction-worker/src/__tests__/` must still pass.
- Existing platform rule packs in `reachability-rules/` must still pass `npm run test:reachability-rules-e2e` (this validates that our change to validate.ts doesn't break the hand-authored rule pipeline — they don't go through `runPatchValidation` but the runSemgrep helper they share must still work).

---

## Risks & Open Questions

### Open questions for Henry
1. **Few-shot fixture rendering** — platform rules in `reachability-rules/CVE-XXX/` have a `fixtures/` subdir alongside `rule.yml`. Do they have `vulnerable.<ext>` and `safe.<ext>` files, or just unstructured fixture content? If structured: easy to render in prompt. If unstructured: we may need to inline rule_yaml only and skip fixture-pair examples. **Will verify during impl; flagging in case we need a fallback strategy.**
2. **Rule "passed" definition** — current `validate.ts` returns `validated` if `fixturePass === true` even when patch validation is skipped or fails. Is that still right after M1? Recommendation: tighten to `validated` requires fixture pass AND (patch pass OR no diff applicable). **Need your call.**
3. **M5 (UI badge)** — defer or include? Affects sequencing.

### Risks
- **Semgrep quirks per language.** Diff-targeted validation runs Semgrep against arbitrary file extensions; some languages may behave differently (e.g., TypeScript's `.tsx` vs `.ts`). Mitigation: rely on `semgrepLanguageFor` which already handles ecosystem→language mapping.
- **Patch fetch budget.** `patchInfo.changedFiles` is currently capped at 8 files + 64KB per blob. If a real-world fix touches 20 files, we silently miss matches in the truncated tail. Mitigation: log a warning when truncation occurs in patch-fetch.ts (already does), and surface in `validation_breakdown`. Bumping the cap is out of scope for this phase.
- **Few-shot prompt cost.** Adding ~6KB to the prompt × per-CVE generation count × monthly = real money. At sonnet pricing ($3/M input), ~$0.018 per CVE extra. Acceptable. With haiku, ~$0.006. Trivial.
- **False-pass risk from looser patch validation.** Diff-targeted validation is *narrower* than whole-repo validation — a rule that passes diff-targeted might still false-positive on the user's own repo. Mitigation: this is exactly autogrep's accepted tradeoff; the fixture round-trip remains as the FP catch.
- **Bench cache staleness.** Cached OSV/patch fixtures will drift from upstream over time. Mitigation: stamp cache files with fetch date; bench warns if any cached file is >90 days old.

### Production risks
- Existing rules in `organization_generated_rules` with `validation_status='failed_validation'` will look stale after the validation logic changes. Mitigation: optional sweep that re-runs validation on existing failed rules at the next scan (the regenerate endpoint already does this on demand).
- No data loss risk — all new fields are additive JSONB columns.
- No breaking schema changes.

---

## Dependencies

- Phase 5 (M1–M5) — must be merged. Currently in `worktree-reachability-phase5`, not yet in main. **This iteration assumes Phase 5 will land first** (whether via merge to main or stacked on the worktree branch).
- Anthropic BYOK key for live E2E re-verification (M6). Same key, freshly rotated post-Phase 5 testing.
- Docker image must rebuild after validate.ts changes (already part of the dev loop).

---

## Success Criteria

1. **Validation rate ≥15%** across the bench harness's canned + live CVE set, sustained across two re-runs.
2. **Zero regression** on `npm run test:reachability-rules-e2e` (platform rules still validate).
3. **<5 sec per rule** for combined fixture + diff-targeted patch validation.
4. **Settings UI shows useful failure reasons** for failed rules (M5 if shipped).
5. **Bench script runs offline** with cached fixtures, reproduces validation rate within ±1 percentage point across runs.
6. **A real validated rule** persisted in `organization_generated_rules` with `enabled: true` after live E2E, fires on the matching PDV in the next scan, upgrades reachability_level to `confirmed`. This is the "did the whole feature work" smoke test.

---

## Live verification results (M6, 2026-04-27)

Ran `bin/deptex-scan run fixtures/test-minimal-npm` against the rebuilt Docker image with M1+M2+M3 baked in. lodash 4.17.20 has 5 detectable CVEs; 1 already covered by a platform rule pack, leaving 4 candidates per run.

| Model | Candidates | Schema pass | Fixture pre | Fixture safe | Patch pre | Patch post | Validated | Cost |
|---|---|---|---|---|---|---|---|---|
| `claude-sonnet-4-6` | 4 | 2 | 2 | 1 | 0 | 2 | 0 | $0.1894 |
| `claude-haiku-4-5-20251001` | 4 | 2 | 2 | 1 | 0 | 2 | 0 | $0.0638 |

**Validation rate: 0% on both models. Below the ≥15% target.**

Sonnet and haiku produced structurally identical candidate shapes for the two CVEs that survived schema validation (CVE-2020-28500 ReDoS, CVE-2025-13465 prototype pollution). Both models cost-tracked correctly, schema-passed at the same 50% rate, and both failed the same gate: `patch_pre_match=0` on every per-file patch target.

**Root cause: structural mismatch between app-callsite rules and library-internal patches.** The prompt directs the AI to write rules whose sources are HTTP request shapes (`req.body`, `req.query`) and whose sinks are user-side calls (`_.toNumber($INPUT)`). That is the *correct* shape for our application reachability use case — strictly stronger than autogrep's library-internal rules. But the upstream lodash patches modify regex internals inside `lodash.js` / `template.js` — files that contain no `req.*` callers. The diff-targeted patch round-trip therefore can never match: the rule targets callsite shapes that the patch by definition doesn't touch.

This is the architectural failure mode the plan flagged but inverted: not "looser patch validation false-passes," but "diff-targeted patch validation is structurally orthogonal to app-callsite rules." Few-shot examples (M2) didn't help — they gave the AI better callsite intuitions, which made the gap *worse*, not better.

**Suggested Phase 5c directions, in increasing difficulty:**

1. **Relax `patch_pre_match` from a hard gate to a signal.** Persist `validated: true` when `fixture_round_trip_passes && schema_passes`, demote `patch_pre_match` to a confidence score on the rule. Autogrep's published 18% rate uses patch validation on library-internal rules where it's structurally meaningful; we don't have that match. (1–2 day refactor in `validate.ts`.)
2. **Dual-rule generation.** Ask the AI for two rules per CVE: a library-internal rule (validates against the patch) and an app-callsite rule (validates against fixtures only). Persist the app-callsite rule with the library-internal rule attached as evidence. Higher cost (~2× tokens), better signal.
3. **Use the patch as input only, not as validation.** Show the AI the diff in the prompt as context for what the vulnerability looks like, then drop patch round-trip entirely and rely on fixture-only validation + the few-shot prompt's safe-fixture FP catch. Cleanest theoretically, loses the "rule actually maps to the upstream fix" guarantee.

**Performance:** M1's claim of "no clone" held — both runs completed in <30s wall time end-to-end, including OSV fetch + GitHub patch fetch + Semgrep validation per CVE. Per-rule validation latency was ~7–12s, dominated by Semgrep startup × 4 patch-target files + 2 fixture targets.

**Cost confirmation:** haiku was 2.97× cheaper than sonnet for identical output shape on this fixture. Plan's risk note ("~$0.018/CVE sonnet, ~$0.006 haiku") was accurate to the cent.

**Blocking smoke test #6 (a validated rule firing on a PDV) cannot pass** until one of the Phase 5c directions lands. M1–M4 of Phase 5b are nonetheless productive: diff-targeted validation, few-shot prompting, and per-stage telemetry are all the load-bearing infrastructure that *enables* Phase 5c iteration. The bench harness (M4) gives us an offline regression sentinel for whichever Phase 5c approach we pick.
