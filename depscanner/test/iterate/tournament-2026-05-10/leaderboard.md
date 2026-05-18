# Source/Sink-Mismatch Tournament — 2026-05-10 (PARTIAL)

Corpus: 15 CVEs that v_base failed with source_sink_mismatch on the
2026-05-10 88-CVE benchmark (schema_pass=true, fixture_pre_match=false).
Stratified across npm/pypi/maven/golang/rubygems.

Model: openai/Qwen/Qwen3-235B-A22B-Instruct-2507 via DeepInfra.
Concurrency 5. Production retry path (`MAX_GENERATION_ATTEMPTS=4` with
validation-feedback prompts) preserved so the numbers are apples-to-apples
with the production rule-gen pipeline.

## Status

The tournament was **truncated after v_b** because per-variant runtime
ran longer than budgeted (~10–13 min/variant × 6 = ~70 min, vs. the
~40 min window available before this task's hard timeout). v_c, v_d, v_e
were not measured; their hypotheses remain open. The 3-variant data we
do have is insufficient to declare a winner.

## Leaderboard (3 of 6 variants measured)

| Rank | Variant | Version | Validated / 15 | Schema pass | Fixture pre-match | Cost |
|------|---------|---------|----------------|-------------|--------------------|------|
| 1 (tie) | v_a_source_expansion | tournament-2026-05-10-a | 2 / 15 (13.3%) | 13 / 15 | 2 / 15 | $0.0703 |
| 1 (tie) | v_b_canonical_fewshot | tournament-2026-05-10-b | 2 / 15 (13.3%) | 15 / 15 | 2 / 15 | $0.0764 |
| 3 | v_base | base-framework-spec-v1 | 1 / 15 (6.7%) | 15 / 15 | 1 / 15 | $0.0736 |
| (untested) | v_c_chain_of_thought | tournament-2026-05-10-c | — | — | — | — |
| (untested) | v_d_anti_patterns | tournament-2026-05-10-d | — | — | — | — |
| (untested) | v_e_minimal | tournament-2026-05-10-e | — | — | — | — |

## Per-CVE pass map (3 measured variants)

| CVE | v_base | v_a | v_b |
|-----|--------|-----|-----|
| CVE-2025-62718 (axios SSRF) | PASS | fail | PASS |
| CVE-2022-25883 (semver ReDoS) | fail | PASS | fail |
| CVE-2024-32465 (git Ruby) | fail | PASS | PASS |
| (other 12 CVEs) | all fail | all fail | all fail |

## Findings

1. **High inter-run variance.** v_base passed CVE-2025-62718 in this run
   but FAILED it on the original 88-CVE benchmark a day earlier. With
   Qwen3-235B at temperature 0 we still see stochastic completion-time
   variance in DeepInfra's load-balanced inference. A single 15-CVE pass
   does not have enough power to discriminate a real +6% improvement
   from variance at this corpus size.

2. **v_a and v_b both lifted +1 unique CVE.** v_a passed CVE-2022-25883
   and CVE-2024-32465 (where v_base failed); v_b passed CVE-2024-32465 +
   the same v_base-passable CVE-2025-62718. The unique CVE intersection
   between v_a and v_b is CVE-2024-32465 (Ruby `git` gem env-var
   handling) — both variants pushed the model toward the HTTP-handler
   fixture shape, which apparently broke through on this specific case.

3. **v_a regressed 2/15 to `invalid_schema`.** The ecosystem
   source-shopping-list addendum (which is large — 7218 chars vs
   v_base's 5391) appears to push some completions off-schema. v_a's
   schema_pass funnel = 13/15 (vs v_base's 15/15). This is a real cost.

4. **No variant cleared the +2σ threshold.** With a baseline 33% global
   pass rate and 15-CVE samples drawn from the failing 67%, "real" lift
   would need to be ≥3 / 15 = 20% to be statistically distinguishable
   from baseline noise. Neither v_a nor v_b cleared this bar with the
   partial data we have.

## Decision

**No production prompt change.** The partial-tournament result does not
support adopting any of v_a, v_b. v_c / v_d / v_e are not measured.

The brief explicitly allows "Tournament found no improvement IS a valid
result" — we treat the inconclusive partial as that outcome rather than
ship a regression.

## Total tournament spend (partial)

$0.2203 across 3 variants × 15 CVEs = 45 rule-gen calls (DeepInfra Qwen).

Remaining $1.28 of the $1.50 budget unspent. Could be used by a follow-up
agent to:
  (a) finish v_c, v_d, v_e on the same 15-CVE corpus (~$0.25, ~30 min) or
  (b) re-run all 6 variants on the full 29-CVE mismatch corpus with
      MAX_GENERATION_ATTEMPTS=1 for cleaner signal (~$0.50, ~60 min).

## Follow-up ideas

- **Repeat-trial averaging.** Run v_base + the top 2 variants 3× each on
  the same 15-CVE corpus and average; reduces variance by ~√3.
- **Stratified-rerun A/B against fixed CVE seeds.** With temperature 0
  and DeepInfra fixed, paired comparisons (same CVE, run-pair-aligned)
  are stronger than independent samples.
- **Feedback-loop generation.** Per the `ai_rule_generation_ceiling.md`
  memory, the ~15–20% one-shot ceiling has a feedback-loop alternative
  that could push to 40–60%. That's the recommended next track once
  one-shot prompt-quality experiments converge.
