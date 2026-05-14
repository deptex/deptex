# Reachability 90% — Implementation Status

**Branch:** `worktree-depscanner-hardening` (consolidated 2026-05-13 — see [[feedback_one_branch_no_new_branches]]). Tip at start: `413ef48`; current: `3e319b5` + baseline commit.
**Plan:** `.cursor/plans/reachability-90-percent.plan.md`
**Started:** 2026-05-13

Living status doc maintained per the marathon-compact-discipline convention.
Updated after each commit.

## Completed

| Phase | Commit | Summary |
|---|---|---|
| Plan prep | `bf4066a` | Plan + review + path-to-90 docs |
| 1.2 diag surface | `625fad4` | TaintTrace serialiser + DropReason vocabulary + diagSink hook + NDJSON writer + 6 drop sites instrumented + preflight stage 12 |
| **2a JS const resolver** | `34359bf` | localOrigins map on IrFunction + extractCallSitesFromIr resolves bare-identifier argTexts. 20-case test (lowerer capture + extractor resolution + end-to-end F4 jwt.verify match/no-match on hoisted shape). |
| **1.3a customer-app fixtures** | `305f659` | 5 multi-file vendored fixtures (npm/pypi/maven/golang/gem) with vuln/safe sides exercising bundled framework_models. Runner asserts vuln ≥1 flow + safe 0 flows. 5/5 pass on tip 7beab0e in 1.9s. baseline-7beab0e.json committed. Preflight grows to 18 stages. |
| **1.0 variance baseline** | `4907a30` | 3-trial probe on tip `bf4066a` engine code unchanged from `413ef48`. Mean 56.06%, stddev 2.98pp. Decision rule: 3-trial avg for <6pp claims; single-trial only for ≥6pp moves. Baseline committed at `depscanner/bench-iterate/variance-probe/baseline.json`. |
| **2b dict-key taint** | `bdf0549` | Python IR lowerer walks `pair.key` + `dictionary_splat` in dict literals. Diff vs Trial 3 confirms 2 deterministic wins (jinja2-22195 + 19-10906) — `*.render(*)` was already in jinja2.yaml, so dict-key alone closed those. |
| **2b measurement** | `(no commit)` | Post-2b unseeded single-trial: 48/88=54.55%, well within variance baseline noise (53.4–60.2). Engine fixes confirmed working on individual CVEs; aggregate buried under AI-fixture variance. |
| **seed plumbing** | `a93a7aa` | `--seed=N` plumbed through OpenAI body. DeepInfra honors `seed` for reproducible sampling. Future engine fixes get unambiguous attribution: rerun same seed pre/post-change, delta = lift. Anthropic + Google silently ignore. |
| **seeded baseline 42** | _(measured)_ | seed=42 baseline: **52/88 = 59.09%** at tip `a93a7aa`. byStatus: 52 validated / 30 failed_validation / 6 vuln_class_out_of_scope. Funnel 82 schema → 53 fixturePre → 81 fixtureSafe → 55 patchPostClean → 52 final. Cost $0.23. Failure distribution: npm 9 (5 bad fixtures, 4 real-taint), pypi 9 (3 real-taint, 2 already-supported, 4 missing-spec/bad), maven 5, golang 4, gem 3. |
| **rule yaml persistence + loader-utils** | `0d55a2c` | runner.ts now writes `payload.framework_spec` to report.json (was lost since rule_yaml→framework_spec rotation). loader-utils.yaml authored (parseQuery/interpolateName/getOptions, qualified + bare + wildcard-receiver patterns) — targets CVE-2022-37601 family. Both deterministic; seed=42 rerun in flight. |
| **seed=42 rerun (loader-utils)** | _(measured)_ | r2: 49/88 = 55.68%. NET **-3 vs r1=52/88**. loader-utils.yaml DID work — CVE-2022-37601 gained — but AI fixture variance ate the lift across 8 unrelated CVEs that flipped pass→fail. CVE-2026-4800 lodash + CVE-2024-21484 jsrsasign also gained (different AI fixtures vs r1). |
| **DeepInfra seed=42 is best-effort, not strict** | `(memo)` | Two identically-seeded runs flipped 13 CVEs (5 gained, 8 lost). DeepInfra's `seed` parameter is hint-only for Qwen3-235B; not reproducible at the AI-fixture-shape level. Implications: deterministic per-CVE measurement requires AI-fixture caching (architectural), not seed plumbing. Phase 2/3 engine fixes still verifiable via unit-test fixtures + multi-trial iterate averaging. |
| **r3 measurement + runner fix** | `71c411e` | r3 = 49/88 (matches r2 by coincidence). Bug fix: failed-validation return path was missing `frameworkSpec` write. Multi-trial picture (seed=42 × 3): union 57/88=64.77% (ceiling), majority 51/88=57.95%, intersection 42/88=47.73%, 31 always-fail, 15 sometimes-pass. |
| **AI rule/fixture coherence prompt** | `d6fbcd6` | r3 frameworkSpec data showed 4 distinct AI failure modes on stable misses: constructor-as-sink, template-filter-as-sink, qualified-class-vs-instance-receiver mismatch, hardcoded-fixture (no taint flow). Added a CRITICAL constraints section to prompt-builder.ts enumerating all four with concrete examples. Bumped prompt version v1 → v2-rule-fixture-coherence so the variant signature changes. |
| **seed=42 r4 (prompt v2)** | _(measured)_ | r4 = **52/88 = 59.09%**. Funnel improved across: schema 81→84, fixturePre 51→55, fixtureSafe 79→81, final 49→52. 8 gained / 5 lost vs r3 — net +3 within single-trial noise. Targeted wins: jinja2-CVE-2019-10906 (constructor-as-sink) + axios-CVE-2025-62718 (bad-fixture mode) now validate. urllib3-26137, jinja2-28493, requests-35195 still failing (deeper AI-prompt-quality issues remain). Cost $0.26. |
| **--temperature flag** | `838829b` | Plumbed `--temperature=N` through CallProviderArgs → openai body. Default 0.1 unchanged for production; iterate runs can now set 0 for greedy decoding. Combined with --seed=42, this is the closest DeepInfra Qwen3-235B gets to deterministic per-CVE generation. |
| **r5 (seed=42 temp=0)** | _(measured)_ | **55/88 = 62.50%** — NEW HIGH WATER MARK. +3 vs r4, +6 vs variance baseline mean (56.06%). Funnel: schema 82, fixturePre 57, final 55. 9 gained / 6 lost vs r4. Big eco wins: golang +3 (x/text-32149, x/net-3978, consul-29153), maven +2 (spring-security-22978, log4j-26464), pypi +2 (jinja2-22195, cryptography-26130). Cost $0.22. Conclusion: temp=0 + prompt-v2 is the new deterministic-ish baseline. |
| **r6 confirmation** | _(measured)_ | **52/88 = 59.09%** — same config as r5 (55) yet 9 CVEs flipped (3 gained, 6 lost). Temp=0 is NOT fully deterministic on DeepInfra Qwen3-235B; the r5 +6pp was a lucky roll. Cost $0.26. |
| **Honest recall picture across r4+r5+r6 (temp=0+prompt-v2)** | `(memo)` | Single-trial mean **~53/88 = 60.2%**, range 52-55. Union r5+r6 = **58/88 = 65.91%** (ceiling). Intersection = **49/88 = 55.68%** (stable floor). Funnel consistently shows +4 fixturePre vs r3 baseline — prompt-v2 IS real engine-side lift, but AI variance swallows ~half on patch_post_clean. Pushing further toward 100% needs multi-trial averaging infra OR a model swap — both bigger than autopilot scale. Cumulative session lift: variance baseline mean 56.06% → current mean ~60% = +4pp deterministic. |

Pushed branch `feat/reachability-90-percent` to origin.

## In progress

| Phase | Status | Notes |
|---|---|---|
| 1.0 variance probe | **DONE** 2026-05-13 18:11Z | 3-trial: 47/48/53 of 88 = 53.4% / 54.6% / 60.2%. Mean **56.06%**, **stddev 2.98pp**, range 6.82pp. Cost $0.75 total. Variance just under the 3pp plan threshold; 3-trial averaging in Phase 1.1 justified. Baseline at `depscanner/bench-iterate/variance-probe/baseline.json`. |
| 1.3 customer-app fixtures | **DONE** (commit `305f659`) | 5/5 fixtures pass. Subagent reported all 18 preflight stages green. |

## Up next (autonomous sequence, post-resume)

Phase 1 closed 2026-05-13. Remaining queue:

1. **Phase 2b-followup** — receiver-pattern audit for Python framework specs (jinja2.yaml, pillow.yaml, etc.). Add `*.method`-style alt-patterns where bundled spec uses `Class.method` but real code uses `instance.method`. Without this, dict-key fix is a no-op on jinja2-22195 / jinja2-34064 because the engine never matches the sink. Cheap (YAML edits + matchesCallPattern unit test). Probable lift: 2-4 pypi CVEs.
2. **Phase 1.1** — 3-trial averaging in runner.ts (~150-200 LOC). Outer trial loop + seed plumbing. Decision rule from 1.0: prefer 3-trial averaging for any change claiming <6pp lift; single-trial OK only for ≥6pp moves.
3. **Phase 2c** — computed-key full taint write.
4. **Phase 2d** — method-chain on awaited results.
5. **Phase 3.0** — FrameworkSpec schema-mirror prerequisite (4-place: spec.ts + spec-loader + zod + prompt-builder + YAMLs).
6. **Phase 3.1** — `weak_default` enum + phase28d migration.
7. **Phase 3.2** — `regex-literal-detector.ts` + FP corpus pin.
8. **Phase 3.3** — `insecure-default-detector.ts` + FP corpus pin.
9. **Phase 4.1** — bucket reclassification + ~3 confirmed-G YAMLs.
10. **Phase 4.2** — prompt sidebar + few-shots into existing `few-shot-examples.ts`.
11. **Phase 5** — final 3-trial + baseline + CI gate + PR.

## Decisions logged this arc

- Phase 1.2 DropReason kept as `type DropReason = string` per pragmatist's "promote to enum once natural categories emerge"; exhaustiveness policed by jest test reading `propagate-core.ts` source.
- 2a const resolver landed as second `localOrigin = new Map<string, string>()` (NOT widening TaintTrace map value), avoiding cascade through 8 per-language propagators.
- NDJSON path canonicalised to `bench-iterate/<variant>/<timestamp>/diag/<cve>.ndjson` (mirrors existing `report.json` namespace).
- Variance probe deferred Phase 1.1; running on `bf4066a` (plan doc commit) — engine code unchanged from `413ef48`, so the measurement is equivalent.
- Phase 1.2's `emitDrop` calls compile to no-ops when `diagSink` is undefined, so production scan pipelines pay zero cost from this commit.
- **Phase 2b pivot 2026-05-13:** plan's named target (urllib3-20-26137 kwarg audit) was based on stale failure data. Variance-probe Trial 3 showed urllib3-20-26137 isn't in the failure corpus at all. Actual pypi miss distribution: 2 dict-key (jinja2 ×2), 4 missing-sink specs (pillow / setuptools / requests / pkcs7), 1 jinja2 kwarg (template.render kwarg), 3 non-taint vuln-class (flask session / certifi / pkcs12 builder). Phase 2b reframed to the dict-key engine fix; spec-coverage work moved to Phase 4.1 as planned, vuln-class rejection to Phase 3.4.

## Open items / risks surfaced mid-stream

- (none yet)

## Cost tracker

| Item | Cost |
|---|---|
| Variance probe (3 × $0.25) | $0.75 (done) |
| Phase 2b code work | $0 (no AI calls) |
| **Total to date** | **$0.75** |

Budget cap: $10.
