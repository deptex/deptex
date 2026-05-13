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
| **1.0 variance baseline** | _(pending commit)_ | 3-trial probe on tip `bf4066a` engine code unchanged from `413ef48`. Mean 56.06%, stddev 2.98pp. Decision rule: 3-trial avg for <6pp claims; single-trial only for ≥6pp moves. Baseline committed at `depscanner/bench-iterate/variance-probe/baseline.json`. |

Pushed branch `feat/reachability-90-percent` to origin.

## In progress

| Phase | Status | Notes |
|---|---|---|
| 1.0 variance probe | **DONE** 2026-05-13 18:11Z | 3-trial: 47/48/53 of 88 = 53.4% / 54.6% / 60.2%. Mean **56.06%**, **stddev 2.98pp**, range 6.82pp. Cost $0.75 total. Variance just under the 3pp plan threshold; 3-trial averaging in Phase 1.1 justified. Baseline at `depscanner/bench-iterate/variance-probe/baseline.json`. |
| 1.3 customer-app fixtures | **DONE** (commit `305f659`) | 5/5 fixtures pass. Subagent reported all 18 preflight stages green. |

## Up next (autonomous sequence, post-resume)

Phase 1 closed 2026-05-13. Remaining queue:

1. **Phase 2b** — Python kwarg-aware sink matching audit (~30-60 LOC in `taint-engine/python/{propagate,ir}.ts`). Targets urllib3-20-26137.
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

## Open items / risks surfaced mid-stream

- (none yet)

## Cost tracker

| Item | Cost |
|---|---|
| Variance probe (3 × $0.25) | $0.75 (done) |
| **Total to date** | **$0.75** |

Budget cap: $10.
