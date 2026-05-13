# Reachability 90% — Implementation Status

**Branch:** `feat/reachability-90-percent` (off `worktree-depscanner-hardening` tip `413ef48`)
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

Pushed branch `feat/reachability-90-percent` to origin.

## In progress

| Phase | Status | Notes |
|---|---|---|
| 1.0 variance probe | running (bg task `boadfd32b`) | 3 sequential 88-CVE iterates on tip `bf4066a` (engine code unchanged from `413ef48`). Trial 1 past CVE 30/88 at last check. ETA ~2-3 hours from launch. Output at `depscanner/bench-iterate/variance-probe/trial-{1,2,3}/report.json`. |
| 1.3 customer-app fixtures | **DONE** (commit `305f659`) | 5/5 fixtures pass. Subagent reported all 18 preflight stages green. |

## Up next (autonomous sequence, post-resume)

When the next turn picks this back up:

1. **Check variance probe** — `tail bench-iterate/variance-probe/run.log` and `ls bench-iterate/variance-probe/trial-{1,2,3}/` to see if all 3 trials completed. If yes, parse the report.json files into a stddev calculation and decide --trials=3 default vs single-seed.
2. **Check customer-app subagent** — if it completed, the fixtures + runner + preflight wire-in + baseline should be on disk and committed. If not, wait.
3. **Phase 1.0 + 1.3b artifact** — commit `bench-iterate/variance-probe/baseline.json` with per-trial pass/fail matrix + global stddev. Update plan if variance >3pp.
4. **Phase 2b** — Python kwarg-aware sink matching audit (~30-60 LOC in `taint-engine/python/{propagate,ir}.ts`). Targets urllib3-20-26137.
5. **Phase 1.1** — 3-trial averaging in runner.ts (~150-200 LOC). Outer trial loop + seed plumbing. Decision rule from 1.0 result.
6. **Phase 2c** — computed-key full taint write.
7. **Phase 2d** — method-chain on awaited results.
8. **Phase 3.0** — FrameworkSpec schema-mirror prerequisite (4-place: spec.ts + spec-loader + zod + prompt-builder + YAMLs).
9. **Phase 3.1** — `weak_default` enum + phase28d migration.
10. **Phase 3.2** — `regex-literal-detector.ts` + FP corpus pin.
11. **Phase 3.3** — `insecure-default-detector.ts` + FP corpus pin.
12. **Phase 4.1** — bucket reclassification + ~3 confirmed-G YAMLs.
13. **Phase 4.2** — prompt sidebar + few-shots into existing `few-shot-examples.ts`.
14. **Phase 5** — final 3-trial + baseline + CI gate + PR.

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
| Variance probe (3 × $0.22) | ~$0.66 (running) |
| **Total to date** | **~$0.66** |

Budget cap: $10.
