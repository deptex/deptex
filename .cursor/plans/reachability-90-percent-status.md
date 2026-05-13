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
| **2b dict-key taint** | `bdf0549` | Python IR lowerer walks `pair.key` + `dictionary_splat` in dict literals, not just `pair.value`. Closes the lowerer-side gap on jinja2-22195 / jinja2-34064 shape. Note: those CVEs ALSO need a receiver-pattern fix (`tmpl.render` vs `jinja2.Template.render(*)`) before they fully validate in iterate — tracked as Phase 2b-followup. New flask-dict-key-taint-{vuln,safe} fixture in python-vulns/. |

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
