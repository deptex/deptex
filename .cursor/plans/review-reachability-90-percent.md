# Plan Review — reachability-90-percent (round 2)

**Verdict: REWORK (surgical)**

Plan reviewed: `.cursor/plans/reachability-90-percent.plan.md` (revised after first review)
Mode: lean (6 personas, no debate)
Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout
Vote tally: 1 READY / 3 REVISE / **2 REWORK**
Findings: 5 P0 / 13 P1 / 13 P2 / 10 P3

Prior review at this same path was overwritten — that one returned REWORK on 7 P0s; the new P0s are different and much smaller in shape (factual fixes, not structural rewrites).

## Summary

The rewrite absorbed all 7 P0s and 14 amendments from round 1 — the structural concerns (enum-mirror breakage, scope creep, projection over-credibility, test coverage) are resolved. The new P0s (5) are smaller-shape: two are "plan says 'reuse X' but X doesn't exist yet" (TaintTrace serialiser, validate.ts shape-trace mode), one is "new FrameworkSpec primitive doesn't enumerate the 4-place schema mirror chain it has to touch," and two are "test threshold asserted without specifying its denominator/decision rule" (real-CVE corpus shape, detector precision gate). All five are 1-paragraph plan patches, not redesigns. Pragmatist, scope-cutter, and opportunity-scout all returned approve-with-nits — direction is sound, ~1.5-2 days of trims still available, no blockers.

## Vote Tally

| Persona | Vote | Top concern | Rationale |
|---|---|---|---|
| skeptic | REVISE | skeptic-f3 | Detector-regime track record is shaky; 3.2/3.3 +1.3 credit each is coupled to 4.2 prompt work landing first |
| pragmatist | REVISE | 4.0 reclassification spike | Plan is substantially tighter; ~1.5-2 days of optional ceremony left (spike, prompt-eval, CI gate) |
| scope-cutter | REVISE | 1.3 real-CVE corpus | 10 fixtures may be 2x smoke-gate minimum; spike could be folded into 4.1a |
| architect | REWORK | ARCH-1, ARCH-2, ARCH-3 | Two plan steps name infra that doesn't exist (TaintTrace serialiser, validate.ts shape-trace); FrameworkSpec primitive doesn't traverse the 4-place mirror chain |
| test-strategy-auditor | REWORK | TS-1, TS-2, TS-3 | Variance decision rule unspecified; real-CVE fixture shape and runtime budget unspecified; precision gate denominator unspecified |
| opportunity-scout | READY | — | Direction sound; P3 opportunities are non-blocking |

## P0 — Fundamental Concerns

### infrastructure-doesn't-exist: TaintTrace serialiser must be BUILT, not reused `[SOLO]`
- **Plan section:** Phase 1.2 (per-CVE diagnostic dump)
- **Claim:** Plan says "REUSING TaintTrace serialiser in propagate-core.ts." `TaintTrace` is a data-only interface in `flow.ts:76` — there is no serialise/serialize/toJSON method anywhere. JSON.stringify works incidentally, but there is no canonical serialiser, no schema, no DropReason union, no round-trip test.
- **Suggested patch:** Re-scope 1.2 from "reuse" to "add `serializeTrace(trace): TraceJson` next to TaintTrace in flow.ts + `DropReason` union + `serializeDiagnosticRecord(...)` in propagate-core.ts." LOC budget ~30-50.
- **Flagged by:** architect (ARCH-1)

### infrastructure-doesn't-exist: validate.ts has no shape-trace mode `[SOLO]`
- **Plan section:** Phase 4.0 (bucket reclassification spike)
- **Claim:** Plan references "validate.ts shape-trace mode" but `depscanner/src/rule-generator/validate.ts` only has Gates 1/2/3. No --shape-trace flag, no instrumentation surface, no corpus-walk orchestration. Grep confirms zero matches for shape-trace/shape_trace/shapeTrace.
- **Suggested patch:** Either (i) explicitly call out "build shape-trace mode in validate.ts as first sub-step of 4.0" with LOC budget (~50, leverages 1.2 DropReason), or (ii) replace with manual classification of 6 candidates using 1.2 diag output (cheaper; corpus is small).
- **Flagged by:** architect (ARCH-2)

### schema-mirror-incomplete: new FrameworkSpec primitives don't traverse the 4-place chain `[SOLO]`
- **Plan section:** Phase 3.2 / 3.3 (regex-literal + insecure-default detectors)
- **Claim:** Plan adds `unsafe_regex_patterns` + `insecure_defaults` as "FrameworkSpec primitives" but only names the new detector files. FrameworkSpec has FOUR concurrent shape declarations that must agree: (1) TS interface `spec.ts:131-140` (closed shape), (2) `spec-loader.ts` hand-rolled validator (extra keys silently ignored — new fields won't load), (3) `framework-spec-schema.ts:115-122` zod with `.strict()` (will REJECT new fields the AI emits), (4) `prompt-builder.ts` + `few-shot-examples.ts`. Plus 23 bundled YAMLs would need optional defaults. Without enumerating these edits, Gate 2 round-trip in validate.ts will reject every spec the model emits with the new primitives.
- **Suggested patch:** In 3.2/3.3, enumerate edits to all four mirrors + YAML migration story ("optional, default to empty array"). Add a Phase 3.0 prerequisite: extend FrameworkSpec schema chain BEFORE writing detector files.
- **Flagged by:** architect (ARCH-3)

### threshold-without-baseline: 10-fixture real-CVE corpus shape and ≥70% threshold unspecified `[SOLO]`
- **Plan section:** Phase 1.3 (10-fixture real-CVE corpus)
- **Claim:** Two unspecified dimensions: (a) "real-shaped multi-file" is undefined — 1 source file? 3-5 files? full vendored npm dep tree? (b) test:real-cve listed as per-commit gate but if fixtures clone/fetch/Docker-boot, per-commit is infeasible. (c) ≥70% threshold asserted before the corpus exists — by definition no baseline.
- **Suggested patch:** Split 1.3 into 1.3a (author corpus + measure baseline on tip 413ef48 + commit baseline) and 1.3b (set threshold = baseline + 10pp, NOT a fixed 70%). Specify each fixture is N≥3 self-contained vendored source files exercising a cross-file edge, no network at test time. Assert wall-clock budget <30s on CI; if exceeded, demote from per-commit to per-wave.
- **Flagged by:** test-strategy-auditor (TS-2) + skeptic (skeptic-f4)

### gate-without-denominator: detector precision ≥90% gate has no fixed corpus `[SOLO]`
- **Plan section:** Phase 3.2 / 3.3 (precision threshold gates)
- **Claim:** "Precision ≥90% gate before detector votes in iterate" — against ≥10 hand-authored negatives, 90% is trivially achievable and meaningless. Against malicious-v2 known-clean, the corpus size is unknown. Without a frozen, sized negative corpus the gate can pass on a small subset and silently regress.
- **Suggested patch:** Pin the negative corpus: "precision measured as TP/(TP+FP) on malicious-v2 known-clean snapshot at commit `<SHA>`, N≥500 files." Commit `test/detectors/<detector>/fp-corpus.manifest.json`. Separately state what the ≥10 hand-authored negatives enforce (smoke/shape correctness), distinct from the precision gate.
- **Flagged by:** test-strategy-auditor (TS-3)

## P1 — High-Priority Gaps

### credit-factor-evidence (skeptic-f1)
0.65 blanket factor presented as calibrated but no evidence ties it to prior sprint's actual TAM-vs-realized ratio. Add Phase 1.0a backtest, or widen projected range to 65-78% instead of point estimate 71.6%, or split factor by lever class (engine 0.7-0.8 vs prompt/spec 0.4-0.5).

### prompt-fix-credit-optimism (skeptic-f2)
4.2 bucket-I credit of 0.5 is high given few-shot-examples.ts has 6 weeks of iteration baked in. Drop to 0.3 → projection lands ~70.7%, putting 72% target at meaningful risk.

### detector-regime-coupling (skeptic-f3)
3.2/3.3 detector wins are COUPLED to 4.2 prompt work — AI must emit `unsafe_regex_patterns`/`insecure_defaults` shapes the engine can match. Plan applies full 0.65 credit independently. Sequence 4.2 BEFORE 3.2/3.3, or drop 3.2/3.3 credit to 0.4. Add Gate-0 per detector: "AI emits matching primitive on ≥1 of N target CVEs in dry-run before merge."

### target-above-projection (skeptic-f9)
Bottom-up projection lands 71.6% (after rounding 63/88), success criterion is ≥72%. Plan's own arithmetic fails the gate by 0.4pp. Lower criterion to ≥70% with stretch ≥74%, OR add one more lever, OR don't ship a plan whose own math misses target.

### trials-flag-plumbing (ARCH-4)
`--trials=3` ≠ what runner.ts's existing retry loop does (which short-circuits on first success with revision feedback). Real implementation is OUTER loop running `processCveCandidate()` N times with seed variation + majority verdict + stddev + seed parameter through `callProviderAndParse`/`generate.ts`. ~200 LOC, not a flag flip. Call out explicitly.

### ndjson-convention-new (ARCH-5)
Deptex has zero existing NDJSON producers. Plan introduces it for diag dumps without justification. Pick the format, document it. Also: path should match existing namespacing: `bench-iterate/<variant>/<timestamp>/diag/<cve>.ndjson` not `bench-iterate/<ts>/diag/<cve>.ndjson`.

### local-map-shape-ambiguous (ARCH-6)
"Extends local map with localOriginExpr" — current value type is `Map<string, TaintTrace>`, consumed by 8 per-language propagators. Plan must pick: (i) widen value to `{trace, originExpr?}` (touches all 8 propagators), OR (ii) add a SECOND map `localOrigin = new Map<string, string>()`. Today reads ambiguously.

### spike-output-artifact (TS-4)
4.0 reclassification spike doesn't specify output artifact. State: JSON shape-trace at `bench-iterate/shape-traces/<date>/<cve>.json` with fixed schema (Zod or jest schema test). 4.1a YAML authoring cites the trace file SHA.

### prompt-eval-noise-floor (TS-5)
4.3 prompt-eval ±5pp gate doesn't measure noise floor first. LLM non-determinism on 12 CVEs can swing >±5pp between identical prompts. Run prompt-eval 3 times on UNCHANGED prompt first; commit `bench-iterate/prompt-eval/noise-floor.json`; gate becomes `max(5pp, 2*observed_stddev)`.

### ci-gate-automation (TS-6)
5.3 CI workflow doesn't specify the diff step. Without a script that reads baseline.json + current.json and exits non-zero, the gate is advisory. Specify `bench-iterate/scripts/diff-baseline.ts` + jest test for threshold math.

### reclassification-spike-duplicates-work (pragmatist + scope-cutter)
4.0 is process for its own sake — either the spike is a no-op (we already know from 1.2 dump) or 4.1a can't start without it (then it IS the first hour of 4.1a). Fold 4.0 into 4.1a.

### prompt-eval-duplicates-iterate (pragmatist + scope-cutter)
4.3 12-CVE prompt-eval is a sub-corpus of the existing 88-CVE iterate. Per-eco sub-aggregate of the 88-CVE answers the same question. Drop 4.3 as independent infra; replace with "rerun 88-CVE single-trial, check per-eco sub-aggregate doesn't regress >5pp."

### enum-still-extends-spec.ts:40-43 (skeptic-f7)
Even with weak_default scoped narrowly, the principle "engine enum is closed; out-of-scope is the escape hatch" is bent. Try routing insecure-default through `vuln_class_out_of_scope` with a sub-tag instead of a new enum value. Or document why weak_default is structurally different from DoS-family and confirm the 8-site footprint is acceptable.

## P2 — Quality Gaps

- **skeptic-f6** LOC contingency framing (2-3x) contradicts 150 LOC replan trigger. Pick one.
- **skeptic-f8** Wave-cadence iterate runs may not distinguish per-step wins under variance. Decide cadence after 1.0 measures variance.
- **skeptic-f10** $20 cap not decomposed. Real estimate ~$7.50 with contingency = $10 cap honest.
- **skeptic-f11** 2d TAM=2 is both axios CVEs — correlated risk; really TAM=1 with diversity loss. Score at +0.65 not +1.3.
- **skeptic-f12** R5 "parallelize per-language" fixture authoring is fictional for solo iterator unless sub-agents are explicit.
- **pragmatist** 10 real-CVE fixtures may be 2x smoke-gate minimum; could start at 5.
- **pragmatist** CI drift gate is ceremony for solo pre-launch.
- **pragmatist** DropReason 15-code enum is premature; start free-text, promote after 1-2 runs.
- **scope-cutter** Fixture matrix could be ≥2 pos + ≥1 neg (3 fixtures) instead of ≥3+≥2.
- **scope-cutter** Iterate cadence could be one rerun at end of P2, not per-wave.
- **ARCH-7** `test/real-cve-fixtures/` near-duplicates existing `test/cve-targeted-flow-fixtures/`. Either extend that root with a `runner-mode: customer-app` flag OR rename new root to `test/customer-app-fixtures/`.
- **ARCH-8** Migration phase28d_weak_default needs explicit pointer for `taint_engine_settings.vuln_classes_enabled` DEFAULT extension.
- **TS-7** Per-commit gate composition (18-stage preflight + 8 jest + cve-targeted + real-cve) has no wall-clock budget. Specify ≤90s local, ≤3min CI; if exceeded, split into fast/full gates.
- **TS-8** Fixture matrix counts (≥3/≥2) have no coverage rationale. Each primitive's directory should list variants covered (declaration vs assignment vs destructured, etc.).

## P3 — Nits & Opportunities

- **scope-cutter** Confirm phase28d migration is bundled with detector PR.
- **scope-cutter** DropReason enum + TaintTrace dump is debug infra; retro after Phase 2.
- **pragmatist** 2d 60-120 LOC is highest-LOC-per-win in P2; name as contingency cut.
- **pragmatist** 4.1a "~3 YAMLs" is suspiciously round before 4.0 runs.
- **ARCH-9** Few-shots picker (`selectFrameworkSpecFewShots`) is ecosystem-keyed; new shape-teaching few-shots either get tagged or ride along.
- **ARCH-10** Weekly CI cron needs provider+model+key env. Call out cost in budget.
- **TS-9** 3-trial averaging tests should also cover thrown-trial counted as fail, --trials=N where N<3 errors, ordering determinism.
- **TS-10** DropReason exhaustiveness jest test (walk source for `dropReason:` literals).
- **opportunity-scout** OPP-1 baseline.json schema + dated history; OPP-2 stddev-aware drift gate; OPP-3 reclassification artifact as JSON; OPP-4 DropReason histogram in cron; OPP-5 fixtures in `reachability-rules/<primitive>/`; OPP-6 prompt-eval per-SHA results.

## Suggested Plan Amendments (consolidated, ordered)

Apply these 9 patches before `/implement`. Each is one paragraph in the plan.

1. **Phase 1.2:** Replace "reuse TaintTrace serialiser" with "ADD `serializeTrace(trace)` in flow.ts + `DropReason` union + `serializeDiagnosticRecord` in propagate-core.ts. LOC ~30-50." Path becomes `bench-iterate/<variant>/<timestamp>/diag/<cve>.ndjson`.
2. **Phase 1.3:** Split into 1.3a (author 5 fixtures, 1 per eco, vendored multi-file ≥3 files each, no network, ≤30s test runtime; measure baseline on tip 413ef48) and 1.3b (threshold = baseline + 10pp, NOT fixed 70%).
3. **Phase 1.1:** Note that `--trials=3` requires OUTER loop restructure in runner.ts + seed plumbing through generate.ts (~200 LOC, not a flag flip).
4. **Phase 3.0 (NEW):** FrameworkSpec schema-mirror prerequisite. Extend `spec.ts`, `spec-loader.ts`, `framework-spec-schema.ts` (selectively relax `.strict()` or extend zod), `prompt-builder.ts`, and add optional-default-empty-array migration to all 23 bundled YAMLs. Must land before 3.2/3.3 detector files.
5. **Phase 3.2/3.3:** Pin detector precision gate: "≥90% on malicious-v2 known-clean snapshot at commit `<SHA>`, N≥500 files. Commit `test/detectors/<d>/fp-corpus.manifest.json`." Distinguish ≥10 hand-authored neg fixtures (shape correctness) from the precision gate.
6. **Phase 4.0:** Either fold into 4.1a (pragmatist + scope-cutter consensus) OR explicitly scope "build shape-trace mode in validate.ts" with LOC budget. Recommended: fold.
7. **Phase 4.3:** Either drop in favor of per-eco sub-aggregate of 88-CVE iterate (pragmatist + scope-cutter) OR add noise-floor pre-measurement (TS-5). Recommended: drop 4.3 as standalone; replace with per-eco sub-aggregate.
8. **Phase 5.3:** Specify `diff-baseline.ts` automation + jest test for threshold math; or downgrade gate to weekly manual-trigger cron (pragmatist scope-cut).
9. **Cumulative projection:** Either widen to 65-78% range OR lower success criterion to ≥70% with stretch ≥74%. Plan's own arithmetic must not miss the gate.

## Findings by Axis

| Axis | Count | Highest | Personas |
|---|---|---|---|
| infrastructure-doesn't-exist | 2 | P0 | architect |
| schema-mirror | 1 | P0 | architect |
| threshold-spec | 2 | P0 | test-strategy |
| projection-credibility | 4 | P1 | skeptic |
| scope/ceremony | 6 | P1 | pragmatist, scope-cutter |
| test-coverage | 6 | P1 | test-strategy |
| opportunity | 6 | P3 | opportunity-scout |

## Recommended Next Step

**REWORK (surgical).** The 5 P0s are fact-checks / threshold specifications, not structural rewrites. Apply the 9 patches (~1-2 hours of editing) and proceed straight to `/implement` — skip a third review. Alternatively, since pragmatist + scope-cutter + opportunity-scout all approve, you can elect to accept the P0s as known unknowns and start implementing Phase 1 (the cheapest, most-replaceable phase) — the act of building 1.0 + 1.2 + 1.3a will resolve ARCH-1, ARCH-2, ARCH-4, TS-1, TS-2 organically. The REWORK verdict is conservative; the practical path forward is to patch the plan or just start.
