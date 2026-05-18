# Source/Sink-Mismatch Failure Analysis — 88-CVE benchmark, 2026-05-10

Source: `depscanner/test/iterate/runs/2026-05-10-marathon/v_base/2026-05-11T01-44-33/report.json`

## Bucket definition

`source_sink_mismatch` = a CVE where:
- `schema_pass: true` (FrameworkSpec is well-formed)
- `pattern_compile_pass: true` (sink regex compiles)
- `fixture_pre_match: false` (vulnerable_fixture produces zero flows)
- final status = `failed_validation`

That bucket has **53 of 59 failures** in v_base — far larger than the brief's 29 estimate. The 29 figure in the brief was a stratified subsample target. For tournament cost reasons we sample a 29-CVE stratified slice that mirrors the ecosystem breakdown (see `mismatch-corpus.ts`):

| Ecosystem | Mismatch pool | Tournament sample |
|-----------|--------------:|------------------:|
| npm       |   12 |  7 |
| pypi      |   17 |  9 |
| maven     |   13 |  7 |
| golang    |    6 |  3 |
| rubygems  |    5 |  3 |
| **Total** | **53** | **29** |

## Failure-mode breakdown (from reading 15 representative cases)

### F1 — Vuln-class is NOT taint-modelable (~30% of bucket)
Examples: CVE-2018-18074 (credential leak on redirect), CVE-2023-32681 (proxy auth leak), CVE-2022-32149 (ReDoS), CVE-2024-28180 (decompression bomb), CVE-2024-32465 (env-var handling), CVE-2022-23633 (Rails executor state).

These are protocol-state / config-default / DoS bugs. There is no `tainted_input → dangerous_sink` data flow to model. The model picks a function name as "sink" but the fixture doesn't carry tainted data into it — because the bug isn't a taint flow.

**Implication:** Prompt should explicitly help the model recognise these and either (a) emit `vuln_class_out_of_scope` self-classification or (b) write a fixture that DOES make the call shape match (e.g. config flag = tainted, redirect URL = tainted body).

### F2 — Vulnerable_fixture uses non-HTTP source (~30% of bucket)
Examples: CVE-2017-7525 (`args[0]`), CVE-2022-42889 (static `payload` literal), CVE-2017-16137 (`'A'.repeat(50000)` literal), CVE-2024-21484 (calls Express handler but bypasses it), CVE-2024-28180 (function parameter `data []byte`).

The vulnerable_fixture writes a CLI-style or static fixture where the "tainted" value is a string literal or function argument. Framework specs (Express, Flask, Spring) contribute sources for `req.body`, `request.args`, `@PathVariable` — they don't model `process.argv` or `args[]` or function parameters.

**Implication:** Prompt should mandate that vulnerable_fixture's tainted value MUST originate from an HTTP source matching the package's ecosystem (Express handler for npm, Flask route for pypi, Spring controller for Maven, net/http for Go, Rails action for gem).

### F3 — Sink pattern too narrow / wrong receiver shape (~20% of bucket)
Examples: CVE-2022-25883 (`new Range(range)` — constructor call, sink probably matches `Range(*)` only), CVE-2024-26130 (`encryption_builder().hmac_hash(...)` — fluent chain, sink probably matches one node), CVE-2022-22965 (`spring-beans` data-binder — sink in BeanWrapper internals, model wrote a controller fixture).

The sink pattern compiles but doesn't match the AST node shape produced by the fixture. Specifically: model writes `new Foo()` but sink is `Foo(*)`; model writes `a.b().c().d()` but sink is `a.d(*)`.

**Implication:** Prompt should call out the THREE callee shapes (exact-name, receiver-wildcard, method-on-class) more explicitly and warn against constructor / fluent-chain mismatch.

### F4 — Wrong sink entirely (~10% of bucket)
Examples: CVE-2024-22195 (Jinja2 xmlattr — model picks `Template` constructor, real sink is `xmlattr` filter), CVE-2021-44832 (log4j JDBC — model picks `setDataSourceName`, real exploit goes through `JndiManager.lookup`), CVE-2017-16137 (debug %o — real sink is `util.inspect`, model writes the wrong call).

Model latches onto the most visible API in the patch summary, not the actual exploit entry point. Reading the diff more carefully would reveal the deeper sink.

**Implication:** Add a chain-of-thought step: "Before emitting, list 2-3 candidate sinks from the diff and pick the one with a clear taint path."

### F5 — Configuration / no flow at all (~10% of bucket)
Examples: CVE-2024-6345 (setuptools — `python -c` exec from cli), CVE-2024-21626 (runc — `pivot_root` fd leak), CVE-2022-29153 (consul — SSRF in service router, no Go HTTP handler).

Same root cause as F1 but specifically tools / CLI / infrastructure code — the model invents a fixture that has no source.

## Cross-cutting patterns

- **Java fixtures default to `public static void main(args)` with `args[0]` as source.** No framework spec contributes a source for `args[0]`. This kills 6/7 Maven cases.
- **Go fixtures often skip net/http and pass a function parameter as "source".** This kills 3/6 Go cases.
- **Ruby fixtures default to Rails internals (ActionController, ActionDispatch).** The Ruby framework spec contributes Rails request sources (`params`, `request.*`) but the model writes the fixture around the bug's internal call chain instead.
- **`new ClassName(taint)` constructor calls** — model writes `new Range(req.body.x)` and the sink is `Range(*)`; pattern doesn't match `new` AST node. Fix in engine PHP-new path landed for `new ClassName($arg)` (PHP) but JS `new` may still be a gap.

## Tournament hypothesis priorities

These directly map to the variants:

| Hypothesis | Variant |
|-----------|---------|
| Broaden the "where do sources come from" hint | A — source-shape expansion |
| Force HTTP-handler vulnerable_fixture | B — few-shot showing the right shape |
| Chain-of-thought: list candidates, pick best | C — CoT scaffolding |
| Warn about the specific F1–F5 anti-patterns | D — failure-mode warnings |
| Test if the current prompt is over-stuffed | E — minimal stripped-down |

## Notes

- Generated `rule_yaml` is NOT captured in the per-CVE record — the harness only persists `vulnerableFixture`, `safeFixture`, and the `validation_breakdown` booleans. This analysis is grounded in the fixtures and the package-name diff context only. The tournament runner will capture full payloads.
- Per `ai_rule_generation_ceiling.md` memory: one-shot rule-gen ceiling is ~15-20% absolute lift. A successful variant should move the 29-CVE subset from 0% (all in the mismatch bucket by construction) to 15-30% pass without regressing the 33% global baseline.
