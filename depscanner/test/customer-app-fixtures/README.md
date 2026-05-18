# Customer-app multi-file fixtures (Phase 1.3a)

Real-customer-shaped multi-file projects that exercise the cross-file taint
engine end-to-end. Each fixture is a self-contained mini-project (≥3 files
per side) with:

  - `vuln/` — a multi-file project where user-controlled input flows from
    an HTTP source in one file, through ≥1 intermediate file, into a
    framework- or stdlib-registered sink in another. The runner asserts the
    engine emits ≥1 `Flow` whose `vuln_class` matches `meta.expected_vuln_class`.
  - `safe/` — a near-identical project where the same shape has been
    patched (sanitizer applied, safe API used, or the user-input → sink
    edge removed). The runner asserts the engine emits 0 flows of that
    `vuln_class`.

Both sides are evaluated against the **bundled** `framework_models/*.yaml`
spec set — the same specs the production pipeline loads in
`src/taint-engine/runner.ts`. An optional per-fixture `spec.json` is loaded
on top of the bundled set when a CVE-specific sink isn't in the bundle yet.

## Difference from `test/cve-targeted-flow-fixtures/`

| Aspect | `cve-targeted-flow-fixtures/` | `customer-app-fixtures/` (this dir) |
|---|---|---|
| Spec source | Per-fixture `spec.json` STANDALONE | Bundled `framework-models/*.yaml` ± optional `spec.json` |
| Files | Single-shape, often single-file | ≥3 files per side, multi-package layout |
| Sides | One project per fixture | `vuln/` AND `safe/` per fixture |
| Asserts | ≥1 flow with matching `osv_id + vuln_class` | vuln/: ≥N flows of `vuln_class`; safe/: ≤M flows |
| Purpose | Engine round-trip: does the CVE-tagged sink stamp `osv_id` onto the Flow? | End-to-end: does the production spec set find a real-customer-shaped CVE AND clear a patched version? |

The two suites are complementary. cve-targeted proves the engine wires
`osv_id` correctly so the classifier can promote PDVs to `confirmed`.
customer-app proves the bundled spec set actually detects a customer-shaped
CVE on a real-world multi-file layout, AND that it doesn't false-positive
on the patched version of the same project.

## Layout

```
<eco>-<framework>-<vuln-shape>/
  meta.json
  spec.json            (optional; only when a CVE-specific sink isn't in bundled)
  vuln/
    <entry file>       (HTTP handler — source-bearing)
    <intermediate>     (service / repo layer)
    <sink-importing>   (the file that calls the sink)
    ...
  safe/
    <entry file>       (HTTP handler, with patched flow)
    <intermediate>
    <sink-importing>
    ...
```

### `meta.json` schema

```jsonc
{
  "language": "js" | "python" | "java" | "go" | "ruby" | "php" | "rust" | "csharp",
  "framework": "express",          // human label only
  "expected_osv_id": "CVE-...",    // documentary; runner doesn't assert
  "expected_vuln_class": "code_injection",
  "expected_vuln_flows_min": 1,    // vuln/ must produce ≥ this many
  "expected_safe_flows_max": 0,    // safe/ must produce ≤ this many
  "package": "lodash",
  "description": "..."
}
```

### `spec.json` (optional)

Same shape as `cve-targeted-flow-fixtures/<...>/spec.json`. Loaded via
`loadSpecFromJson` and concatenated onto the bundled spec list. Use this
only when the CVE-specific sink isn't in `framework-models/*.yaml` yet —
prefer extending the bundled spec.

## Adding a new fixture

1. Create `<eco>-<framework>-<vuln-shape>/` under this directory.
2. Author `meta.json` (see schema above).
3. Build `vuln/` (≥3 files): HTTP entry → ≥1 intermediate → sink-importing
   module. The cross-file taint edge must live in the engine's graph (the
   source must enter in file A and the sink must execute in file B/C).
4. Build `safe/` (≥3 files): patch the same shape so 0 flows of the target
   `vuln_class` survive. Common patches:
   - Replace user-input sink argument with a fixed literal.
   - Pass user input through a sanitizer registered for this `vuln_class`
     in `framework-models/*.yaml` (e.g. `html.escape`, `Integer.parseInt`,
     `strconv.Atoi`, `CGI.escapeHTML`, `secure_filename`).
   - Switch to a non-sink API entirely.
5. Run `npm run test:customer-app` from `depscanner/`. The runner writes
   `baseline-<gitsha>.json` with per-fixture pass/fail + flow counts.

## Test cadence

The runner is wired into `taint-engine-preflight.ts` as stage
`customer-app` (between `cve-targeted` and `recall`) so it runs on every
pre-merge preflight via `npm run test:taint-engine-all`. Wall-clock budget
on a fresh checkout: ≤30s for all 5 starter fixtures combined.

Per the reachability-90-percent plan (Phase 1.3a in
`.cursor/plans/reachability-toward-100-roadmap.md`), this suite gates the
"the engine actually finds customer-shaped CVEs" assertion separately from
the synthetic single-shape fixtures the existing test surface covers.

## Known limitations

- Sinatra DSL (`get '/foo' do ... end`) blocks aren't lowered by the Ruby
  substrate; the gem fixture uses class-based controllers
  (`class App < Sinatra::Base`) instead — same source/sink shape, just
  not the route-DSL.
- `*.render(*)` is a bundled Jinja2 XSS sink and Java `*.readValue(*)` is
  a bundled deser sink, so the safe side has to avoid passing user input
  through those calls altogether (or use a registered sanitizer first).
- Fixtures vendor `require`-style imports but do NOT vendor the actual
  npm/pip/gem/go modules — the engine treats unresolved imports as
  external, which is the intended production behavior.

## Baseline files

`baseline-<gitsha>.json` snapshots the per-fixture pass/fail + flow counts
the runner saw at that revision. New baselines are written every run; old
ones are kept under git to track regressions.
