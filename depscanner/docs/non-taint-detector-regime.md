# Non-Taint Detector Regime — Phase F4 Design

> **Historical path note (2026-06):** this design doc predates the move to the
> framework-models taint engine. The per-CVE **rule-pack generator** it
> references — `reachability-rules/CVE-YYYY-NNNNN-slug/rule.yml` + `fixtures/`
> — has been **retired** and that directory no longer exists. Framework specs
> now live in `src/taint-engine/framework-models/*.yaml` (one spec per
> framework, not per CVE), and per-CVE regression fixtures live in
> `test/cve-targeted-flow-fixtures/<lang>-*/` (run by the `cve-targeted` stage
> of `npm run test:taint-engine-all`). The `reachability-rules/CVE-*/...`
> snippets below are kept only to illustrate the original generator shape; read
> them as historical, not as on-disk paths. The prototype detector
> (`src/taint-engine/non-taint-detector.ts`) and `framework-models/` do still
> exist.

Companion to `docs/path-to-90-percent-recall.md`. Phase F4 in that writeup
identifies ~8 CVEs in the 88-CVE corpus that the cross-file taint engine
cannot validate even with perfect spec coverage and engine polish, because
the vulnerability shape is not "attacker data reaches a dangerous sink".
This document specifies a complementary detector pass — the "non-taint
regime" — that fires on a different set of signals:

1. **Sanitizer-absence**: a known-dangerous callsite is missing a hardening
   argument (e.g. `jwt.verify(token, key)` without an `algorithms`
   allowlist; `requests.Session(verify=False)`).
2. **Version-comparison + module-reachability**: a vulnerable function is
   called by the project, and the installed package version sits inside an
   advisory's affected range, without requiring a source-to-sink data
   flow.

A small prototype of (1) ships in this same commit as
`src/taint-engine/non-taint-detector.ts` with one unit test. (2) is
sketched here but not implemented — it needs a manifest reader + a semver
helper that the prototype lane does not own.

---

## Corpus scope

From the F4-non-taint triage set, the 8 entries with
`bucket: "F4_non_taint"` plus 2 borderline E3-overlap entries that depend
on sanitizer-absence shape, mapped to sub-regime:

| CVE | Package | Sub-regime | Notes |
|-----|---------|-----------|-------|
| CVE-2024-35195 | requests (pypi) | sanitizer-absence (forbidden literal) | `Session(verify=False)` |
| CVE-2022-23539 | jsonwebtoken (npm) | sanitizer-absence (required kwarg) | `jwt.verify` missing `algorithms` |
| CVE-2024-28849 | follow-redirects (npm) | sanitizer-absence (forbidden config) | `Authorization` header on cross-origin redirect (libraryinternal — best-effort caller signal) |
| CVE-2023-30861 | flask (pypi) | sanitizer-absence (config) | Session-cookie `Vary` header alignment |
| CVE-2017-16137 | debug (npm) | regex-shape / parser-internal | %o formatter ReDoS — caller-side detectable by version-range only |
| CVE-2026-40175 | axios (npm) | version-comparison | Prototype-pollution-as-header-injection; only triggers if attacker has mutated `Object.prototype` already |
| CVE-2022-21698 | prometheus client_golang | sanitizer-absence (cardinality) | `WithLabelValues(*)` with attacker-controlled label-value count |
| CVE-2022-29153 | hashicorp consul | version-comparison | Library-internal redirect-following bug |
| CVE-2024-21484 | jsrsasign (npm) | sanitizer-absence (weak crypto) | Padding-oracle in `RSAKey.decrypt`; could also be modelled as a taint sink |
| CVE-2023-49083 | cryptography (pypi) | version-comparison | C-extension NULL deref in `pkcs7.load_*` |

**Sub-regime breakdown:**
- Sanitizer-absence: **6 CVEs** (requests, jsonwebtoken, follow-redirects, flask, prometheus, jsrsasign)
- Version-comparison + module-reachability: **3 CVEs** (axios proto-pollution, consul, cryptography)
- Regex-shape / parser-internal (covered by version-comparison since the
  fix is parser-internal): **1 CVE** (debug)

Realistic ceiling if both sub-regimes ship: **+8 CVE (+9.1pp)** on the
88-CVE corpus.

The /60–80% range claim in `path-to-90-percent-recall.md` covers this
ceiling as the "F4 stretch" row.

---

## Sub-regime 1: sanitizer-absence

### Detection model

For each `FrameworkSink` augmented with a `required_arguments` field, walk
every call site whose callee text matches the sink pattern. For each
`RequiredArgument` entry, decide whether the call hardened itself:

- `match_mode: 'required'` — fire if the named argument is **absent**
  (neither as kwarg nor at the declared positional slot). Models
  CVE-2022-23539 (`algorithms` option missing from `jwt.verify`).
- `match_mode: 'forbidden'` — fire if the argument is **present and
  matches one of `unsafe_literals`**. Models CVE-2024-35195
  (`verify=False` on `requests.Session(*)`).
- `match_mode: 'must_equal'` — fire if the argument is present but its
  literal is NOT in `safe_literals`. Useful for "must pass one of these
  algorithm names" style hardening assertions.

Engine confidence baseline: **0.85**. Higher than typical taint flow
(0.5–0.7 for long paths) because the absence-check is purely syntactic —
no inter-procedural reasoning, very little false-positive risk. Below 1.0
because the matcher is text-only and can be fooled by spread args
(`...config`), dynamic kwarg construction (`**kwargs`), and wrapper
helpers.

### Schema extension

Add an optional `required_arguments` array to `FrameworkSink` in `spec.ts`.
Proposed diff (NOT applied in the prototype commit):

```ts
// depscanner/src/taint-engine/spec.ts

export interface FrameworkSink {
  pattern: string;
  vuln_class: VulnClass;
  argument_indices: number[];
  description: string;
  osv_id?: string;

  /**
   * Phase F4 (non-taint regime). When present, the non-taint detector
   * walks call sites matching `pattern` and asserts each requirement.
   * Empty / undefined means this sink participates only in the taint
   * pipeline (current behaviour).
   */
  required_arguments?: RequiredArgument[];
}

export interface RequiredArgument {
  name: string;
  position?: number;
  match_mode?: 'required' | 'forbidden' | 'must_equal';
  safe_literals?: string[];
  unsafe_literals?: string[];
}
```

`argument_indices` stays `number[]` — a sink can declare both a taint
contract AND a non-taint contract on the same pattern; the propagator
keys off `argument_indices.length > 0` and the non-taint detector keys
off `required_arguments?.length > 0`. In practice most F4 sinks set
`argument_indices: []` because their relevance is sanitizer-absence
only.

YAML authoring shape:

```yaml
framework: jsonwebtoken
version: "*"
language: js
sources: []
sinks:
  - pattern: jwt.verify(*)
    vuln_class: auth_bypass
    argument_indices: []
    description: "jwt.verify without an explicit algorithms allowlist"
    required_arguments:
      - name: algorithms
        position: 2
        match_mode: required
```

### Integration with the taint engine

A separate detector pass, NOT an extension of `propagator.ts`:

```
runner.ts
  ├── buildCallgraph  → Callgraph
  ├── lower IR        → IrFunction[]
  ├── propagator.run  → Flow[]         (taint regime, unchanged)
  └── runNonTaintDetectors(specs, irFunctions)  → NonTaintFinding[]
                       ─ extracts CallSite[] from IrFunction[].steps
                       ─ calls detectSanitizerAbsence(spec, callsites)
                       ─ stamps osv_id from sink for CVE-targeted specs
```

Why separate pass:

1. **No state interaction**. The propagator threads taint state through
   call edges; non-taint detection only needs per-callsite inspection.
   Bundling them risks cross-contamination (a sink that participates in
   both regimes shouldn't double-count).
2. **Different output channel**. The taint pipeline emits `Flow[]`
   destined for `project_reachable_flows`. Non-taint findings need their
   own destination (see "Schema-mirror updates" below) because the path
   trail concept doesn't apply.
3. **Different confidence semantics**. A sanitizer-absence finding is a
   direct AST observation; gluing it onto `Flow.engine_confidence`'s
   path-length-derived score muddies both.

The CallSite extractor reuses `Step` (`kind === 'call'`): every IR call
becomes a CallSite. Kwargs are already partially modelled via
`Step.kwargIndices` for Python; the prototype `CallSite.kwargNames` /
`kwargValues` is the extension surface for non-taint reasoning.

Reachability-tier interaction: a non-taint finding maps to
`reachability_level: module` (call is in the project AST) or `function`
(call is in a reachable function from the callgraph entry-point set).
`data_flow` / `confirmed` tiers are taint-specific and remain
unattainable for the non-taint regime — which is fine; sanitizer-absence
findings should be precise enough to land directly at `function` tier.

### Migration story

No DB migration in the prototype commit. Production rollout would add:

1. **No `vuln_class` enum extension required for the v1 corpus.** The
   six in-scope CVEs map onto existing classes:
   - `auth_bypass` (requests, jsonwebtoken, follow-redirects, jsrsasign,
     flask cookie-header)
   - `redos` / `dos` (debug — borderline; debug is parser-internal so
     it falls under version-comparison anyway)
   - Prometheus cardinality is a `dos` shape; the existing taxonomy
     accommodates it without enum work.

2. **New `reachability_source` value**: the existing taint engine writes
   `reachability_source = 'taint_engine'` to `project_reachable_flows`.
   Non-taint findings should write `reachability_source =
   'non_taint_detector'` to the same table so the classifier's
   confirmed-tier OR-clause can promote them when an osv_id is present.
   This is a code change, not a schema migration.

3. **Optional**: extend `project_reachable_flows` with a `finding_kind`
   column (`'taint_flow' | 'sanitizer_absence' | 'version_match'`) to
   keep the funnel telemetry distinguishable. Defer until v2.

### Test-fixture shape

For the rule-generator validation harness (`validate.ts`), a non-taint
fixture pair is similar to the existing taint pair but the matcher gate
asserts a finding from the non-taint detector instead of a flow:

```
fixtures/CVE-2022-23539/
  vuln/handler.js     // jwt.verify(token, key)  — no algorithms
  safe/handler.js     // jwt.verify(token, key, { algorithms: ['HS256'] })
```

Gate-2 (fixture round-trip) asserts:

1. Vuln fixture: `detectSanitizerAbsence` returns ≥ 1 finding with the
   sink's `osv_id`.
2. Safe fixture: 0 findings.
3. (As today) post-patch fixture: 0 findings — same harness, same gate
   logic.

The version-comparison sub-regime additionally needs a `package.json` /
`requirements.txt` in the fixture (see below).

---

## Sub-regime 2: version-comparison + module-reachability

### Detection model

For each `FrameworkSink` augmented with `affected_versions` (semver-range
form), the detector checks two conditions:

1. **Module reachability**: at least one call site in the project AST
   matches the sink's `pattern` (or the package is imported at all, for
   import-as-reachability sinks).
2. **Version-in-range**: the installed version of the sink's package
   (read from the project SBOM passed in by the orchestrator) sits inside
   `affected_versions`.

When both hold, emit a finding at `reachability_level: module`. Confidence
0.6 (lower than sanitizer-absence because the false-positive rate is
higher — most version-only matches are useful only as a low-priority
signal alongside the package-version-only path that dep-scan already
provides).

### Why this is worth doing despite dep-scan overlap

dep-scan already flags every vulnerable package by version. The
version-comparison sub-regime adds:

- **Module-reachability gate**: filter out the long tail of vulnerable
  packages that are imported transitively but never called. Today these
  inflate the finding count without representing real exposure.
- **CVE-targeted callsite anchors**: link the finding to a *specific*
  call site in the user's code, so the UI can deep-link to the relevant
  line. Today dep-scan can only point at the `package.json` entry.

### Schema extension (sketch only)

```ts
export interface FrameworkSink {
  // ...existing fields...
  required_arguments?: RequiredArgument[];   // sanitizer-absence
  affected_versions?: string;                // semver range, e.g. "<1.7.4 || >=2.0.0 <2.0.6"
  package_name?: string;                      // npm / pypi name to match SBOM against
  ecosystem?: 'npm' | 'pypi' | 'maven' | 'golang' | 'gem';
}
```

### Why version-comparison is NOT in the prototype

- Needs a package-manifest reader (SBOM lookup) plumbed into the detector
  entrypoint. The taint engine today is stateless w.r.t. the SBOM —
  threading it in is a non-trivial wire-up.
- Needs `semver` for npm-style ranges, plus equivalents for PyPI's PEP
  440 and Maven's range grammar. Each ecosystem's range syntax differs;
  doing this rigorously means depending on a different parser per
  ecosystem.
- Useful smoke test is harder to write — fixtures need synthetic
  `package.json` files with specific versions, and Jest's mock-fs setup
  in `depscanner/src/__tests__/` is not currently configured for that.

Defer until v2 of the F4 regime. The sanitizer-absence sub-regime alone
unlocks 6 CVEs (the higher-leverage half) with a quarter the
implementation surface.

---

## Test-fixture shape (sanitizer-absence)

Reusing the existing `vuln/` + `safe/` pattern from the AI rule
generator (`reachability-rules/CVE-YYYY-NNNNN-slug/fixtures/`):

```
reachability-rules/CVE-2022-23539-jsonwebtoken-algorithms/
  rule.yml                     # framework_spec embedded inline
  fixtures/
    vuln/index.js             # const jwt = require('jsonwebtoken');
                              # jwt.verify(req.body.token, key);   // no algorithms
    safe/index.js             # jwt.verify(req.body.token, key, { algorithms: ['HS256'] });
```

`rule.yml` payload:

```yaml
framework: jsonwebtoken
version: "*"
language: js
sources: []   # explicit — non-taint regime has no source side
sinks:
  - pattern: jwt.verify(*)
    vuln_class: auth_bypass
    argument_indices: []
    description: "jwt.verify without an explicit algorithms allowlist"
    osv_id: CVE-2022-23539
    required_arguments:
      - name: algorithms
        position: 2
        match_mode: required
sanitizers: []
```

For version-comparison fixtures, the `vuln/` subtree gains a
`package.json` pinning the vulnerable version; `safe/` pins the fixed
version:

```
reachability-rules/CVE-2026-40175-axios-proto/
  rule.yml                     # affected_versions: ">=0.20.0 <1.7.0"
  fixtures/
    vuln/package.json         # { "dependencies": { "axios": "1.6.0" } }
    vuln/index.js             # axios.get('http://...')
    safe/package.json         # { "dependencies": { "axios": "1.7.4" } }
    safe/index.js             # axios.get('http://...')   — same code, different version
```

---

## Estimated effort

| Track | Effort | CVE lift |
|-------|--------|----------|
| **Prototype (this commit)** — stand-alone detector + unit test | 0.5 day | 0 |
| **Schema extension + spec-loader passthrough** | 0.5 day | 0 |
| **CallSite extractor + runner integration** | 1 day | 0 (substrate) |
| **validate.ts Gate-2 + Gate-3 integration** | 1 day | 0 (substrate) |
| **6 F4 framework_model authoring** (sanitizer-absence shapes) | 1 day | +6 CVE (+6.8pp) |
| **Total sanitizer-absence track** | ~4 days | **+6 CVE** |
| Version-comparison + SBOM threading + per-ecosystem range parsing | +3 days | +3 CVE (+3.4pp) |
| **Total F4 ceiling** | ~7 days | **+9 CVE / +10.2pp** |

These are conservative; if every authored model lands on the first try
and Gate-2 passes cleanly, the actual lift could be the full 8-CVE
F4-bucket from triage. The above assumes 1 follow-up cycle per spec.

---

## Cross-references

- Prototype: `src/taint-engine/non-taint-detector.ts`
- Prototype test: `src/__tests__/non-taint-detector.test.ts`
- Recall ceiling discussion: `docs/path-to-90-percent-recall.md`
- Existing sink shape: `src/taint-engine/spec.ts` → `FrameworkSink`
- Existing flow output shape: `src/taint-engine/flow.ts` → `Flow`
