# Path to 90% Recall — 88-CVE Iterate Corpus

Re-triage of the 38 non-validated CVEs in the latest `v_base` iterate run
(`depscanner/bench-iterate/v_base/2026-05-12T17-41-24/report.json`,
50/88 = 56.8%). Companion data: `.cursor/plans/triage-2026-05-12-post-abcd.json`.

This writeup classifies each non-validated CVE after assuming sibling Phase E
agents land (E1: vuln_class normalization, E2: engine method-chain +
computed-key, E3: weak_crypto / auth_bypass enum extension, E4: maven
commons-text + xmlsec framework_models). It then enumerates the Phase F
sub-phases needed to push recall further.

---

## State snapshot (after ABCD merge, before E1–E4)

- 50/88 validated = **56.8%** baseline.
- 38 non-validated: 30 `failed_validation` + 8 `vuln_class_out_of_scope`.
- Per-ecosystem non-validated count:

  | Ecosystem | Non-validated | Validated (out of corpus share) |
  |-----------|---------------|---------------------------------|
  | npm       | 9             | strong, ~14/23 working           |
  | pypi      | 11            | mid                              |
  | maven     | 6             | mid, anchored on jackson/log4j   |
  | golang    | 8             | weakest, almost no F1 yet        |
  | gem       | 4             | weakest density                  |

- Funnel weak point: `fixture_pre: 51/88`. The Gate-2 fixture round-trip is
  the dominant failure mode. Patch round-trip and schema gates are healthy.

---

## Expected impact of sibling Phase E agents (already in flight)

| Phase | CVEs unlocked (per re-triage)                                 | Δpp |
|-------|--------------------------------------------------------------|----|
| E1 vuln_class normalization | CVE-2019-10906 (jinja2 sandbox_escape), CVE-2020-28493 (jinja2 urlize redos) | +2.3 |
| E2 method-chain + computed-key | CVE-2026-4800 (lodash _.template imports key)               | +1.1 |
| E3 weak_crypto / auth_bypass enum | CVE-2022-23539 (jsonwebtoken alg confusion), CVE-2022-22978 (spring-security regex bypass) | +2.3 |
| E4 maven commons-text + xmlsec | CVE-2023-44483 (xmlsec)                                     | +1.1 |
| **E-total**                       | **6 CVEs**                                                  | **+6.8 pp → 64% recall** |

Note these are upper bounds; some E-flips also need a Phase F follow-up to
land the corresponding bundled spec (E3 → F1 jsonwebtoken / spring-security
specs).

---

## Phase F sub-phases

### F1 — Framework_model coverage gap (13 CVEs)

Add one bundled `.yaml` spec per missing library. Each CVE is unlocked by a
1-file add of 5-15 sinks. Top 5 by leverage:

1. **`spring-beans.yaml`** — `*.setPropertyValue*(*)`, `BeanWrapperImpl(*)`
   sinks (code_injection). Unlocks CVE-2022-22965 Spring4Shell.
2. **`spring-security.yaml`** — `new RegexRequestMatcher(*)`,
   `*.regexMatchers(*)` sinks (auth_bypass; needs E3). Unlocks
   CVE-2022-22978.
3. **`apache-poi.yaml`** — `new HWPFDocument(*)`, `WorkbookFactory.create(*)`
   sinks (dos; needs E3). Unlocks CVE-2017-12626 plus likely more
   document-parser CVEs not in corpus.
4. **`log4j.yaml` extension** — add log4j-1.x `SocketAppender` / `startServer`
   deserialization sinks. Unlocks CVE-2023-26464.
5. **`semver.yaml`** — `new semver.Range(*)`, `semver.validRange(*)`,
   `semver.satisfies(*, *)` redos sinks. Unlocks CVE-2022-25883. Trivial.

Other F1 adds (CVE → spec): CVE-2026-25639 (`axios.yaml`
`axios.mergeConfig`), CVE-2024-6345 (`setuptools.yaml` `PackageIndex.download`),
CVE-2022-32149 (`x-text.yaml` `ParseAcceptLanguage`), CVE-2023-3978
(`x-net-html.yaml` `html.Parse`), CVE-2024-45337 (`x-crypto-ssh.yaml`
`PublicKeyCallback`), CVE-2022-23633 (`actionpack.yaml` `Executor.wrap`),
CVE-2024-32465 (`ruby-git.yaml` `Git.open`/`Git.clone`), CVE-2022-23837
(`rack.yaml` multipart parser).

**F1 estimated lift: +13 pp → 77.8% cumulative with E.** Each spec adds 1-2
pp. Diminishing returns kick in as the long tail thins out, but the next 13
CVEs are genuinely a "one spec each" workload.

### F2 — Source coverage gap (0 CVEs, deferred)

No CVE in the corpus is currently blocked solely on a missing source pattern.
Bundled framework_models cover the dominant http source surfaces
(express/flask/fastify/spring/gin/rails) and stdlib file/env sources are
present. F2 would matter if we added CLI / argv / websocket / message-queue
source patterns, but no CVE in this corpus requires that — every fixture
either has an http source already covered or has a synthesised source the
fixture author baked in (which is the right shape for engine taint anyway).

**F2 deferred. Revisit if a future corpus pulls in CLI tools or worker-queue
libraries.**

### F3 — Engine feature gaps (5 CVEs)

Each row is a discrete engine capability the propagator currently lacks.

| Feature | CVEs unlocked | Δpp |
|---------|---------------|----|
| **Keyword-arg-aware sink matching** (today engine matches positional `f(*)` only; AI rules and many sinks specify `f(method=*)`) | CVE-2020-26137 (urllib3 putrequest), CVE-2024-34064 (jinja2 xmlattr) | +2.3 |
| **Patch-round-trip file-glob exclude** (post-patch counts include `test/`, `tests/` paths the upstream patch didn't touch) | CVE-2025-62718 (axios 11 test-file matches), CVE-2017-16137 (debug), CVE-2022-22817 (pillow) | +3.4 |
| **Computed-key / dynamic-property-write taint** (`obj[req.query.k] = v` should taint `obj` when key is attacker-controlled) | CVE-2026-4800 (E2 overlap) | (counted in E2) |
| **Struct-field-init sink (go)** (`&ssh.ServerConfig{PublicKeyCallback: f}` is a sink, not a call) | CVE-2024-45337 | +1.1 |
| **Ruby bracket-vs-dot accessor parity** (`params[:x]` vs `params.x` both yield http_input) | CVE-2023-28120 | +1.1 |

Top 3 highest-leverage engine features in priority order:

1. **Patch-round-trip file-glob exclude** — 3 CVE direct wins, also lifts
   several already-validated CVEs out of noisy logs. Smallest LOC change
   (one filter in `validate.ts` `runDiffTargetedValidation`).
2. **Keyword-arg-aware sink matching** — 2 CVE wins, plus likely several
   pypi CVEs not yet in corpus. Touches `matchesCallPattern` /
   `pattern-syntax.ts`.
3. **Ruby bracket accessor parity** — single CVE win but Ruby is the most
   under-validated ecosystem (4 of 4 ruby non-validated entries). Small fix
   in `ruby/propagate.ts` source-binding resolution.

**F3 estimated lift: +5.6 pp → 83.4% cumulative.**

### F4 — Non-taint vulns (8 CVEs)

These are vulnerabilities whose detection requires a regime other than data-
flow taint:

- **Memory-safety / parser-internal**: CVE-2023-49083 (cryptography PKCS7
  null deref), CVE-2017-16137 (debug %o ReDoS — F3 covers patch round-trip
  but real fix is regex change).
- **Config / insecure-default**: CVE-2024-35195 (requests
  Session.verify=False persisting), CVE-2024-28849 (follow-redirects
  Authorization header leak), CVE-2023-30861 (flask cookie-cache header
  alignment).
- **Cardinality / resource exhaustion as semantic property**:
  CVE-2022-21698 (prometheus label cardinality), CVE-2026-40175 (axios
  prototype-pollution-as-header-injection).
- **Library-internal**: CVE-2022-29153 (consul http check follows
  redirects).

F4 path is to spin up a **config-rule / AST-pattern regime** (separate from
taint) that fires on presence of a vulnerable call shape without requiring a
source. Existing reachability levels (`module` / `function`) are already the
right output channel — the rules just need a non-taint matcher.

Top 3 highest-leverage F4 actions:

1. **Insecure-default detector** for `requests.Session(verify=False)`,
   `ssl.PROTOCOL_*` weak versions, etc. Single CVE direct (CVE-2024-35195)
   but extensible across pypi.
2. **Header-config rule** for cross-redirect Authorization leak
   (CVE-2024-28849) and flask cookie+Vary mismatch (CVE-2023-30861).
3. **Prometheus cardinality lint** — flag http-input flowing into
   `WithLabelValues(*)`. Hybrid taint/config; can ride on the same engine.

**F4 estimated lift: +5–8 pp** (best case all 8 land; realistic +5 pp →
88.4% cumulative).

### Uncoverable — 6 CVEs

Genuinely outside any reasonable static-analysis regime on caller source:

| CVE | Why uncoverable |
|-----|----------------|
| CVE-2021-25287 (pillow oob_read) | Memory-safety in C decoder; caller pattern is `Image.open` which fires on every call. |
| CVE-2023-37920 (certifi root CA) | Vulnerability is the bundled CA list; every caller of `certifi.where()` equally affected. Package-version only. |
| CVE-2023-34053 (spring-boot Observation DoS) | Tag-cardinality reasoning; no localisable call pattern with acceptable FP rate. |
| CVE-2022-27664 (golang http2 GOAWAY DoS) | HTTP/2 protocol-level; every HTTP/2 server affected. |
| CVE-2023-44487 (HTTP/2 Rapid Reset) | Same — protocol-level, server-internal. |
| CVE-2024-21626 (runc /proc/self/fd) | Container runtime escape; no application-source pattern. |

These contribute **0 pp lift under any static regime**. They are the floor
of "honest uncoverable" — detection here means depending on
package-version-only signal, which is what the existing dep-scan/OSV path
already provides outside the reachability engine.

---

## Cumulative recall projection

| Stage | New validated | Cumulative | Cumulative pct |
|-------|---------------|------------|----------------|
| Today (post-ABCD)                      | 50  | 50 | 56.8% |
| + Phase E (E1+E2+E3+E4)                | +6  | 56 | 63.6% |
| + Phase F1 (13 spec adds)              | +13 | 69 | 78.4% |
| + Phase F3 (5 engine features)         | +5  | 74 | 84.1% |
| + Phase F4 (5–8 non-taint rules)       | +5  | 79 | 89.8% |
| + Phase F4 stretch (all 8)             | +3  | 82 | 93.2% |
| Uncoverable floor                      | —   | —  | 6 CVEs (6.8%) |

**Realistic ceiling on this 88-CVE corpus: ~88–90%.** The original
"~90%" claim survives, but with the caveat that the last 5 pp is non-taint
F4 work — not engine improvements — and that there is a hard 6-CVE
uncoverable floor (6.8%) below which static reachability analysis on caller
source cannot go without becoming package-version-only.

The 80% milestone is achievable with F1+F3 alone, which is the cleanest
short-term path (no new regime, just spec adds + engine polish).

---

## Suggested ordering

1. **Land Phase E** (already in flight) — confirms +6 CVE baseline.
2. **F3 patch-round-trip file-glob exclude** — single PR, lifts 3 CVE + is
   prereq for F1 spec adds (whose validation Gate-3 will otherwise blow up
   on test-file matches).
3. **F1 wave A (npm/pypi/maven specs)** — `axios.yaml` extension,
   `setuptools.yaml`, `semver.yaml`, `spring-beans.yaml`,
   `log4j.yaml` 1.x extension. 5 specs, +5 CVE.
4. **F3 keyword-arg matching** — engine PR; lifts urllib3 + jinja2 +
   any future kwarg-heavy pypi CVE.
5. **F1 wave B (golang/gem specs)** — `x-text.yaml`, `x-net-html.yaml`,
   `apache-poi.yaml`, `ruby-git.yaml`, `actionpack.yaml`, `rack.yaml`. 8
   CVE, biggest impact on the weakest ecosystems.
6. **F4 regime** — separate workstream. Define config-rule schema, port
   `requests.Session(verify=False)` and `follow-redirects Authorization`
   detectors as proof-of-concept. Hold until F1+F3 land so engine wins are
   not muddled with regime-change wins.

---

## Cross-references

- Per-CVE data: `.cursor/plans/triage-2026-05-12-post-abcd.json`
- Previous-run triage (pre-ABCD, stale): `.cursor/plans/triage-2026-05-12.json`
- Bundled specs: `depscanner/src/taint-engine/framework-models/`
- Validation runner: `depscanner/src/rule-generator/validate.ts`
- Engine cores: `depscanner/src/taint-engine/{propagator,python,java,go,ruby,php}*`
- Latest run: `depscanner/bench-iterate/v_base/2026-05-12T17-41-24/`
