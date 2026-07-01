# Reachability Benchmark — Methodology

The Deptex reachability classifier reports per-vulnerability tier
(`confirmed` / `data_flow` / `function` / `module` / `unreachable`) used
to weight depscore. This document explains how we measure that
classifier's noise-reduction rate honestly: the corpus, the gates, the
oracle, and the precision lever the v3 arc added on top.

If you're evaluating Deptex against other SCA tools' headline noise
numbers (Snyk, Endor Labs, Socket, Semgrep), the punchline is at the
bottom: published vendor claims are unverifiable on unpublished corpora;
ours is a held-out 49+ CVE corpus with frozen ground truth, an
independent oracle, and reproducible gate arithmetic.

---

## What the corpus is

`depscanner/scripts/reachability-corpus.yaml` lists real OSS application
repositories pinned at specific tagged refs, each with hand-labelled
ground-truth verdicts on every observed CVE. The corpus is *application*
shaped — not framework shaped — because frameworks consume their own
dependencies, so a framework repo has nothing meaningfully unreachable.
Applications are what customers run; they declare a handful of direct
deps and pull a large transitive tree they don't all reach.

The current corpus (v3 baseline carrying forward from v2) — **8 repos, 49
hand-labelled CVEs** across the four labelled application repos:

| repo | ecosystem | ref | CVEs | role |
|---|---|---|---|---|
| `expressjs/express` | npm | `4.18.2` | 24 | framework with rich devDep tree |
| `spring-projects/spring-petclinic` | maven | `c7ee170` (pinned) | 10 | spring boot demo app |
| `sharkdp/bat` | cargo | `v0.24.0` | 3 | cat-replacement CLI |
| `fastify/fastify` | npm | `v4.26.0` | 12 | dev-scope-dominant npm app |
| `caddyserver/caddy` | golang | `v2.4.6` | 0 | go ecosystem coverage — not yet labelled |
| `mlflow/mlflow` | pypi | `c22889f` (pinned) | 0 | pypi ecosystem coverage — not yet labelled |
| `symfony/demo` | composer | `f73440d` (pinned) | 0 | composer ecosystem coverage — not yet labelled |
| `discourse/discourse` | gem | `ad49d8f` (pinned) | 0 | rubygems ecosystem coverage — not yet labelled |

The four `0`-CVE repos are pinned and cloned for ecosystem breadth (go /
pypi / composer / rubygems) but their per-CVE verdicts aren't authored yet,
so they don't contribute to Gate 1 / Gate 3 today — only to the cross-
ecosystem plumbing the resolvers exercise.

Ground-truth label set per CVE: `confirmed | data_flow | function |
module | unreachable`. Labels live alongside the repo entry in the YAML
with a one-paragraph rationale citing the relevant code path.

## How a CVE gets labelled

Each label has to survive code inspection — we read the application
source, identify whether the vulnerable function is on a call path
the application's first-party code can reach, and write the rationale
down with the label. The rules of thumb:

- **reachable** (`confirmed` / `data_flow` / `function`): the
  vulnerable function lies on a call path the application exercises.
  Express's `qs` parser is reachable because every request goes through
  it; petclinic's spring-webmvc is reachable because every `@Controller`
  request is dispatched through it. Used to forbid Gate 3 false
  negatives.
- **module**: the package is present and definitely used, but the
  specific vulnerable function isn't on a verified call path.
  jackson-core in petclinic is module — Spring serialises JSON through
  it, but petclinic is mostly server-rendered Thymeleaf so whether the
  vulnerable parse path is exercised is unverified.
- **unreachable**: the vulnerable code is on no call path in this
  repo. Express's `handlebars` advisories are unreachable because
  handlebars is a devDependency exercised only by the `examples/` view-
  engine demo; express's `lib/` never invokes a template engine.

## The three gates

The corpus harness `npm run test:reachability-corpus` evaluates three
gates against the scanner's output:

### Gate 1 — overall noise reduction

```
score = (unreachable_count + 0.5 * module_count) / observed
```

The denominator is the number of corpus CVEs the scanner found
(`observed`). The numerator credits `unreachable` at weight 1.0 and
`module` at 0.5. `function` / `data_flow` / `confirmed` count zero.
This formula was chosen because:

- `unreachable` (depscore 0.0) is the most aggressive noise reduction —
  vendor would never alert on it. Full credit.
- `module` (depscore 0.5) means "yes the package is here, but we don't
  know the specific function" — partial credit; vendor would still
  alert but with lower severity.
- The reachable tiers are alerts the vendor SHOULD produce, so they
  contribute nothing to noise reduction.

Mathematically, **100% is impossible** on a representative corpus. Every
real application has at least some CVEs whose vulnerable function is
genuinely on its critical path — those have to be classified reachable,
and they contribute zero to Gate 1. The honest ceiling on this metric
is roughly **85-92%**.

### Gate 2 — per-ecosystem floor

Every ecosystem represented in the corpus must have at least one
`unreachable` verdict — otherwise the classifier is structurally
blind to that ecosystem. v2 shipped with this gate passing for
npm / maven / cargo. v3 brings go and pypi into scope via custom
transitive resolvers.

### Gate 3 — zero false negatives

The hard constraint. A CVE labelled `reachable` (`confirmed` /
`data_flow` / `function`) that the scanner classifies `unreachable`
is a false negative — we hid a real vulnerability. Gate 3 forbids
any such case. This is the load-bearing safety contract; the other
gates can soften, this one cannot.

## Baseline lock + independent oracle

Two layers of integrity beyond the gates:

- **`reachability-corpus-baseline.lock.yaml`** freezes a subset of
  the labels as immutable. Any change or deletion of a frozen label
  fails the gate. New labels (added repos) are accepted as additions.
  This catches "I tweaked the corpus to make my number go up."
- **`reachability-corpus-oracle.yaml`** is a second, independent set
  of verdicts on the same CVEs. Currently authored by the same person
  who wrote the primary labels (open caveat — see below). Diffs
  between the oracle and the scanner's output surface in the gate
  log so a human can investigate.

The pinned commit SHAs on the repo refs mean re-running the gate
months later produces the same dep set, which produces the same
verdicts. The reproducibility is the methodology's whole point.

## The v3 precision arc — callgraph-confirmed transitives

v2 used a deterministic heuristic to detect "unreachable":

```
unreachable = transitive_dep
            AND files_importing_count == 0
            AND not_a_framework_embedded_runtime
            AND ast_extraction_produced_output
            AND dependency_graph_trusted
```

This works for clean orphan transitives (`idna` in `bat` — bat does
no DNS work, never imports url-handling code; idna is genuinely
unreachable). It produces a precision miss on the inverse: a transitive
dep called by a *framework* on behalf of the application, where the
application source never directly imports it. The canonical case is
`jackson-core` in `spring-petclinic` — petclinic doesn't
`import com.fasterxml.jackson.*`, but Spring Boot's request handler
deserialises every JSON request through jackson on every request. v2
classified jackson `unreachable`; reality says module-or-better.

v3 extends the taint-engine's existing whole-program callgraph to also
emit `usedDependencies: Set<string>` — the set of dep package names
the callgraph traced a CallEdge into. The reachability classifier
AND-clauses one more condition onto the heuristic:

```
unreachable = ... AND NOT callgraph_traced_call_edge_into_this_dep
```

Stamped on the demoted PDV's `reachability_details.verdict` as
`callgraph_reached_transitive` so the per-CVE audit trail makes the
decision visible. Also persisted on
`project_dependencies.callgraph_reached` as a tri-state (`null` =
not measured / `true` = traced / `false` = measured-but-not-traced)
for future UI surfaces.

The lever is honest about its drag: every callgraph-traced demotion
moves a CVE from `unreachable` (Gate-1 weight 1.0) to `module` (weight
0.5), costing `0.5/N` per CVE on the headline. On a corpus where 5-10
deps demote, expect a 5-10pp drag on Gate 1. The corpus expansion has
to outpace that drag to land in the 85-92% band.

### Per-language status

| Language | precision signal source | shipping in v3 |
|---|---|---|
| JavaScript / TypeScript | TS Compiler API resolves cross-package symbols even when the workspace doesn't `import` them. Pull `decl.getSourceFile().fileName` from each external resolution; extract package name from `node_modules/<pkg>/...`. | **yes** |
| Java | requires class-FQN → SBOM-purl resolver (jackson packages are `com.fasterxml.jackson.*`; SBOM purls are `pkg:maven/com.fasterxml.jackson.core/jackson-databind`). 1-hour spike + 4-6h impl deferred to v3.1. | deferred |
| Python / Go / Rust | tree-sitter callgraphs deliberately skip dep dirs (`site-packages` / `pkg/mod` / `registry/src`). The languages' framework patterns don't reproduce the JS re-export case the same way — `filesImporting > 0` already catches most reaches. Marginal value vs implementation cost. | deferred |
| Ruby / PHP / C# | same skip pattern. Deferred to v3.1. | deferred |

The classifier treats undefined or empty `usedTransitives` identically
to v2 behavior — any language whose callgraph doesn't extract the set
yet falls back cleanly without false negatives.

## go and pypi shallow-SBOM resolvers

A second class of "I can't measure this ecosystem" problem: cdxgen
without `--deep` emits a direct-deps-only SBOM for `gomod` and `pypi`.
The reachability classifier's `unreachable` verdict keys on
`!is_direct`, so a shallow SBOM produces zero unreachable verdicts on
those ecosystems — they fail Gate 2 by construction.

v3 ships per-ecosystem transitive resolvers under
`depscanner/src/transitive-resolvers/`. The wire-in in `sbom.ts`
triggers only when ecosystem ∈ {gomod, pypi} AND every parsed dep is
`is_direct === true` (the structural shallow-SBOM signal — never
fires when a deep SBOM already has transitives):

- **go**: `go list -m -json all` enumerates every module in the
  build graph. Parsed by a stream-tolerant JSON walker.
- **pypi**: `pip install --dry-run --report=-` runs pip's own
  resolver in dry-run mode with zero install side effects. Falls back
  to a throwaway venv + `pipdeptree --json` for poetry-locked projects
  pip's resolver chokes on.

Dedup policy: cdxgen wins on coords (it carries license + bom-ref
metadata the resolver doesn't); the resolver fills only the gap.
Soft-fail when no manifest exists (`transitive_resolver_skipped` log);
hard-fail with a structured warning when the tool errored but the
manifest existed (`transitive_resolver_failed`, pipeline continues).

## Running the corpus

Prerequisites:
- 55 GB free disk for the dep-scan VDB cache (`~/.deptex/vdb`).
- Docker for the local depscanner build (`npm run docker:build`).
- `DEEPINFRA_API_KEY` only needed if running with AI rule generation
  on; the corpus runs default to `--no-rule-gen` because rule
  generation doesn't shift Gate 1.

Run:
```bash
cd depscanner
npm run docker:build
DEPTEX_SKIP_OPTIONAL_SCANS=1 \
  npm run scan:oss-corpus -- \
    --repos=scripts/reachability-corpus.yaml \
    --output=oss-corpus-runs/<name> \
    --parallel=2 \
    --no-rule-gen \
    --scan-timeout=900
npm run test:reachability-corpus -- --report=oss-corpus-runs/<name>/report.json
```

`DEPTEX_SKIP_OPTIONAL_SCANS=1` turns off IaC / malicious / SAST /
secrets — none of those affect reachability classification and they
dominate scan time on real repos (the malicious-package scan fans
GuardDog out to a Semgrep run per dependency).

The harness exits non-zero if any of the three gates fail. Per-CVE
verdicts land in `oss-corpus-runs/<name>/report.json`; the golden
report at `scripts/reachability-corpus.golden-report.json` is the
checked-in reference for offline re-evaluation (`npm run
test:reachability-corpus -- --report=<that>`).

## Adding a new repo

1. Identify an application repo at a tagged ref with multiple CVEs
   on its dependency tree. Frameworks are wrong shape; pick apps.
2. Append a `repos[]` entry to `reachability-corpus.yaml`:
   ```yaml
   - name: <repo>
     repo_url: https://github.com/<owner>/<repo>.git
     ecosystem: npm | maven | cargo | gomod | pypi | rubygems | composer
     ref: <tag-or-pinned-SHA>     # NEVER a moving branch
     ground_truth_cves:
       - id: CVE-YYYY-NNNNN       # CVE-shaped, not GHSA-only
         expected_reachability: confirmed | data_flow | function | module | unreachable
         source: |
           One-paragraph rationale citing the relevant code path.
   ```
3. Run a scan against the new repo + the existing corpus once locally
   to confirm Gates 1/2/3 still pass.
4. Add the new labels to `reachability-corpus-baseline.lock.yaml` (so
   they're protected against silent edits going forward).
5. Mirror in `reachability-corpus-oracle.yaml` — independent verdicts.

## Open caveats (be honest about limits)

- **Oracle independence**: the primary labels and the oracle file are
  currently authored by the same person. The methodology surfaces
  diffs between them and the scanner, but doesn't yet have a
  cross-checked author for the oracle. For a true integrity claim
  this needs a second reviewer.
- **Java precision**: v3 ships the npm precision lever but not the
  Java equivalent — `jackson-core` in `petclinic` is still labelled
  `module` in the corpus but read as `unreachable` by the v2-style
  heuristic. Mild over-classification, not a Gate-3 false negative,
  but a known precision miss until the class-FQN → SBOM-purl
  resolver lands in v3.1.
- **Headline ceiling**: as established above, ~85-92%. Marketing
  claims above this band on a representative corpus are either on
  proprietary corpora that include lots of clean unreachable
  test/build-tool transitives, or are gaming the metric. Do not
  chase the ceiling.

## How this compares to vendor numbers

- **Endor Labs** publishes a 97% noise reduction figure (92% customer
  average) but doesn't publish the corpus, the methodology, or the
  per-CVE breakdown. Endor's number is plausibly true on their
  customer mix; it's not falsifiable on a held-out corpus you can
  inspect.
- **Snyk** publishes no headline noise-reduction percentage,
  emphasizing reachability coverage (>99% of applicable vulns
  analyzable) over a single number. Their docs acknowledge the
  accuracy-vs-recall tradeoff.
- **Socket (post-Coana acquisition)** publishes a tiered model:
  35% dep-level / 80% precomputed / 90% full-app. The methodology
  isn't published per-tier.
- **Semgrep** advocates dataflow reachability over function-level
  but doesn't publish noise-reduction numbers.
- **Coana's published research** explicitly recommends benchmarking
  on your own corpus because vendors game open benchmarks. This is
  what `reachability-corpus.yaml` is.

The honest position: vendor numbers above ~92% on a representative
corpus are unverifiable marketing claims. The corpus + frozen
baseline + oracle here lets you sanity-check the classifier on a
specific reproducible test set you can read. It does not claim to
match a vendor's customer-mix-specific number.
