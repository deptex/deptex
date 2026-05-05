# Research: Building Our Own Cross-File Inter-Procedural Taint Engine

**Question:** Can Deptex build its own deterministic cross-file taint stitching engine (instead of integrating Joern or relying only on AI), on a multi-month timeline, scoped to "useful but not perfect"?

**Verdict (TL;DR):** **Yes, with sharp caveats.** A 3–6 month single-engineer effort can ship a useful **deterministic forward-propagation engine for one language** (recommend TS/JS first) wired in as a **second opinion alongside atom**, paired with an **AI augmentation layer for taint-spec inference and false-positive filtering** (the published IRIS architecture, ICLR 2025). It cannot match Snyk Code or CodeQL depth — that's 30+ engineer-years and a decade of hand-curated framework models. Doing it pure-clean-room "from a tree-sitter AST" is an 18–30 month project; doing it on top of the **TypeScript Compiler API** for JS/TS specifically is a feasible quarter.

---

## Current State in Deptex

We already have:
- **Tree-sitter universal usage extractor** across 8 languages (JS/TS, Python, Java, Go, Ruby, PHP, Rust, C#) plus 34 framework entry-point detectors — gives us per-file ASTs and import resolution as inputs.
- **atom (from dep-scan)** producing cross-file taint flows for **JS/TS and Java only**, wired into the `reachability_rules` pipeline step (Phase 3). For Go, Kotlin, Swift, Python frameworks → atom is weak/empty.
- **Semgrep open-source** in single-file taint mode, with a Phase 5 AI-rule-generator producing per-CVE rules at ~72% validation rate on the original 18-CVE corpus.
- **No callgraph, no def-use chains, no SSA, no inter-procedural propagation engine of our own.**

The gap is clear: cross-file taint for languages atom doesn't cover, plus a stronger second opinion for JS/Java cases atom misses (dynamic dispatch, framework indirection).

---

## Engineering-Effort Reality from Established Players

| Product | First language production-ready | Total team-years to "useful for one language" | Architecture | Source |
|---|---|---|---|---|
| **Joern (OSS)** | 2018 (C/C++) | ~30–60 engineer-years cumulative; ~4,165 commits since 2019-03; CPG concept from Yamaguchi 2014 | Code Property Graph + pre-resolved callgraph + on-the-fly walk (NOT IFDS). Hand-written semantics for any external method | [joern.io blog](https://joern.io/blog/interproc-dataflow-2024/), [Yamaguchi 2014](https://ieeexplore.ieee.org/document/6956589/) |
| **Snyk Code (DeepCode)** | ~2019 (JS, ~3 yrs from founding) | ETH research from 2013 → company 2016 → Snyk acquisition 2020 (4 founders + 11–50 employees) | Hybrid symbolic + ML from day 1 (per ETH Zurich) | [ETH Zurich](https://ethz.ch/en/news-and-events/eth-news/news/2020/09/deepcode.html), [Tracxn](https://tracxn.com/d/companies/deepcode/__DMIAMeVqOx1KFUhatsUqqoaQ6PgulLYmuOxWYfV6ziI) |
| **Semgrep Pro Engine** | Feb 2023 (Java + JS, "6+ months focused work") | r2c founded 2017; OCaml engine pre-existed since 2020; 2 dedicated sub-teams (PA + security research) | Interprocedural taint layer on top of mature pattern-matching engine | [Semgrep blog](https://semgrep.dev/blog/2023/the-birth-of-semgrep-pro-engine/) |
| **CodeQL (Semmle)** | ~2010 (Java) | 13 years founding → GitHub acquisition 2019, ~80 employees, $31M raised. **28 MB of hand-curated QL standard-library code** | Datalog-style engine over extracted code DB | [Wikipedia: Semmle](https://en.wikipedia.org/wiki/Semmle), [github/codeql](https://github.com/github/codeql) |

**Key insight:** the CodeQL engine itself isn't huge; the **28 MB of QL standard library** (per-framework source/sink/sanitizer specs hand-written for Spring, Flask, Express, Django, …) is what makes it find real bugs. Same lesson from Joern: their `reachableBy` "soundly overapproximates" any external method without a hand-written summary file. **The engine is ~10% of the work; the framework models are the other 90%.**

---

## Architecture Choices Compared

### Option A: CPG (like Joern / CodeQL)
- Build one big graph across all files: AST, CFG, DDG, call-graph, type-info, all unified.
- Query language for taint traversal (`reachableBy`).
- **Pro:** queries compose cleanly; one substrate handles many vuln classes.
- **Con:** building the CPG is the whole project. Joern's 30+ engineer-years are mostly CPG schema + 12 frontends. Not realistic solo.

### Option B: IFDS / IDE solver (like Phasar)
- Reps/Horwitz/Sagiv POPL 1995 algorithm — graph reachability on an "exploded supergraph" with function summaries.
- **Pro:** mathematically clean, fully context-sensitive, ~500–1000 LOC for the solver itself.
- **Con:** the solver is the easy part. IFDS needs (1) per-procedure CFG, (2) callgraph, (3) finite domain, (4) distributive transfer functions — and **tree-sitter gives you zero of those**. Phasar is LLVM-IR-only because Phasar's authors didn't want to rebuild those four prerequisites either. ([Phasar wiki](https://github.com/secure-software-engineering/phasar/wiki/Writing-an-IFDS-analysis), [Bodden tutorial](http://www.bodden.de/pubs/bodden12inter-procedural.pdf))
- **Verdict:** IFDS is the wrong abstraction unless we already have an IR. We don't.

### Option C: Forward propagation on a substrate-borrowed callgraph (RECOMMENDED)
- Use existing OSS to get the callgraph + SSA per language; write a worklist forward-propagation engine on top.
- **Pro:** the callgraph is the hard part; if we don't reinvent it, we're left with maybe 3–4k LOC of taint propagator over the callgraph.
- **Con:** loses context-sensitivity (calls to the same function from different sites see merged taint). Acceptable for v1 — you trade ~15pp recall for tractability.

This is roughly what **Snyk Code** (per [Snyk DCAIF docs](https://snyk.io/articles/snyk-dcaif-under-the-hood/)) and the **2018-paper-quality** academic prototypes do. It's not state-of-the-art, but it's deterministic, explainable, and shippable.

---

## What We Can Actually Lift (vs. Reimplement)

| Component | Per-language source | License | Lift verdict |
|---|---|---|---|
| **JS/TS callgraph + symbol resolution + type-aware call edges** | [TypeScript Compiler API](https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API) (`createProgram`, `TypeChecker`, `findReferences`) | Apache-2.0 | **LIFT.** Replaces months of work. This is the single highest-leverage decision. |
| JS/TS callgraph (validator/baseline) | [Jelly (cs-au-dk)](https://github.com/cs-au-dk/jelly) | BSD-3-Clause | Lift as second opinion. Active research artifact. |
| **Go callgraph + SSA** | [golang.org/x/tools/go/callgraph + go/ssa](https://pkg.go.dev/golang.org/x/tools/go/callgraph) | BSD-3-Clause | **LIFT.** ~1 day to wrap as a JSON-emitting subprocess. Free SSA + sound CHA/RTA/VTA. |
| **Python callgraph + SSA + def-use** | [Scalpel](https://github.com/SMAT-Lab/Scalpel) | Apache-2.0 | LIFT (academic prototype but right primitives + clean license). |
| Python references | [Jedi](https://github.com/davidhalter/jedi) | MIT | LIFT for cross-file name resolution. |
| Python inter-procedural taint engine (mature) | [Pysa (Facebook)](https://github.com/facebook/pyre-check) | MIT | Wire as subprocess; don't fork. |
| Java/Kotlin inter-procedural taint | [OpenTaint](https://github.com/seqra/opentaint) | Apache-2.0 + MIT | Watch (38 stars, JVM-only today, TS roadmap item). Don't bet on it. |
| Java/Kotlin/Ruby/PHP/Rust/C# | — | — | **NO mature OSS exists**. Tree-sitter + own engine is the only path. |
| **Pyan3** for Python callgraph | [Technologicat fork](https://github.com/Technologicat/pyan) | **GPL-2.0** | License-toxic for commercial open-core. Skip. |
| **Semgrep OSS taint propagator** | [semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 | Single-file only; cross-file is Pro/proprietary. Forking the OCaml engine for our backend is unrealistic. |
| **CodeQL CLI** | [github/codeql-cli-binaries](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) | Custom | **LICENSE FORBIDS** analyzing closed-source/private code without GitHub Advanced Security. Non-starter for our customers. |

**Honest summary:** there is no "lift the whole engine" option that covers our 8 languages. The right architecture is **per-language substrate**, with the taint propagator written once in TypeScript over a normalized language-agnostic IR.

---

## What "Good Enough" Looks Like (Precision/Recall Reality)

JavaScript ground-truth from real benchmarks:
- "Study of JavaScript Static Analysis Tools" ([arxiv 2301.05097](https://arxiv.org/pdf/2301.05097)): JS SAST tools catch only **15.1% of vulns on average**; union of three best tools catches 57.6% at **0.11% precision**. CodeQL alone catches **31.3%** across all CWEs.
- "Bimodal Taint Analysis" / Fluffy ([ISSTA 2023](https://software-lab.org/publications/issta2023_Fluffy.pdf)): on Node.js benchmarks, state-of-the-art static analyzers found **3 true positives where dynamic-augmented found 63** — a 20× recall gap.

OWASP Benchmark v1.2 (Java, 2,740 cases, [arxiv 2601.22952](https://arxiv.org/abs/2601.22952)):
- CodeQL F1 = 74.4%, Semgrep F1 = 69.4%
- Joern shows FPR ≈ 0 but corresponding low TPR — "conservative analysis strategy that likely suffers from a high false negative rate"

A **naive forward-propagation engine without aliasing or context sensitivity** would land roughly at:
- **JavaScript: 10–25% recall** (between ESLint SSC alone and CodeQL alone) at modest FP rates
- **Java: 40–60% TPR** on OWASP Benchmark (Java's static type system makes the callgraph tractable)
- **Python: 20–35% recall** (frameworks dominate, hand-written models are the multiplier)

**The leverage move (IRIS, ICLR 2025):** combine a deterministic engine with LLM-inferred taint specs + LLM FP filtering. On CWE-Bench-Java ([arxiv 2405.17238](https://arxiv.org/abs/2405.17238)):
- CodeQL alone: 27/120 detected
- **IRIS + GPT-4: 55/120 (+103%)**, recall on sink specs **87.11%**, FDR ~5pp better
- SAST-Genius: **91% false-positive reduction** on Semgrep output via LLM post-filter ([arxiv 2509.15433](https://arxiv.org/abs/2509.15433))

This is the published frontier. **It maps directly onto Phase 5's existing AI infrastructure** — we already have AI rule generation, BYOK providers, retry loops, validation harnesses. Adding "AI taint-spec inference per-org" and "AI FP filter" is incremental.

---

## Recommendation: The Hybrid Path

**Verdict: YES with caveats — but build a hybrid, not a clean-room IFDS engine.**

### Recommended architecture
- **Substrate per language** (lift, don't reinvent):
  - JS/TS: TypeScript Compiler API (whole-program callgraph + symbols + type-aware edges)
  - Go: `golang.org/x/tools/go/callgraph` + `go/ssa` as a subprocess
  - Python: Scalpel (SSA + def-use) + Jedi (references) + optionally Pysa as subprocess
  - Java/Kotlin/Ruby/PHP/Rust/C#: defer; use atom for what it covers, AI rules for the rest
- **Common worklist taint propagator** in TypeScript over a normalized IR (forward, flow-sensitive, context-insensitive). ~3–4k LOC.
- **Source/sink/sanitizer spec format** YAML per (vuln-class, framework). Hand-curate the top 5 frameworks per language for v1 (Express/Fastify, Flask/FastAPI, Spring, Gin, Rails).
- **AI augmentation layer** (IRIS-style):
  - Per-org spec inference: feed the model a new framework's source code, get back inferred sources/sinks/sanitizers
  - FP filter: every flow above some confidence runs through an LLM check before reaching the user
- **Wire as a SECOND OPINION to atom**, not a replacement. Atom keeps doing JS/Java; new engine adds Go/Python/etc. and offers a stronger pass on JS/Java where atom misses.

### Recommended starting language: **JavaScript/TypeScript via TS Compiler API**

Why:
- TS Compiler API gives us months for free (whole-program symbols, type-aware callgraph, cross-file references — that's the core of the project handed to us)
- We already validate against JS-heavy fixtures in Phase 5 — direct A/B compare against atom is straightforward
- Highest commercial leverage: npm is the largest ecosystem in our user base
- Worst-case fallback if framework models aren't ready: still useful as a "find calls that look like X across files" tool

Alternative: Python first (atom is weakest there, frameworks dominate). Reasonable but more upfront work because we'd lean on Pysa-as-subprocess + Scalpel learning curve.

### 3–6 month milestone breakdown

| Month | Deliverable | Validation |
|---|---|---|
| **M1** | TS Compiler API substrate: `tsc-callgraph` extractor producing JSON callgraph + symbol table for a TS project. JS-heavy projects via `allowJs: true`. | Run on test-npm + 3 OSS repos; verify edges match `findReferences` |
| **M2** | Worklist forward-propagation taint engine over the callgraph. Spec format (YAML) for sources/sinks/sanitizers. Hand-write 5 vuln classes (SQLi, SSRF, XSS, path-traversal, command-injection) for Express. | Run vs. CWE-Bench-JS; compare flows against atom output on test-npm |
| **M3** | Wire into existing `reachability_rules` pipeline as a parallel signal alongside atom. Output normalized to existing flow-record format. Frontend label: "deterministic taint v1 (beta)". | A/B vs. atom on the deptex-test-npm corpus; report agreement rate + delta CVEs caught |
| **M4** | Hand-curate framework models for Fastify, Next.js, NestJS. Add 5 more vuln classes (proto pollution, deser, ReDoS, prototype merge, regex bypass). | 50-CVE JS subset of the new 88-CVE Phase 5 corpus — measure validation lift |
| **M5** | AI FP filter (IRIS post-filter style). For every flow above confidence threshold, run LLM check before surfacing. Wire BYOK provider with cost caps. | Compare precision/recall on same 50-CVE subset with and without filter on |
| **M6** | AI taint-spec inference: per-org pipeline that ingests a new framework's source and produces draft YAML spec for review. Optional Python frontend MVP via Scalpel + Jedi if budget allows. | Drop a new framework on it (e.g. tRPC) and measure model output quality |

After 6 months we have: **a working deterministic JS/TS engine with hybrid AI augmentation, integrated as a second opinion to atom, with a path to Python in M7+.**

### What we're explicitly punting for v1
- **Aliasing precision** — no Andersen, no points-to. Conservative over-approximation. (Sridharan ECOOP 2012 shows context-sensitive Andersen on JS is **O(N⁴)** — not happening.)
- **Dynamic dispatch beyond TS types** — typed code resolves cleanly via tsc; untyped JS gets best-effort, log a warning.
- **Async/promise chains** — treat as sync for v1. Most taint flows still resolve.
- **eval/reflection/Function constructor** — log a warning; flow ends.
- **Polymorphism beyond single-class hierarchy** — Joern punts here too.
- **Cross-language flows** (e.g. JS calling into a WASM module) — out of scope.
- **Joern-style soundness claims** — we explicitly market as "best-effort, second opinion."

### Top 3 risks
1. **Framework-model curation is a tar pit.** "Just Express" is 50+ middleware shapes, query parsing, body parsing, route decorators, response sinks. CodeQL has 28 MB of this for a reason. **Mitigation:** lean hard on the AI spec-inference layer earlier than M6 — it might need to be M3.
2. **Untyped JavaScript wrecks recall.** Half of npm has no types. tsc's type checker is useless on those projects, and the callgraph degrades to "best guess." **Mitigation:** measure typed-vs-untyped recall split early; consider requiring a `tsconfig.json` for V1 GA.
3. **Time-budget creep on the second language.** Python adds Scalpel + Jedi + Pysa learning curve. M6 deliverable might slip. **Mitigation:** set a hard go/no-go decision at end of M5 — if the AI augmentation layer is performing well on JS, defer Python to M7+ and consolidate the JS story instead.

### What this is NOT
- Not "match Snyk Code on JS." That's a 2-year project with a research-grade team.
- Not "replace atom." Atom keeps running; this is additional signal.
- Not "match CodeQL depth." Their standard library is a decade of Spring/Flask/Express models.
- Not "ship without AI." The published frontier (IRIS, SAST-Genius) is hybrid by 2025; pure-deterministic is leaving recall on the table.

---

## Recommended Next Step

Run `/interview` on this concept ("Deptex Cross-File Taint v1 — TS Compiler API + AI Augmentation") to lock scope decisions before `/plan-feature`. Key interview questions to surface:
1. M1 vs M5 sequencing — do we ship the deterministic-only engine in M3 (and risk low recall headlines) or wait until M5 with the AI filter integrated?
2. Naming + UX — "deterministic taint" vs "second-opinion taint" vs "Deptex taint engine" — affects how we position vs atom in the UI.
3. Frontend exposure — surface as a separate badge, fold into existing reachability_level, or both?
4. Cost cap policy — does AI FP filtering use the existing EPD cost cap, the per-org Aegis cap, or get its own bucket?

---

## Appendix: Sources

**Joern + CPG architecture**
- [Yamaguchi et al., "Modeling and Discovering Vulnerabilities with Code Property Graphs" (IEEE S&P 2014)](https://ieeexplore.ieee.org/document/6956589/)
- [Joern blog: How Interprocedural Data-flow Works in Joern (2024)](https://joern.io/blog/interproc-dataflow-2024/)
- [CPG specification](https://cpg.joern.io/)
- [Joern frontends docs](https://docs.joern.io/frontends/)
- [Joern dataflow semantics docs](https://docs.joern.io/dataflow-semantics/)
- [Joern developer notes (Andreas Kellas)](https://www.wunused.com/posts/joern-developer-notes/)

**IFDS / academic taint analysis**
- [Reps/Horwitz/Sagiv POPL 1995](https://pages.cs.wisc.edu/~fischer/cs701.f14/popl95.pdf)
- [Phasar wiki: Writing an IFDS analysis](https://github.com/secure-software-engineering/phasar/wiki/Writing-an-IFDS-analysis)
- [Bodden, "Inter-procedural data-flow analysis with IFDS/IDE and Soot" (2012)](http://www.bodden.de/pubs/bodden12inter-procedural.pdf)
- [Sridharan ECOOP 2012 on JS Andersen complexity](https://manu.sridharan.net/files/ECOOP12Correlation.pdf)
- [Bimodal Taint Analysis (Fluffy, ISSTA 2023)](https://software-lab.org/publications/issta2023_Fluffy.pdf)
- [Scalable Compositional Static Taint (ICSE 2023)](https://yuleisui.github.io/publications/icse23.pdf)

**Engineering history**
- [ETH Zurich: DeepCode acquisition (2020)](https://ethz.ch/en/news-and-events/eth-news/news/2020/09/deepcode.html)
- [Snyk DCAIF under the hood](https://snyk.io/articles/snyk-dcaif-under-the-hood/)
- [Semgrep blog: Birth of Pro Engine](https://semgrep.dev/blog/2023/the-birth-of-semgrep-pro-engine/)
- [Semgrep supported languages](https://semgrep.dev/docs/supported-languages)
- [Wikipedia: Semmle](https://en.wikipedia.org/wiki/Semmle)
- [TechCrunch: GitHub acquires Semmle (2019)](https://techcrunch.com/2019/09/18/github-acquires-code-analysis-tool-semmle/)
- [github/codeql repo](https://github.com/github/codeql)
- [CodeQL ExternalFlow MaD docs (Java)](https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/dataflow/ExternalFlow.qll/module.ExternalFlow.html)

**Hybrid AI + symbolic frontier**
- [IRIS (ICLR 2025) — arxiv 2405.17238](https://arxiv.org/abs/2405.17238)
- [IRIS at OpenReview](https://openreview.net/forum?id=9LdJDU7E91)
- [SAST-Genius — arxiv 2509.15433](https://arxiv.org/abs/2509.15433)
- [Endor Labs platform](https://www.endorlabs.com/platform)

**Benchmarks**
- [JS SAST study, arxiv 2301.05097](https://arxiv.org/pdf/2301.05097)
- ["Sifting the Noise" OWASP Benchmark, arxiv 2601.22952](https://arxiv.org/abs/2601.22952)
- [Cycode SAST benchmark (2024)](https://cycode.com/blog/benchmarking-top-sast-products/)

**OSS lift candidates**
- [TypeScript Compiler API wiki](https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API)
- [Jelly (cs-au-dk)](https://github.com/cs-au-dk/jelly)
- [Static JS Call Graphs comparative study, arxiv 2024](https://arxiv.org/html/2405.07206v1)
- [golang.org/x/tools/go/callgraph](https://pkg.go.dev/golang.org/x/tools/go/callgraph)
- [Scalpel](https://github.com/SMAT-Lab/Scalpel)
- [Jedi](https://github.com/davidhalter/jedi)
- [Pysa basics docs](https://pyre-check.org/docs/pysa-basics/)
- [OpenTaint](https://github.com/seqra/opentaint)
- [Semgrep taint mode docs](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode)
- [CodeQL CLI license](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md)
