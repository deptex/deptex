# Depscanner Full-Pipeline Stress-Test Plan

**Goal:** move from "5 flagship ecosystems deep, gates green, 9-app corpus" to *defensible-under-attack*: every pipeline stage exercised against adversarial inputs, faults, scale, and prod-parity — with regression tripwires that fire automatically, not manually.

**Current evidence baseline (2026-07-02):** 388 reachability unit tests · 5 framework models (3 two-app-validated) · 9-app assembled corpus (77.0% silenced / 700 findings, precision 75%, 0 noise-leak, Gate 1/3 + baseline-lock(31) + oracle(49) PASS) · 3 labelled repos (36 CVEs) · taint preflight 23/23 · dogfood corpus 12 fixtures · M1/M2 silence-log instrumentation merged. **Nothing from this loop deployed to prod.**

**Doctrine for every workstream:** a stress test that finds nothing must be *shown* to be able to find something (inject a known fault first, watch it fire). Silence is not success.

---

## WS-A — Corpus & Ground Truth (the evidence base)

The single highest-leverage workstream: every other number is only as believable as this.

- **A1. Label the 6 unlabelled corpus apps** (caddy, gitea, mastodon, discourse, saleor, paperless-ngx). Protocol: per-repo triage subagents grounded in real code (file:line citations required), then an independent adversarial-verify pass per verdict (2-of-3 refuters kill a label), labels land in `reachability-corpus.yaml` ground_truth_cves. Never label from the model's own output (corpus-integrity doctrine). *Deliverable: labelled set grows 36 → ~150+ CVEs; precision/FN numbers become statistically meaningful.*
- **A2. Corpus 12 → 25+** from `.cursor/plans/corpus-candidates.md` with per-ecosystem quotas: ≥2 real apps per modelled ecosystem, ≥1 for each unmodelled one (Flask, Laravel, Koa/Nest, cargo-server, nuget). Include the GitLab- and Bitbucket-hosted candidates — this stresses the **multi-provider clone path**, not just the classifier.
- **A3. Adversarial repo shapes** (one fixture or real repo each): monorepo/workspaces (npm workspaces, go.work, maven multi-module) · vendored deps (`vendor/`, checked-in node_modules) · dynamic imports (`importlib`, `require(var)`) · git submodules · symlink cycles · 1GB+ repo · empty/corrupt manifests · non-UTF8 + BOM + CRLF sources · generated/minified code. Assert: scan completes or fails *cleanly* (no hang, no partial-write), and every signal gatherer refuses demotions rather than mis-parsing.
- **A4. Determinism + VDB pinning:** scan each corpus repo twice on the same image → verdict diff must be empty. Quantify the known dep-scan VDB volatility (caddy 133 vs 43) and pin a VDB snapshot for scoring runs so corpus numbers are reproducible.

## WS-B — Parser/Extractor Robustness (the comment-paren bug class)

Both real bugs this loop (gitea openpgp, saleor dev-toolbar) were input-parsing/scoping bugs in signal gatherers. Attack all of them systematically.

- **B1. Property/fuzz tests for every gatherer:** Go import extractor, Python import extractor, Gemfile group parser, pyproject/Pipfile/requirements parsers, composer.lock, pom/Gradle reader. Generate weird-but-valid inputs (comments with delimiters inside blocks, string literals containing import syntax, nested parens, line continuations, mixed encodings). **Invariant under test: a parse degradation may only ever BLOCK a demotion, never enable one** (fail-safe direction is a testable property).
- **B2. Differential extraction:** compare each regex gatherer's import set vs tree-sitter's AST-derived set on all corpus repos. Any package the AST sees that the regex misses = a latent silence-FN → fix + regression fixture.
- **B3. Boundary cases:** files at exactly MAX_FILE_BYTES, repos at exactly MAX_CODE_FILES/BYTES caps, deep dir nesting at MAX_DIR_DEPTH — assert `truncated=true` propagates and all code-scan demotions refuse.

## WS-C — Reachability Classifier + the 5 Framework Models

- **C1. Retrofit two-app validation for the 2 single-app models:** Java/Spring (2nd real Spring Boot app — e.g. a JHipster-style or spring-boot-realworld app) and PHP/Symfony (2nd Symfony app). These predate the method that caught bugs in both models it was applied to; assume they hide one until proven otherwise.
- **C2. Negative-control suite:** run each model's gatherer against WRONG-framework repos (Django model on a Flask repo, Rails model on Sinatra, Symfony model on Laravel, Spring model on Quarkus) → assert `recognized=false` or zero moves. Recognition gates are the only thing standing between a model and someone else's ecosystem.
- **C3. Truncation stress at scale:** artificially lower caps on the biggest corpus repos → assert every demotion refuses, promotions still fire only on positive signals.
- **C4. Mutation testing on decision functions:** mutate each rule (drop a pattern, flip a gate, widen an owner) → at least one unit test must fail. Any surviving mutant = missing test.
- **C5. Cross-run FN differ (M2) as a standing tripwire:** on every image bump, scan the full corpus old-vs-new and alert on ANY visible→silenced transition. This is the single most important automated guard — wire it as a script (`npm run corpus:diff`), not a manual step.

## WS-D — Taint Engine

- **D1. CI on every PR:** `taint-engine:validate` + all per-language `test:taint-engine-*` suites (partially done — make it a required check).
- **D2. Recall floor:** dogfood preflight must hold 23/23; add seeded flows for the 2 newest ecosystems' specs.
- **D3. FP regression lock:** the backend 59→0 pass fixtures (xss content-type, redos compile-only, validate-then-use, SAML sanitizer) stay locked in `express-vulns/*-safe`; extend the pattern to one FP-cluster fixture per framework spec.
- **D4. Propagator non-convergence sentinel (TSCALE1):** assert no flow truncation on the largest corpus repos; log + alarm if the iteration cap is hit (a known silence-FN source).

## WS-E — Scanner Categories Beyond SCA

- **E1. Semgrep:** client-SPA filter regression suite; per-framework pack sanity on all corpus apps (expected-finding-count envelopes, not exact counts); wall-time budget per repo.
- **E2. Secrets:** TruffleHog on dogfood seeds (verified/unverified split asserted); an FP-corpus of high-entropy-but-benign files (fixtures, lockfile hashes, minified JS).
- **E3. IaC/container:** Checkov↔semgrep dedup regression; container-reachability e2e against 5 more base images (distroless, alpine, ubi).
- **E4. Malicious packages:** the NULL-version flag-all trap regression (name-only matching must never return); semver-range matching property tests (N4/N6); cache hit-rate probe (the 92.3% miss bug class); a cold-scan of a fresh repo asserting reasonable wall-time.
- **E5. DAST:** the parked NodeGoat form-login authenticated-scan test ([[dast_auth_todo]]); spec-param enrichment fixtures; ZAP timeout/recovery behavior when the target dies mid-scan.

## WS-F — Orchestration & Fault Tolerance (chaos)

Every test here first proves it can fail (inject the fault, watch detection fire).

- **F1. Kill the worker at every step boundary** (post-clone, post-SBOM, mid-taint, pre-finalize): job must be stuck-detected ≤5min, retried ≤3 attempts, and produce NO duplicate PDVs / no half-finalized run (the 6h-loop finalize-stamp bug class).
- **F2. Reproduce + fix the fleet-reaper flake** — the known `requested_stop=true, exit_code=0` kill of a BUSY machine mid-taint (scalable-extraction-infra domain: dispatcher/zombie-reaper/fly autostop vs no :3000 listener). This is a real prod data-loss class, currently open.
- **F3. QStash failure injection:** populate-dependencies / backfill-trees endpoints return 500s → verify retry semantics, idempotency, and no poison-message loop.
- **F4. DB blips mid-batch:** fail the PDV batched upsert partway → rerun must converge (upsert idempotency); silence-events flush must stay fail-soft (never blocks the scan).
- **F5. Resource exhaustion:** disk-full during clone; OOM during cdxgen/semgrep (already non-fatal — assert it stays so); per-step scan-timeout honored with partial results correctly finalized as degraded, never `ready`.
- **F6. Concurrency:** N simultaneous scans per machine size; claim_scan_job atomicity under contention (FOR UPDATE SKIP LOCKED race probe).

## WS-G — Scale & Performance

- **G1. Giant-repo tier:** 2–3 of the largest feasible OSS monorepos; a 30k-dep project (validates the R3 batched-upsert path at scale + step wall-time envelopes).
- **G2. Memory ceilings per step** on the standard Fly machine size; document the matrix (which repo size needs which machine).
- **G3. Step-timing regression alarms:** `[timing]`-style per-step durations already stream to extraction_logs — add a corpus-run report that flags >2x step regressions between images.

## WS-H — Prod-Parity & Deployment Gate

- **H1. Linux-parity run:** scan the full corpus on the actual Fly-built Linux image (not the local Windows-built one) → verdict diff vs local must be empty. (All loop validation so far ran locally.)
- **H2. Staged rollout:** merge PR → deploy → M2 cross-run differ on Deptex's own repos (backend/frontend) old-image-vs-new → 48h silence-event-log watch → then call it shipped. The M1/M2 instrumentation was built exactly for this.
- **H3. CI gates green as required checks:** dogfood:check, schema-check, taint suites, reachability jest, corpus:diff.

---

## Sequencing & exit criteria

| Phase | Workstreams | Exit criterion |
|---|---|---|
| 1 (highest leverage) | A1 labels · C5 corpus:diff tripwire · C1 Java/PHP 2nd-app | Labelled set ≥150 CVEs; diff tool wired; 5/5 models two-app validated |
| 2 | B1/B2 parser fuzz+differential · C2 negative controls · A2 corpus growth | 0 AST-vs-regex import gaps on corpus; 0 cross-framework moves; corpus ≥20 repos incl. GitLab/Bitbucket |
| 3 | F1–F6 chaos · E1–E5 scanner categories | Every injected fault detected + recovered; reaper flake fixed |
| 4 | G scale · H prod-parity + rollout | Linux parity clean; deployed behind the M2 watch |

**Standing rule:** any bug found at any phase gets (1) a deterministic minimal reproduction, (2) a fix, (3) a regression fixture, (4) a ledger entry — the loop discipline that caught gitea/openpgp and saleor/dev-toolbar.
