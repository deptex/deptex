# Depscanner Dogfood — Feature Brief

## Problem Statement

The depscanner has had two months of heavy engineering — reachability v3, DAST v2.1a/b/c/d, DAST HAR import, IaC v2 item G with SONAME bridge composition, malicious-packages v2, and per-ecosystem precision arcs. The code is in main. **Henry has not personally walked through the full "user creates a project" flow himself.** Before pushing this into v1 production-ready territory we need first-hand confidence that a stranger's first project will scan cleanly across all 8 languages × all 27 framework detectors × every scan category that auto-fires (SBOM, vulnerabilities, reachability, IaC, container, IaC↔code composition, malicious packages, Semgrep SAST, TruffleHog secrets) plus the opt-in DAST flow.

## Current State in Deptex

**The create-project flow exists and already does almost everything we need:**

- `POST /api/organizations/:id/projects` (`backend/src/routes/projects.ts:1057-1254`) inserts a project row — does NOT auto-scan.
- `POST /api/organizations/:id/projects/:projectId/repositories/connect` (`backend/src/routes/projects.ts:4250`) is what actually fires extraction via `queueExtractionJob()` (`backend/src/lib/extraction-jobs.ts:42-194`) → inserts `scan_jobs` row with `type='extraction'` → spawns Fly machine.
- Frontend entry: `CreateProjectSidebar` (`frontend/src/components/CreateProjectSidebar.tsx`) mounted from `OrganizationLayout`.
- Manual sync: `POST /api/organizations/:id/projects/:projectId/sync` (`backend/src/routes/projects.ts:11001-11081`), same path, 60s cooldown.
- Real-time progress: `extraction_logs` table + Supabase Realtime channel `extraction-logs-${projectId}` + `useExtractionLogs` hook + `InlineExtractionLogs` component.

**Extraction pipeline order** (`depscanner/src/pipeline.ts:4`):
```
clone → SBOM (cdxgen) → dep-scan vulns → OSV fallback → tree-sitter usage extraction
    → framework detection → taint engine (reachability) → iac_container_scan
    → malicious_scan → semgrep SAST → trufflehog secrets → finalize
```
Gated by `DEPTEX_SKIP_OPTIONAL_SCANS` for the optional-scan block. **DAST is a separate `scan_jobs.type` family** (`'dast'`, `'dast_zap'`, `'dast_nuclei'`, `'dast_zap_dry_run'`) — opt-in because it needs a live URL.

**Monorepo support** (`backend/database/add_package_json_path_to_project_repositories.sql`): one GitHub repo can back N projects, each pinned to a different sub-path via `package_json_path`. This is the mechanism we lean on to put all 27 fixtures in the deptex/deptex monorepo.

**Existing scanner test corpus** (`depscanner/fixtures/`, 16 fixtures): toy single-vuln-class repos used as scanner unit-test inputs with golden-JSON snapshots. **Different purpose from this dogfood arc** — they verify scanner internals on tiny inputs; the dogfood verifies the user-flow shape on real-shaped multi-category fixtures. Keep both, no merge.

**Framework detector inventory** (`backend/src/lib/ecosystems.ts:21-65`, `depscanner/src/tree-sitter-extractor/index.ts:37-46`):
- npm (8): nextjs, create-react-app, react, vue, nuxt, svelte, @angular/core, express
- pypi (4): django, fastapi, flask, scrapy
- maven (3): spring-boot, quarkus, android
- golang (3): gin-gonic, labstack/echo, gofiber
- cargo (3): actix, axum, rocket
- gem (2): rails, sinatra
- composer (3): laravel, symfony, wordpress
- nuget (1): Microsoft.AspNetCore

**What's missing:**
- No per-framework realistic-shaped fixture corpus that exercises ALL scan categories per fixture.
- No annotation-based verification primitive (we have golden-snapshot diffs for unit fixtures; nothing for "did the scanner find every seeded finding").
- No mechanism to deploy + DAST a fixture locally as part of the dogfood.

## Competitive Landscape

### Trivy (Aquasecurity)
- **Pattern:** ~37 fixture folders under `integration/testdata/fixtures/repo/`, one per package-manager ecosystem (npm, pip, cargo, gomod, pom, poetry, yarn, pnpm, composer, conan, cocoapods, nuget, gradle, terraform, helm, dockerfile, conda, etc.).
- **Verification:** Golden JSON snapshots in `integration/testdata/*.golden`. Diff = pass/fail.
- **Source:** github.com/aquasecurity/trivy.
- **Assessment:** Coarse layout pattern (folder-per-ecosystem) is right; golden-snapshot verification we already do for `depscanner/fixtures/`. Not stealing the verification primitive.

### Grype (Anchore)
- **Pattern:** Two layers — per-matcher `grype/matcher/<ecosystem>/testdata/` (~18 matchers, each colocated with the code that uses it), plus an end-to-end `test/integration/testdata/` driven by Go `_test.go` files with programmatic assertions against mock DBs.
- **Source:** github.com/anchore/grype.
- **Assessment:** Per-matcher colocation is a different concern than per-framework dogfood; not a fit. Programmatic Go assertions are equivalent to our snapshot-runner approach.

### semgrep-rules (Semgrep)
- **Pattern:** Organized `language/framework/category/<rule>.yaml` + sibling `<rule>.py/.js/.go/etc.` fixture. Inline `# ruleid:` annotation marks every line that MUST match; unannotated lines must NOT match. `# ok:` marks explicit negatives.
- **Source:** github.com/semgrep/semgrep-rules.
- **Assessment: highest-leverage idea worth stealing.** The annotation lives on the seeded line; harness diffs declared-vs-actual; fixtures self-document; no separate golden file to drift.

### Snyk / Endor / Socket
- All proprietary. No published per-framework fixture suite. Their first-scan UX is observable but not their internal regression matrix. Whitespace observation: **none of the big SCA vendors publish a documented per-framework e2e fixture suite.** A documented Deptex `test-repos/` with inline annotations is a real open-core / trust lever.

## Landscape Synthesis

- **Table-stakes:** Per-ecosystem scanner test fixtures with snapshot or programmatic assertions (Trivy, Grype). We already have this in `depscanner/fixtures/`.
- **Frontier:** Inline rule-id annotations 1:1 with fixture code (Semgrep). Lowest-maintenance verification primitive when fixtures evolve.
- **Whitespace:** A published, documented per-framework end-user fixture suite that exercises the full create-project flow + scan-category matrix. Not done by any major SCA vendor we could find. Open-core advantage.
- **Deptex position today:** Has the engine, has the unit-test fixtures, has the create-project flow. Doesn't have the end-user-flow regression corpus. This brief closes that.

**Feasibility verdict:** Low technical risk. Every primitive already exists (monorepo `package_json_path`, full extraction pipeline, real-time logs). The work is fixture-authoring + annotation parser + diff harness — no novel research.

**Top 3 risks:**

1. **Scope explosion.** 27 frameworks × 9 scan categories ≈ 240 verification cells. Hand-authoring 27 realistic-shaped repos with intentional findings in every category is ~3-5 days per fixture if done thoroughly. The "one mega-PR with all 27" decision is brave; /plan-feature should re-evaluate against actual per-fixture authoring cost and may want to phase it.
2. **Live VDB / OSV data fragility.** Per [[feedback_live_data_test_fragility]], the dep-scan VDB and live OSV API return different result sets in different environments. Strict 1:1 annotation match works if annotations are keyed by **specific CVE-IDs / semgrep-rule-IDs / file:line locations** (we verify the SPECIFIC finding is present), not by counts. Annotations must NOT be "expect N findings" or "expect any CVE."
3. **Intentionally-vulnerable repos and Aegis interaction.** Original concern was that Aegis / Fix Agent could auto-PR fixes onto fixtures. **Resolved (see Blocker Resolutions §1):** no exclusion mechanism needed — the fixtures will double as Aegis test material since Aegis isn't production-ready anyway. Risk consciously accepted.

## User Stories

- As **Henry**, I want to click "Create project" in the Deptex UI 27 times (one per framework), each time pointing at a different sub-path of `deptex/deptex`, and see a successful scan complete with every seeded finding correctly surfaced in the UI, so that I'm confident a real new user's first project will not fail.
- As **a new Deptex user**, I want my first project to clone, scan, and surface findings without weird worker crashes or missing-category gaps, regardless of which framework my app uses.
- As **a contributor**, I want a documented per-framework fixture corpus with inline expectation annotations so I can verify any depscanner change I make against the full matrix locally.

## Locked Scope Decisions

1. **Goal: 99% "first scan works" confidence across all 27 framework detectors.** *Reason: this is the v1-production gate — no marketing or scaling work happens until the per-framework happy path is solid.*

2. **All 27 framework detectors in scope.** *Reason: Henry explicitly overrode the "top 10 only" recommendation. Long-tail frameworks (scrapy, quarkus, nuxt, svelte, etc.) are part of v1.*

3. **Verification primitive: inline `# deptex:` annotations on seeded lines.** *Reason: Semgrep's `# ruleid:` pattern is the highest-leverage primitive in the comparable-OSS landscape. Lowest maintenance cost when fixtures evolve, fixtures self-document, no separate golden file to drift.*

4. **Annotations are keyed by SPECIFIC IDs (CVE-ID, semgrep-rule-ID, malicious-package name, secret-type), not by counts.** *Reason: live VDB/OSV data fragility per [[feedback_live_data_test_fragility]]. Counting CVEs is fragile across environments; checking "CVE-X specifically appears at file:line Y" is stable.*

5. **Strict 1:1 pass threshold.** Every annotation must match a finding AND every finding must have an annotation. Hard fail on mismatch. *Reason: forces annotations + scanner output into lock-step. Loose thresholds let regressions hide.*

6. **Pass requires both automated 27/27 strict pass AND Henry's manual UI walkthrough of all 27.** *Reason: automated harness catches finding-level regressions; manual walkthrough catches UX bugs (loading states, empty states, log streaming behavior) the automated harness misses.*

7. **All scan categories that auto-fire on project creation are in scope.** SBOM, vulnerabilities, reachability, IaC (Checkov), container (Trivy), IaC↔code composition, malicious-packages, Semgrep SAST, TruffleHog secrets. *Reason: every scan category that fires for a real user must fire for the dogfood.*

8. **DAST is exercised by locally deploying each runnable fixture + triggering a DAST scan against the running URL.** Pure-frontend / mobile frameworks (react, vue, svelte, angular, create-react-app, android) and non-server frameworks (scrapy) have no DAST cell in the matrix. *Reason: DAST inherently needs a live target; replicating real user flow means actually deploying the app.*

9. **Pure-frontend frameworks ship a stub deployable shell** — minimal nginx/node Dockerfile + minimal k8s manifest — with intentional IaC misconfigs seeded into those stubs. *Reason: every real-world SPA gets deployed behind some server, so the stub is realistic, not synthetic. Lets IaC + container categories have something to find.*

10. **Test repos live at `depscanner/test-repos/<framework>/` in the `deptex/deptex` monorepo.** *Reason: Henry's explicit preference for maintenance simplicity, and we can leverage the existing `package_json_path` monorepo feature so no mirror script is needed.*

11. **27 separate Deptex projects, all backed by `github.com/deptex/deptex`, each with `package_json_path` pointed at one fixture's sub-path.** *Reason: leverages existing monorepo support, exercises real clone-from-GitHub flow, no mirror script needed.*

12. **Per-fixture seed matrix: minimum 1 of each category** (1 reachable vuln, 1 unreachable vuln, 1 IaC misconfig, 1 container CVE, 1 TruffleHog-detectable secret, 1 malicious-package pattern, 1 Semgrep SAST finding). More where natural for the framework. *Reason: enforces full-matrix coverage without forcing comprehensive vuln-class explosion. Realistic-shape over exhaustive.*

13. **Existing `depscanner/fixtures/` stays untouched** as the scanner unit-test corpus. NEW `depscanner/test-repos/` is the dogfood corpus. *Reason: different purposes (unit-test vs end-user-flow), different scopes, different verification primitives.*

14. **One mega-PR with all 27.** *Reason: Henry's explicit pick. /plan-feature will need to re-evaluate against actual authoring cost — flagged as a risk above.*

15. **Manual walkthrough is v1; automated harness is v2.** *Reason: v1 catches UX bugs the harness would miss. Don't gate v1 on harness work; v2 stacks on top.*

## Data Model

No new tables required if intentionally-vulnerable repos can be excluded from Aegis / Fix / PR-blocking via existing settings. **Open question (blocker for /plan-feature):** does such a flag exist today, or do we need a new `projects.is_test_fixture BOOLEAN DEFAULT FALSE` column + propagation through Aegis/Fix entry points?

Possible new artifacts (no new tables):
- `depscanner/test-repos/<framework>/` directories — 27 of them
- `depscanner/test-repos/<framework>/.deptex/expected.yaml` (or similar) — sidecar manifest listing CVE IDs / semgrep rule IDs / malicious-package names / secret types expected (cross-reference for annotations)
- `depscanner/test-repos/<framework>/.deptex/deploy.sh` (where applicable) — script that brings the fixture up locally for DAST
- Annotations live inline as comments in the source: `# deptex: CVE-2024-XXXX reachable` on the vulnerable-import line, `// deptex: ok` on safe-but-similar lines (Semgrep pattern), etc.

## API Endpoints

No new API endpoints required. Dogfood uses existing:
- `POST /api/organizations/:id/projects/:projectId/repositories/connect` to wire each fixture as a project.
- `POST /api/organizations/:id/projects/:projectId/sync` for re-runs.
- `POST /api/dast/...` (existing DAST routes) for the deploy-then-DAST phase.
- `GET /api/projects/:projectId/vulnerabilities` (or whatever the findings endpoint is) for the verification diff in v2 automated harness.

## Frontend Surface

No new pages. The dogfood EXERCISES existing surfaces — Henry walks each scan in the browser using the existing UI to confirm:
- Project create sidebar works for sub-path projects
- Extraction log stream renders in real time
- Findings appear correctly in the Findings tab (whatever name lands after [[org_security_tab_state]])
- Reachability badges + sanitizer chain + per-flow suppress all behave
- IaC/container/malicious-package/secret tabs surface their categories
- DAST results land where expected

**Implicit dependency:** the Findings tab work in `worktree-org-security-tab` (uncommitted) directly affects the UI surface that the manual walkthrough exercises. **Decide whether to commit/wipe that worktree BEFORE starting the dogfood**, or accept that the walkthrough validates whatever's on main at the time.

## User Flows

### Per-fixture flow (manual, v1)

1. Henry creates fixture `<framework>` at `depscanner/test-repos/<framework>/` with all 7 categories seeded + inline annotations + (if web-server) `.deptex/deploy.sh`.
2. Henry pushes the fixture to a branch in `deptex/deptex` (or directly to main once stable).
3. Henry opens Deptex, clicks "Create project", picks the deptex/deptex repo connection, sets `package_json_path` to `depscanner/test-repos/<framework>/`.
4. Henry watches `InlineExtractionLogs` stream the scan.
5. Once scan completes, Henry walks the project's Findings tab + IaC tab + container tab + secrets tab + Semgrep tab + reachability flows.
6. Henry runs (or scripts) `depscanner/test-repos/<framework>/.deptex/deploy.sh` to bring the app up locally (where applicable).
7. Henry triggers a DAST scan against the local URL.
8. Henry checks every annotation in the fixture is matched by a finding in the UI, AND no extra findings exist that aren't annotated.
9. Repeat for next framework.

### Per-fixture flow (automated, v2 — out of scope this brief)

`npm run dogfood:<framework>` programmatically creates the project via API, polls until scan completes, fetches findings, parses fixture annotations, diffs declared-vs-actual, reports pass/fail. v2 brief gets written after v1 ships.

## Edge Cases & Failure-Mode Policy

- **Scan times out / crashes on a fixture.** Hard fail for that fixture. Captured as a bug to fix BEFORE the dogfood is declared done. Do not paper over with retries.
- **VDB cold-start gives different CVE counts than expected.** Annotations are CVE-ID-specific, so missing CVE-X is a real failure, not drift noise. If the production Fly worker's persistent VDB is reliably warm (per `3952cd8`), this should not happen — and if it does, it IS the kind of bug we want to find.
- **Aegis Fix Agent or PR-blocking flow accidentally fires on fixture findings.** Hard policy: must be disabled for fixture projects before the dogfood starts. Mechanism (flag / dedicated org / role-based exclusion) decided at /plan-feature time.
- **Existing `worktree-org-security-tab` uncommitted polish.** Decide BEFORE dogfood starts: commit those changes, wipe them, or accept walkthrough validates current main. Don't let it linger and contaminate the dogfood's UI verification.
- **Fly worker scale-to-zero startup time.** First scan of the dogfood will pay cold-start cost (~30-60s). Acknowledged in advance, not a bug.
- **`depscanner/test-repos/` lockfiles bloat the deptex/deptex monorepo.** 27 fixtures × full lockfiles (node_modules-equivalent metadata, NOT installed) could be ~500KB-2MB per fixture. Total +20-50MB on the repo. Acceptable.

## Non-Functional Requirements

- **Per-scan duration:** depends on framework + repo size; reachability + cdxgen are the long poles. Expectation: 2-10 minutes per fixture for the extraction bundle, plus 5-15 minutes for DAST where applicable.
- **Total dogfood walkthrough time:** 27 × ~15 minutes = ~7 hours of wall-clock if done back-to-back. More realistic: 1-2 frameworks per day across 2-3 weeks if Henry's also doing other things.
- **AI cost:** EPD + AI rule generation may fire per scan. Production cost caps already in place (org-level via `getPlatformKeyForProvider()`). Expect ~$0.10-0.50 AI spend per fixture if AI augmentation triggers; potentially $5-15 total across the dogfood.
- **No CI-suitability requirement for v1.** Per [[feedback_live_data_test_fragility]], the dogfood is local-and-production-Fly-only. v2 automated harness will need to decide whether to ship CI integration, with the warm-VDB caveat in mind.

## RBAC Requirements

No new permissions. Dogfood operations use existing:
- `manage_teams_and_projects` to create the 27 projects.
- Standard read permissions to view findings during walkthrough.
- DAST trigger permission (whatever DAST routes require today).
- Aegis disablement on fixture projects (whatever permission gates Aegis settings).

## Dependencies

- ✅ Create-project + repo-connect flow (shipped).
- ✅ `package_json_path` monorepo support (`backend/database/add_package_json_path_to_project_repositories.sql`).
- ✅ Full extraction pipeline including IaC + container + composition (shipped via PRs #42, #45, #46, #50).
- ✅ DAST v2.1d with recorded login (shipped via PR #47).
- ✅ DAST HAR import (shipped via PR #52, main `b8b3162`).
- ✅ Persistent Fly VDB cache (shipped via `3952cd8`).
- ⚠️ Findings tab UI (in flight on uncommitted `worktree-org-security-tab` — Henry must decide whether to commit/wipe before dogfood starts).
- ❓ Mechanism to exclude fixture projects from Aegis / Fix / PR-blocking flows (open question — does this exist? probably not).

## Success Criteria

The dogfood is "done" when ALL of the following hold:

1. All 27 fixtures live in `depscanner/test-repos/<framework>/` with inline `# deptex:` annotations.
2. All 27 fixtures have been connected as Deptex projects against the real production Deptex instance.
3. All 27 scans complete successfully (no worker crashes, no scan timeouts, no missing-step failures).
4. For each fixture, every inline annotation matches an actual finding in the Findings UI.
5. For each fixture, no actual finding exists in the UI that lacks a corresponding annotation.
6. For each runnable web fixture (~21 of the 27), a DAST scan has been triggered against the locally-deployed app and produces the seeded DAST findings.
7. Henry has personally walked through the UI for all 27 fixtures.
8. The full create-project → scan → findings-display flow has zero "wait what is this" UX bugs in Henry's walkthrough.

## Blocker Resolutions (settled before /plan-feature)

1. **Aegis / Fix Agent / PR-blocking exclusion → NOT NEEDED.** Henry: Aegis isn't production-ready anyway; the dogfood fixtures will double as Aegis test material. No `is_test_fixture` flag, no exclusion mechanism. Aegis is allowed to see, suggest fixes for, and even attempt PRs against the intentionally-vulnerable fixtures — that's a feature for testing Aegis, not a bug.

2. **Target instance → prod Deptex org, in a dedicated team named "Vulnerable projects" (or similar).** Realistic flow, no separate-org setup overhead, and the team boundary keeps the 27 fixture projects visually grouped + easy to filter out of any org-wide dashboards.

3. **`worktree-org-security-tab` uncommitted polish → Henry commits it himself in that worktree BEFORE this arc continues.** Once committed, the dogfood walks whatever's on main (will include that polish). Not this arc's responsibility.

## Open Questions

1. **(can defer to /implement)** — Where exactly does each fixture's `.deptex/expected.yaml` and `deploy.sh` live? Naming convention TBD.

2. **(can defer to /implement)** — Mega-PR is locked. /plan-feature should still re-test that against fixture-authoring cost estimates per framework and surface phasing as a counter-proposal if the numbers demand it (rather than silently deviating).

3. **(informational)** — Pure-frontend stub Dockerfiles — do we want them based on the most common real-world deploy pattern per framework (nginx for React/Vue, Next.js standalone, etc.) or a generic node-serve container? /plan-feature can decide.

4. **(informational)** — Does `cdxgen` + `dep-scan` + Checkov + Trivy + Semgrep + TruffleHog all correctly honor the `package_json_path` sub-path, or do any of them scan from repo root regardless? Needs verification at /implement time.

## Recommended Next Step

Resolve **open questions 1-3 (blockers)** with Henry, then run `/plan-feature depscanner-dogfood` to get an implementation plan. /plan-feature should:
- Re-test the "one mega-PR" decision against per-framework authoring cost estimates.
- Specify the per-fixture file layout (annotations, expected.yaml, deploy.sh).
- Design the dogfood-protection mechanism (Aegis exclusion).
- Map each of the 27 frameworks to a starter `npm/composer/cargo/etc. init` recipe so authoring is mechanical.
- Define the manual-walkthrough checklist that Henry actually uses per fixture.
