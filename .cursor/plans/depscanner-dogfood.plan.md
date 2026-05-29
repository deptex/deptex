# Depscanner Dogfood — Implementation Plan

> **Revision 3 (2026-05-22)** — applies the 8 patches (A, B, C, D, E, F, G, I) from `.cursor/plans/review-depscanner-dogfood.md` Rev-2 review (verdict REVISE, 1 READY / 4 REVISE / 1 REWORK). Headline changes from Rev 2: dropped `exclude_from_org_rollups` column entirely (use dedicated test org instead — vaporizes 3 P0s), copy-not-extend (no snapshot-test pollution), dropped inline annotations (expected.yaml is sole source of truth), harness ships in M1 not M6 (executable cross-batch gate from day one), added harness self-tests + negative-path demo, DAST baseline HAR capture per server-side fixture, locked service-role auth for harness.

> **Revision 3.1 (2026-05-22, pre-implement correction)** — Isolation mechanism corrected back to the original `/brainstorm` blocker resolution: fixtures live in the existing **`deptex` prod org** under a dedicated **`Vulnerable Projects` team**, NOT in a separate `deptex-dogfood` org. (Rev-2 Patch A's "dedicated org" framing was a drift from the locked scope decision.) No structural plan changes; only the prereq + the runbook navigation step + the success-criteria phrasing change. All other Rev-3 decisions stand.

## Overview

Hand-author **13 framework fixtures** as standalone copies at `depscanner/test-repos/<framework>/` (9 of them copied from an existing `depscanner/fixtures/test-*` directory as starting point; originals stay byte-stable), wire each as a separate Deptex project via `package_json_path` sub-paths inside a new **`Vulnerable Projects` team in the existing `deptex` prod org**, and walk every scan end-to-end through the prod UI to confirm v1 production-readiness of the create-project + scan + findings flow. Verification uses `.deptex/expected.yaml` per fixture (alias-aware, bucket/subset match) consumed by a `npm run dogfood:check` diff harness that ships **in M1** as the executable regression gate across all subsequent ecosystem batches.

**Phased shipping, 6 PRs total** (M1 foundation+express+harness + M2-M5 ecosystem batches with cumulative harness gating + M6 sign-off+DAST baselines). Realistic timeline: ~2.5-3 weeks of work.

**v1b backlog** (deferred): 14 framework-detector fixtures with extraction-only verification — react/vue/svelte/angular/create-react-app/nuxt/quarkus/android/echo/gofiber/actix/rocket/symfony/wordpress/sinatra/scrapy. Pulled out of v1 because they're intra-ecosystem siblings exercising the same scanner code paths as their v1a sibling.

## What changed from Revision 2 (for review-fixers and future-me)

| Patch | Source | What's different in Rev 3 |
|---|---|---|
| A — Drop `exclude_from_org_rollups` | pragmatist-r2-f2 + scope-cutter-r1-f3 (independent) | Phase37 migration, new column, Settings checkbox, rollup-query filter sites, schema:dump refresh — all **STRUCK**. Vaporizes skeptic-f1 (missing PATCH endpoint), skeptic-f2 + architect-r2-f2 (rollup-isolation mis-framed), test-strategy-auditor-f4 (no filter test). **Rev 3.1 correction:** isolation via a new **`Vulnerable Projects` team inside the existing `deptex` prod org**, NOT a separate org — Henry creates the team manually before M1. |
| B — Copy not extend | architect-r2-f1 | Each `depscanner/test-repos/<framework>/` is a **standalone copy** of the matching `depscanner/fixtures/test-*` (where applicable). Originals untouched, snapshot tests unaffected. `.deptex/SOURCE.md` per fixture records upstream SHA for traceability. |
| C — Re-size M1 | skeptic-f3 | M1 dropped phase37/UI/filter work per Patch A. New M1 = foundation + express + minimum harness, sized [M-L] 4-6 days with gate at >6 days. |
| D — Drop inline annotations | skeptic-f7 + pragmatist-r2-f1 (rev-1 carry-over) | `expected.yaml` is sole source of truth. No `# deptex:` inline annotations. CONVENTIONS.md no longer has per-language comment syntax matrix. Source files in fixtures are unannotated realistic code. |
| E — Harness self-tests + negative-path demo | skeptic-f5 + test-strategy-auditor-f1 + test-strategy-auditor-f6 | M1.7 includes vitest unit tests for `dogfood-check.ts` (mutation cases: drop osv_id → FAIL; alias substitution → PASS; bucket boundaries; subset semantics). M1.9 includes negative-path demo in PR description. |
| F — Harness ships in M1 | test-strategy-auditor-f2 | Harness is part of M1, not deferred to M6. M2-M5 cross-batch gate is `npm run dogfood:check` (executable), not "Henry re-syncs via UI." |
| G — Lock copy + service-role auth | architect-r2-f3 + architect-r2-f4 | Copy (not symlink — Windows portability). Harness uses Supabase service-role direct query (not user JWT). Documented tradeoff: M1.7 walkthrough validates API surface manually. |
| I — DAST baseline HAR | test-strategy-auditor-f3 | Per server-side fixture: capture `.deptex/dast-baseline.har` after first successful DAST scan via the HAR-import feature (PR #52). Harness re-imports HAR for verification without re-deploying. ~15-30 min per server-side fixture. |
| (carry-over from Rev 2) | various | M0 deleted (architect-r1-f1). Scope 27→13 (pragmatist-r1-f1). Bucket/subset match (skeptic-r1-f2). M1.5.5 seed-probe (test-strategy-auditor-r1-f4). Alias-aware annotations + M6 OSV refresh (test-strategy-auditor-r1-f6). RESULTS.md not per-fixture walkthrough.md (pragmatist-r1-f3 / scope-cutter-r1-f5). sync_frequency=manual + dependabot exclusion + historical-malicious-pkg names. |

## Competitive Research & Design Rationale

(Brief documented the landscape — Trivy folder-per-ecosystem + golden JSON, Grype per-matcher + Go assertions, Semgrep 1:1 fixture/rule + inline `# ruleid:`.)

1. **`expected.yaml` as sole source of truth** (NOT inline annotations — see Patch D). A single structured YAML per fixture is what the harness consumes; source files stay clean and realistic. v2 can introduce inline annotations when an annotation parser ships and there's a real consumer.
2. **Standalone copies, not extensions** (Patch B). Reuses the *intent* of `depscanner/fixtures/test-*` (the taint-engine source) but as a starting point for an independent copy, so the originals stay byte-stable and existing snapshot tests don't break.

**Open-core differentiation:** no major SCA vendor publishes a documented per-framework e2e fixture suite. Shipping `depscanner/test-repos/` + the annotation convention + the `npm run dogfood:check` harness is a credible trust/transparency lever post-v1.

## Codebase Analysis

### Verified at probe time

- `package_json_path` flows: `project_repositories.package_json_path` → worker job payload → `runPipeline()` → `ExtractionJob.package_json_path` → `ctx.workspaceRoot` at `depscanner/src/pipeline-steps/clone.ts:81`.
- **All 9 scanners honor `workspaceRoot` correctly** (orchestrator wires it through). Checkov + Trivy receive sub-path values; the `repoPath` param is semantically `workspaceRoot`, just misnamed. No scanner code change needed for the dogfood.
- A 30-min cosmetic rename of `repoPath` → `scanRoot` is *nice-to-have* hygiene; tracked in v1b backlog.
- DAST is URL-centric — each fixture's DAST flow is its own target URL.
- **No `is_test_fixture` flag** exists. Per Henry's blocker resolution: not needed; Aegis allowed to see fixtures.
- **No org-rollup-exclusion mechanism** exists, and the plan no longer needs one (Patch A — dedicated test org isolates).

### Existing-feature precedents

- **Copy strategy:** standalone copy of `depscanner/fixtures/test-*` per fixture into `depscanner/test-repos/<framework>/`. Originals never modified.
- **Deploy-then-DAST runbook:** `docs/runbooks/dast-har-import-dogfood.md` from PR #52. Same shape: per-target deploy script + HAR capture.
- **HAR baseline pattern:** Per PR #52, DAST can replay against a recorded HAR. Use this for the v1 DAST baseline (Patch I).

### Files that will be created vs modified

**Created:**
- `depscanner/test-repos/` — top-level directory + README + RESULTS.md
- `depscanner/test-repos/<framework>/` — 13 framework folders
- `depscanner/test-repos/<framework>/.deptex/expected.yaml` per fixture (alias-aware)
- `depscanner/test-repos/<framework>/.deptex/deploy.sh` per server-side fixture
- `depscanner/test-repos/<framework>/.deptex/dast-baseline.har` per server-side fixture (M6 / per-batch capture)
- `depscanner/test-repos/<framework>/.deptex/SOURCE.md` per fixture (upstream taint-engine fixture SHA for traceability)
- `docs/runbooks/depscanner-dogfood.md` — top-level runbook
- `depscanner/bin/dogfood-check.ts` — diff harness (M1)
- `depscanner/bin/__tests__/dogfood-check.test.ts` — harness self-tests (M1)
- `depscanner/README.md` (if not present) — explains the four-corpus map (unit toy / dogfood / per-CVE rule / external benchmark)
- `.github/dependabot.yml` — exclude `depscanner/test-repos/**`

**Modified:**
- `depscanner/package.json` — add `dogfood:check` script
- `CLAUDE.md` — short section pointing at the dogfood corpus

**NOT modified:**
- No scanner code (Checkov / Trivy / etc. — already correct)
- No backend routes (no PATCH endpoint needed)
- No database migrations (no `exclude_from_org_rollups` column per Patch A)
- No frontend code (no Settings checkbox)
- No new RBAC permissions
- No new env vars (harness uses existing `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY`)
- **Existing `depscanner/fixtures/test-*` directories STAY BYTE-STABLE** — Patch B critical invariant. Verified before AND after M1 with `npm run snapshot -- --include-slow`.

## Data Model

**No schema changes.** Patch A drops the `exclude_from_org_rollups` column entirely.

Isolation mechanism: a **new `Vulnerable Projects` team inside the existing `deptex` prod org** that Henry creates before M1 walkthrough. All 13 fixture projects live in that team; project membership filters keep them out of unrelated team views. The org's all-projects rollup will see them — accepted tradeoff: these fixtures are real seeded vulns the team should see anyway, and avoiding the separate-org route is per Henry's `/brainstorm` locked decision.

## API Design

**No new endpoints.** Existing routes only:

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/organizations/:id/projects` | Create each fixture's project row (in `deptex` org → `Vulnerable Projects` team) |
| `POST` | `/api/organizations/:id/projects/:projectId/repositories/connect` | Wire each project to `deptex/deptex` with `package_json_path` sub-path |
| `PATCH` | `/api/organizations/:id/projects/:projectId/repositories/settings` | Set `sync_frequency=manual` (existing endpoint) |
| Existing DAST routes | per `backend/src/routes/dast/*` | Per-fixture DAST trigger + HAR import |
| Existing findings endpoints | per `backend/src/routes/scanner-findings.ts` | Read findings during walkthrough |

Harness uses **service-role direct Supabase query** (Patch G), bypassing the HTTP API — the M1.7 walkthrough is what validates the API surface manually.

## Frontend Design

**No frontend changes.** The dogfood EXERCISES existing surfaces:

- `CreateProjectSidebar` (`frontend/src/components/CreateProjectSidebar.tsx`) — used 13 times in `deptex` org → `Vulnerable Projects` team
- `InlineExtractionLogs` + `useExtractionLogs` — verified streaming each scan
- Findings tab on `OrganizationFindingsPage.tsx` (main `cdd2410`, PR #55) — walked per-fixture
- IaC + container + secrets + Semgrep + malicious tabs — verified to surface seeded categories
- DAST UI (post-HAR-import merge, PR #52) — used per server-side fixture

## Implementation Tasks

### M1 — Foundation + express + harness

Complexity: **M-L** (~4-6 days). Ships as first PR. Gate at >6 days: re-plan M2-M5 estimates.

1. **[S] M1.1 — `depscanner/test-repos/README.md`.** One paragraph: what the corpus is, four-corpus map (unit toy in `fixtures/`, dogfood here, per-CVE rule fixtures in `reachability-rules/`, external benchmark), pointer to `docs/runbooks/depscanner-dogfood.md` for the per-fixture walkthrough.
2. **[S] M1.2 — `docs/runbooks/depscanner-dogfood.md`.** The runbook Henry follows per fixture: (a) confirm fixture exists at `depscanner/test-repos/<framework>/`, (b) in Deptex UI, navigate to `deptex` org → `Vulnerable Projects` team, create project, connect to `deptex/deptex` repo with `package_json_path` set to fixture path, (c) set sync_frequency=manual on the connected repo, (d) wait for scan, (e) walk per-tab UI checklist (Findings, IaC, container, secrets, Semgrep, malicious), (f) if server-side fixture, run `.deptex/deploy.sh` + trigger DAST + capture HAR via the DAST UI's HAR export, save as `.deptex/dast-baseline.har`, (g) run `npm run dogfood:check --fixture <name>` to verify, (h) fill RESULTS.md row.
3. **[S] M1.3 — `depscanner/test-repos/RESULTS.md`.** Top-level table: framework | scan_passed | harness_passed | findings_matched | dast_har_captured | bugs_found | walkthrough_date | notes.
4. **[S] M1.4 — `expected.yaml` schema documentation** (inline in runbook):
   ```yaml
   reachable_vulns:
     - osv_id: CVE-2021-23337
       aliases: [GHSA-35jh-r3h4-6jhm]
       file: server.js
       line: 12
       reachability_bucket: reachable  # accepts {confirmed, data_flow, function}
   unreachable_vulns:
     - osv_id: CVE-2020-28500
       aliases: [GHSA-29mw-wpgm-hmr9]
       reachability_bucket: unreachable  # accepts {module, unreachable}
   iac_findings:
     - rule_id: CKV_DOCKER_3
       file: Dockerfile
       line: 5
   container_cves:
     - osv_id: CVE-XXXX-YYYY
       aliases: [GHSA-...]
       base_image: node:14.0
   secrets:
     - rule_id: aws-secret-key
       file: .env.example
       line: 3
   malicious_pkg:
     - package: <historical-malicious-name>
       ecosystem: npm
       note: historical-not-published — see .github/dependabot.yml exclusion
   semgrep_findings:
     - rule_id: javascript.express.security.injection.tainted-sql-string
       file: routes/api.js
       line: 18
   dast_findings:  # only if deploy.sh exists
     - alert: Reflected XSS
       url_pattern: /search?q=
   ```
   Allow-incidental-extras semantics: harness only fails on missing expected findings, not on unexpected ones. Extras get categorized in RESULTS.md as add-annotation or false-positive-backlog.
5. **[S] M1.5 — Seed-probe pre-check.** Throwaway script: create minimal repo with ONE seed per scanner (lodash@4.17.20 reachable, USER root Dockerfile, vulnerable base image, fake AWS key in `.env.example`, historical-malicious npm package, SQL-concat in JS). Run through depscanner CLI locally AND once via the prod create-project flow against `deptex` org → `Vulnerable Projects` team. Confirm each scanner emits its expected finding in BOTH environments. If any seed fails, fix BEFORE M1.6.
6. **[L] M1.6 — Build `depscanner/test-repos/express/`.** Greenfield reference fixture (no existing express in `depscanner/fixtures/`). Structure:
   ```
   depscanner/test-repos/express/
   ├── README.md                 # what's seeded + why
   ├── package.json              # lodash@4.17.20 + 1 unreachable vuln dep + 1 historical-malicious dep
   ├── package-lock.json
   ├── server.js                 # entry: reachable + Semgrep + secret refs
   ├── routes/api.js             # more taint sources/sinks
   ├── Dockerfile                # vulnerable base + IaC misconfigs
   ├── k8s.yaml                  # IaC misconfigs
   ├── .env.example              # seeded AWS test key
   └── .deptex/
       ├── expected.yaml         # populated from seed-probe data + OSV alias query
       ├── deploy.sh             # docker-compose up; port 4001
       └── SOURCE.md             # "greenfield — no upstream taint-engine fixture"
   ```
   No inline `# deptex:` annotations (Patch D). expected.yaml is the canonical source.
7. **[M] M1.7 — Build the harness `depscanner/bin/dogfood-check.ts` + self-tests.**
   - CLI args: `--fixture <name>` (required) + `--project-id <uuid>` (required from env or arg)
   - Auth: `createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)` — direct DB query, no API round-trip (Patch G)
   - Walks `depscanner/test-repos/<framework>/.deptex/expected.yaml`
   - Hits Supabase tables directly: `project_dependency_vulnerabilities`, `project_secret_findings`, `project_semgrep_findings`, `project_iac_findings`, `project_container_findings`, `project_malicious_findings`, `dast_findings`
   - Diff: every expected `osv_id` (or any of its `aliases`) must appear; every expected `rule_id` / `secret_id` / IaC misconfig must be present; `reachability_bucket` is matched against the actual reachability level via the {confirmed,data_flow,function} vs {module,unreachable} buckets
   - Print PASS/FAIL per fixture + per-category breakdown + exit non-zero on FAIL
   - **Self-tests** (`depscanner/bin/__tests__/dogfood-check.test.ts`, vitest, Patch E):
     - (a) golden expected.yaml + matching findings → PASS
     - (b) drop a required osv_id from findings → FAIL with helpful diff
     - (c) replace osv_id with a known alias from `aliases:` → PASS
     - (d) replace osv_id with unrelated CVE → FAIL
     - (e) bump reachability from `confirmed` to `module` when bucket is `reachable` → FAIL
     - (f) bump from `confirmed` to `data_flow` when bucket is `reachable` → PASS
     - (g) add extras to findings → PASS (subset semantics)
     - (h) malformed YAML → exit non-zero with parse error
8. **[M] M1.8 — Henry's pattern-test walkthrough on express + capture DAST HAR.** Walk via runbook end-to-end. Iterate seeds + expected.yaml until `npm run dogfood:check --fixture express --project-id <uuid>` returns PASS. Capture DAST baseline HAR. Categorize bugs encountered: (a) seed bugs (express-specific), (b) PATTERN bugs (corpus convention needs fixing — update runbook + CONVENTIONS-equivalent section).
9. **[S] M1.9 — Negative-path demo + dependabot exclusion + ship M1 PR.**
   - Negative-path demo: temporarily remove an annotation from express's expected.yaml on a scratch branch, run harness, paste FAIL output in M1 PR description, revert
   - Add `.github/dependabot.yml` exclusion for `depscanner/test-repos/**`
   - Wire `dogfood:check` in `depscanner/package.json`
   - Conventional commit: `feat(test-repos): foundation + express reference + dogfood-check harness`

**Gate after M1:** Use express's actual per-category authoring time to re-baseline M2-M5 estimates. If express took >6 days, surface to Henry and decide whether to scope down v1a further before continuing.

### M2 — npm batch (nextjs + react)

Complexity: **M** (~3-4 days). Two fixtures: nextjs copies from existing taint-engine fixture; react is greenfield SPA.

1. **[S] M2.1 — Copy `depscanner/fixtures/test-nextjs-server-action-xss/` → `depscanner/test-repos/nextjs/`.** Add Dockerfile + k8s.yaml + `.env.example` + `.deptex/expected.yaml` (populated by inspecting the upstream fixture's taint-engine reachable flows + adding the seed-probe categories). `.deptex/SOURCE.md` records upstream commit SHA. **The original `depscanner/fixtures/test-nextjs-server-action-xss/` is untouched.**
2. **[M] M2.2 — Build `depscanner/test-repos/react/`.** Greenfield SPA reference. nginx-stub Dockerfile + minimal k8s.yaml + intentional IaC misconfigs. No DAST cell (pure-frontend, no server). All other categories covered. SOURCE.md notes "greenfield SPA reference."
3. **[S] M2.3 — Walkthrough + harness gate.** Walk each via runbook. Run `npm run dogfood:check --fixture nextjs` + `--fixture react`. Both must PASS. Also re-run express's check to confirm M1 still passes.
4. **[S] M2.4 — Capture DAST baseline HAR for nextjs** (SSR has a server). React has no DAST cell.
5. **[S] M2.5 — Snapshot stability verification.** Run `npm run snapshot -- --include-slow` before AND after M2. Zero unexpected diffs (Patch B invariant — proves the originals are still byte-stable).
6. **[S] M2.6 — Ship M2 PR.** `feat(test-repos): nextjs and react dogfood fixtures`.

### M3 — pypi batch (django + fastapi + flask)

Complexity: **M** (~2-3 days). All three copy from existing taint-engine fixtures.

1. **[S] M3.1 — Copy `test-django-xss-pypi/` → `test-repos/django/`** + layer dogfood categories.
2. **[S] M3.2 — Copy `test-fastapi-sqli-pypi/` → `test-repos/fastapi/`** + layer dogfood categories.
3. **[S] M3.3 — Copy `test-flask-traversal-pypi/` → `test-repos/flask/`** + layer dogfood categories.
4. **[S] M3.4 — Walkthroughs + harness gate.** `npm run dogfood:check` against all 5 fixtures so far (express, nextjs, react, django, fastapi, flask) — must be 6/6 PASS. The harness is the cross-batch gate, not Henry's manual re-sync.
5. **[S] M3.5 — Capture DAST baseline HARs** for all three (all have servers).
6. **[S] M3.6 — Snapshot stability verification.**
7. **[S] M3.7 — Ship M3 PR.** `feat(test-repos): pypi framework dogfood fixtures`.

### M4 — maven + golang + cargo batch (spring-boot + gin-gonic + axum)

Complexity: **M** (~2-3 days). All three copy from existing taint-engine fixtures.

1. **[S] M4.1 — Copy `test-spring-petclinic-maven/` → `test-repos/spring-boot/`**.
2. **[S] M4.2 — Copy `test-gin-cmdi-go/` → `test-repos/gin-gonic/`**.
3. **[S] M4.3 — Copy `test-rust-axum-traversal/` → `test-repos/axum/`**.
4. **[S] M4.4 — Walkthroughs + harness gate** against all 9 fixtures so far.
5. **[S] M4.5 — Capture DAST baseline HARs.**
6. **[S] M4.6 — Snapshot stability verification.**
7. **[S] M4.7 — Ship M4 PR.** `feat(test-repos): maven, golang, and cargo dogfood fixtures`.

### M5 — gem + composer + nuget batch (rails + laravel + aspnet)

Complexity: **M** (~3-4 days). rails is greenfield (no existing gem fixture); laravel + aspnet copy from existing.

1. **[M] M5.1 — Build `depscanner/test-repos/rails/`.** Greenfield Rails app skeleton with multi-category seeded findings. SOURCE.md notes "greenfield — no upstream taint-engine gem fixture."
2. **[S] M5.2 — Copy `test-laravel-sqli-php/` → `test-repos/laravel/`**.
3. **[S] M5.3 — Copy `test-csharp-aspnet-sqli/` → `test-repos/aspnet/`**.
4. **[S] M5.4 — Walkthroughs + harness gate** against all 12 fixtures so far.
5. **[S] M5.5 — Capture DAST baseline HARs.**
6. **[S] M5.6 — Snapshot stability verification.**
7. **[S] M5.7 — Ship M5 PR.** `feat(test-repos): gem, composer, and nuget dogfood fixtures`.

### M6 — Sign-off (folded M7 → M6)

Complexity: **S** (~1-2 days). Final PR.

1. **[S] M6.1 — Final harness run** against all 13 fixtures. `npm run dogfood:check` (no `--fixture` arg → runs all). Must be 13/13 PASS.
2. **[S] M6.2 — Targeted spot-check** in UI. Henry walks 3-5 randomly-picked fixtures (cross-batch, one per ecosystem) to spot UX bugs the harness can't catch. RESULTS.md updated.
3. **[S] M6.3 — OSV alias refresh.** Re-query OSV API for each fixture's pinned CVEs; update `expected.yaml` if any alias rotations detected. Re-run harness. **Decision tree for FAIL:** if finding missing AND OSV API shows the CVE exists for this version → bug (file in `docs/dogfood-bug-backlog.md`); if finding missing AND OSV API shows the CVE rotated → drift, update expected.yaml + note in RESULTS.md.
4. **[S] M6.4 — Aggregate writeup.** `docs/dogfood-2026-XX-XX-writeup.md` — scanner bugs found, scanner improvements landed, fixtures that needed > 1 iteration, what surprised us. Dual-audience: internal memory note + draft blog post.
5. **[S] M6.5 — Update CLAUDE.md.** Short section pointing future contributors at `depscanner/test-repos/` + the runbook + the harness.
6. **[S] M6.6 — Memory note** `memory/depscanner_dogfood_state.md` — 13/13 v1a pass + harness shipped + v1b backlog summary inline (no separate file per scope-cutter-r1-f2).
7. **[S] M6.7 — Ship M6 PR.** `chore(test-repos): final sign-off + writeup for dogfood corpus v1a`.

## Testing & Validation Strategy

### Per-fixture (M1-M5)

- **Scan completes:** No worker crashes, no timeouts, no missing-step failures.
- **`npm run dogfood:check --fixture <name>` PASS:** bucket/subset match against expected.yaml. Allow-incidental-extras (extras categorized in RESULTS.md, don't fail).
- **UI walkthrough:** Henry walks per-tab via the global runbook; RESULTS.md row filled.
- **DAST per server-side fixture:** Deploy via `.deptex/deploy.sh`, trigger DAST, capture HAR as `.deptex/dast-baseline.har`. Expected DAST findings appear.
- **Snapshot stability:** `npm run snapshot -- --include-slow` before AND after each batch — zero unexpected diffs in `depscanner/fixtures/`.

### Per-batch ship gate (M2-M5)

- All fixtures authored in this PR are harness-green
- ALL prior fixtures still harness-green (cumulative `npm run dogfood:check` runs all)
- Snapshot tests on `depscanner/fixtures/` still byte-stable (Patch B invariant)
- If a fixture cannot be made green, fix scanner bug in same PR (small) or split + defer (large) — never merge a broken fixture into main

### Harness self-tests

- `vitest run depscanner/bin/__tests__/dogfood-check.test.ts` must PASS in M1 + any PR that touches the harness
- Mutation cases per M1.7's spec — alias matching, bucket boundaries, subset semantics, malformed YAML

### Performance targets (RESULTS.md per-fixture)

- **Per-scan duration:** 2-15 min. >20 min = bug.
- **AI cost per fixture:** <$0.50. >$5 = bug.

### Regression risks

- **Worker job claim race** under fan-in: sync_frequency=manual on ALL fixture projects (success criterion). Don't queue all 13 simultaneously — pace 1-2 at a time during walkthrough.
- **Findings tab UI under heavy data:** walkthrough catches.
- **DAST port collisions:** Each `deploy.sh` uses port `4000 + alphabetical-index` (express=4001, fastapi=4002, etc.).

## Risks & Open Questions

### Risks

**R1. Phased shipping cost.** Estimates "pessimistic-realistic, not commitments." Gate after M1 at >6 days.

**R2. Live VDB / OSV alias drift.** Bucket/subset match + alias-aware `expected.yaml` mitigates. M6.3 re-queries OSV. Drift-vs-bug decision tree in M6.3.

**R3. Malicious-pkg seeding.** Use historical-not-currently-published names + `.github/dependabot.yml` exclusion + SECURITY.md note.

**R4. Cross-ecosystem scanner bugs.** Each batch PR re-runs harness against all prior fixtures. Caught early without Henry's eyeballs.

**R5. Fly worker scale-to-zero cold-start.** Acceptable. Not a bug.

**R6. Webhook fanout on deptex/deptex pushes.** **Mitigation (hard runbook step + success criterion):** all fixture projects set to `sync_frequency=manual`.

**R7. Per-batch ship-bar drift.** Each PR's pre-merge gate makes the ship bar explicit: all fixtures in this PR harness-green AND all prior fixtures harness-green.

**R8. Aegis Fix Agent interaction with fixtures.** Per Henry's blocker resolution: allowed. Aegis-triggered PRs against fixtures are acceptable + instructive; just don't auto-merge them. Aegis context loaders continue to see fixtures (no exclusion mechanism).

**R9. Snapshot test pollution from extensions.** **Mitigated by Patch B** — Each test-repos/ is a copy, not an extension. M2-M5 verifies snapshot stability before AND after each batch.

**R10. Harness self-correctness.** **Mitigated by Patch E** — vitest unit tests in M1 + negative-path demo in M1 PR description.

### Open questions

**O1. Port assignment for parallel deploys.** Documented in runbook: `4000 + alphabetical-index`.

**O2. v1b backlog ordering.** Defer to post-v1. Inline summary in M6.6 memory note, not a separate file.

**O3. `repoPath` → `scanRoot` cosmetic rename.** Tracked in v1b backlog. Not blocking.

## Dependencies

- ✅ Create-project + repo-connect flow.
- ✅ `package_json_path` monorepo support.
- ✅ Full extraction pipeline including IaC + container + composition (PRs #42, #45, #46, #50).
- ✅ DAST v2.1d (PR #47) + HAR import (PR #52, main `b8b3162`) — needed for `.deptex/dast-baseline.har` capture.
- ✅ Persistent Fly VDB cache (`3952cd8`).
- ✅ Findings tab on `OrganizationFindingsPage.tsx` (main `cdd2410`, PR #55).
- ❌ **`Vulnerable Projects` team in existing `deptex` prod org.** Henry creates manually before M1.8 walkthrough. Documented in runbook M1.2.
- ❌ **`.github/dependabot.yml` exclusion** — landed in M1.9.

## Success Criteria

Done when ALL hold:

1. ✅ `depscanner/test-repos/<framework>/` exists for all 13 v1a fixtures (standalone copies — `depscanner/fixtures/test-*` byte-stable).
2. ✅ Each fixture has `.deptex/expected.yaml` (alias-aware), `.deptex/SOURCE.md`, and (for server-side) `.deptex/deploy.sh` + `.deptex/dast-baseline.har`.
3. ✅ All 13 Deptex projects created in the `deptex` prod org under the `Vulnerable Projects` team, each pinned to its sub-path + `sync_frequency=manual`.
4. ✅ All 13 scans completed successfully.
5. ✅ `npm run dogfood:check` returns PASS (13/13).
6. ✅ Harness self-tests pass (`vitest run depscanner/bin/__tests__/dogfood-check.test.ts`).
7. ✅ For each server-side fixture, DAST has been triggered, findings match expected.yaml, and `.deptex/dast-baseline.har` is committed.
8. ✅ Henry has spot-checked 3-5 fixtures in UI (M6.2) + filled RESULTS.md for all 13.
9. ✅ M6 aggregate writeup saved; CLAUDE.md updated; memory note saved.
10. ✅ Snapshot stability invariant held: `npm run snapshot` returns zero unexpected diffs at M6.
11. ✅ Dependabot exclusion confirmed; deptex repo has no Dependabot alerts from `depscanner/test-repos/`.
12. ✅ All scanner bugs found during the arc fixed in same arc (or in `docs/dogfood-bug-backlog.md` with explicit deferral).

---

## Recommendation for next step

Revision 3 applies the 8 patches (A, B, C, D, E, F, G, I) from the Rev-2 multi-persona review (REVISE verdict). Headline structural changes: no schema work (dropped `exclude_from_org_rollups`), no scanner code changes, harness ships in M1 with self-tests, fixture corpus is copy-not-extend so `depscanner/fixtures/` byte-stability is preserved, DAST baseline HARs make DAST regression executable.

Optionally re-run `/review-plan depscanner-dogfood` to confirm verdict flips to READY; otherwise proceed to `/implement depscanner-dogfood`. M1 is self-gating — express's M1.5 seed-probe + M1.7 harness self-tests + M1.8 pattern-test walkthrough validate the corpus pattern before M2-M5 scale out.
