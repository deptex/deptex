# Feature Brief: IaC + Container Scanning (v1 — Foundation)

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

## Feature Name & One-liner
**IaC + Container Scanning v1.** Bundle Trivy + Checkov into the extraction worker so Deptex scans Terraform / Kubernetes / Helm / CloudFormation / ARM / Bicep / Serverless / SAM / CDK / Dockerfile files for misconfigurations and pulls container images (Dockerfile-derived + registry-configured) for OS-package CVE scanning, surfacing all findings in a unified security table.

## Problem Statement
Half of every modern repo — `Dockerfile`, `*.tf`, K8s manifests, `helm/`, `cloudformation/` — is invisible to Deptex today. Users connect a repo, see their package CVEs, and miss the misconfigured S3 bucket, the privileged K8s pod, the base-image CVEs in their production container. Every major SCA platform (Snyk, Aikido, GitHub Advanced Security) ships both as table-stakes; we don't. Foundation v1 closes this gap with broad format coverage, deferring the reachability/Aegis/policy differentiators to v2 once we've validated the foundation works.

## Competitive Landscape
Full research at `.cursor/plans/research-iac-containers.md`. Key positioning for v1:
- **Snyk IaC + Container** — table-stakes parity target. Coverage shape mirrored. Their Rego custom rules and runtime monitoring stay v2.
- **Aikido** — closest analogue: bundles Trivy + Checkov-class scanners with auto-detection + AI fix. v1 matches their *coverage*; v2 matches their *AI-fix UX* via Aegis.
- **Endor Labs (Feb 2026)** — moved the frontier with "container reachability." Foundation v1 is the platform for our v2 counter-play, which leverages our Phase 2 tree-sitter usage data.
- **Trivy + Checkov (OSS)** — both Apache 2.0; we bundle them rather than build proprietary scanners.

## User Stories
- As an **org admin**, I want to see at a glance which of my projects ship containers / use Terraform, so I can understand my organization's infrastructure surface.
- As a **developer**, I want to see misconfigurations in my Terraform / K8s manifests in the same security UI as my package CVEs, so I have one triage queue.
- As a **security engineer**, I want container CVEs ranked by depscore with asset-tier weighting, so I can prioritize across all finding types.
- As a **developer**, I want IaC + container scans to run automatically when I push, with no extra config, so adoption is zero-friction.
- As an **org admin**, I want to configure registry credentials (ghcr.io / ECR / GCR / Docker Hub private) per project, so we can scan the actual production images we ship.
- As a **developer**, I want to disable specific scanners on projects where they're noisy (e.g., turn off Trivy on a docs-only repo), so the security tab stays signal-rich.

## Data Model

### New tables

**`project_iac_findings`**
- `id` UUID PK
- `project_id` UUID FK → projects
- `extraction_id` UUID (soft-switch atomic commit pattern)
- `extraction_run_id` TEXT NOT NULL (upsert-then-delete-stale, mirrors `project_semgrep_findings`)
- `scanner` TEXT (`trivy` | `checkov`)
- `rule_id` TEXT (e.g., `CKV_AWS_20`, `AVD-AWS-0086`)
- `framework` TEXT (`terraform` | `kubernetes` | `helm` | `cloudformation` | `arm` | `bicep` | `serverless` | `sam` | `cdk` | `dockerfile`)
- `file_path` TEXT
- `line_start`, `line_end` INTEGER
- `severity` TEXT (`LOW` | `MEDIUM` | `HIGH` | `CRITICAL`)
- `depscore` NUMERIC(5,2) (extended scoring model, see Scoring section)
- `message` TEXT
- `description` TEXT (rule's full explanation)
- `cwe_refs` TEXT[]
- `compliance_refs` JSONB (CIS / SOC2 / NIST mappings the scanner provides)
- `code_snippet` TEXT (offending lines, ~10 lines context)
- `rule_doc_url` TEXT (link to Trivy/Checkov documentation)
- `suppressed`, `risk_accepted`, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason` (mirrors `project_dependency_vulnerabilities`)
- Stable identity for user-decision preservation: `(rule_id, file_path)` — line drift forgiven across re-extractions
- Timestamps

**`project_container_findings`**
- `id` UUID PK
- `project_id` UUID FK → projects
- `extraction_id` UUID
- `extraction_run_id` TEXT NOT NULL
- `image_reference` TEXT (e.g., `node:18-bullseye`, `ghcr.io/foo/bar:v1.2.3`)
- `image_digest` TEXT (sha256:...) — for cache lookups
- `image_source` TEXT (`dockerfile_base` | `dockerfile_referenced` | `registry_configured`)
- `os_package_name` TEXT (e.g., `libssl3`)
- `os_package_version` TEXT
- `os_package_ecosystem` TEXT (`debian` | `alpine` | `redhat` | `ubuntu` | `apk` | `rpm` | `deb`)
- `osv_id`, `cve_id` TEXT
- `severity` TEXT
- `cvss_score`, `epss_score` NUMERIC
- `depscore` NUMERIC(5,2) (existing depscore rubric — these ARE CVEs)
- `is_kev` BOOLEAN
- `fix_versions` TEXT[]
- `layer_digest` TEXT (which image layer the package is in — useful for base-image vs added-layer attribution)
- `suppressed`, `risk_accepted`, `risk_accepted_by`, `risk_accepted_at`, `risk_accepted_reason`
- Stable identity: `(image_digest, os_package_name, os_package_version, osv_id)`
- Timestamps

**`container_image_scan_cache`** (global)
- `image_digest` TEXT PK (sha256:...)
- `image_reference` TEXT (last-seen reference for diagnostics)
- `scan_results` JSONB (raw Trivy output — re-parsed cheaply on cache hit)
- `scanned_at` TIMESTAMPTZ
- `scanner_version` TEXT (invalidate on Trivy upgrade)
- TTL: refresh after 7 days even on hit (catches new CVEs in unchanged digests)

**`project_registry_credentials`**
- `id` UUID PK
- `project_id` UUID FK → projects
- `registry_type` TEXT (`ghcr` | `ecr` | `gcr` | `acr` | `dockerhub` | `quay` | `harbor` | `jfrog` | `custom`)
- `registry_url` TEXT (custom-registry support)
- `encrypted_credentials` TEXT (AES-256-GCM via `AI_ENCRYPTION_KEY`, same pattern as `organization_ai_providers`)
- `encryption_key_version` INTEGER
- `created_by` UUID FK → auth.users
- Timestamps

**`project_configured_images`**
- `id` UUID PK
- `project_id` UUID FK → projects
- `image_reference` TEXT (the user-supplied image tag/URL to pull and scan)
- `credentials_id` UUID FK → project_registry_credentials (nullable — public images skip auth)
- `enabled` BOOLEAN DEFAULT true
- Timestamps

**`project_scanner_config`**
- `project_id` UUID PK FK → projects
- `iac_enabled_override` BOOLEAN (NULL = use auto-detect; TRUE/FALSE = override)
- `container_enabled_override` BOOLEAN
- `iac_frameworks_override` TEXT[] (NULL = auto; array = explicit list)
- Timestamps

### New columns
- `projects.infra_types TEXT[]` — auto-populated by detection step (e.g., `['terraform', 'kubernetes', 'dockerfile']`)
- (no new columns on existing finding tables)

### Schema dump
After applying migrations, run `cd backend/extraction-worker && npm run schema:dump` per CLAUDE.md.

## API Endpoints

### Findings
- `GET /api/projects/:projectId/iac-findings` — list, paginated
- `POST /api/projects/:projectId/iac-findings/:findingId/ignore` — toggle suppressed
- `POST /api/projects/:projectId/iac-findings/:findingId/risk-accept` — body: { reason }
- `GET /api/projects/:projectId/container-findings` — list, paginated
- `POST /api/projects/:projectId/container-findings/:findingId/ignore`
- `POST /api/projects/:projectId/container-findings/:findingId/risk-accept`

### Settings
- `GET /api/projects/:projectId/scanner-config`
- `PUT /api/projects/:projectId/scanner-config` — body: { iac_enabled_override, container_enabled_override, iac_frameworks_override }
- `GET /api/projects/:projectId/configured-images`
- `POST /api/projects/:projectId/configured-images` — body: { image_reference, credentials_id? }
- `DELETE /api/projects/:projectId/configured-images/:id`
- `GET /api/projects/:projectId/registry-credentials` (returns metadata only — never the encrypted secret)
- `POST /api/projects/:projectId/registry-credentials` — body: { registry_type, registry_url?, credentials } (server encrypts before insert)
- `DELETE /api/projects/:projectId/registry-credentials/:id`

### Worker (internal)
- Internal API key gate, same as existing extraction worker endpoints.
- Worker reads scanner config, registry credentials (decrypted), and configured images from the database directly (no new external endpoints).

All routes use `authenticateUser` and project-membership checks (existing pattern in `backend/src/routes/projects/`).

## Frontend Views

### Security page (existing)
- Add "IaC" + "Container" finding-type filter chips to the unified security table (Round 3 decision: unified, not per-type tabs).
- Each row: severity badge, finding-type chip, depscore, rule_id, file:line / image:package, ignore/risk-accept actions.
- Expand-row pattern matches existing vuln/Semgrep cards: code snippet (highlighted lines), severity + depscore, rule documentation link, AI explainer button (Tier 1 Gemini), suppress/risk-accept controls.
- Empty state when project has no infra detected: "No infrastructure files detected. Last scan: timestamp. Configure container image → / Trigger rescan →"

### Project Settings — new "Scanners" tab
- Section: **Auto-detected coverage** — read-only list of detected `infra_types` from last extraction.
- Section: **Scanner overrides** — toggles to force-enable or force-disable IaC / Container scanning regardless of detection. Multi-select for IaC frameworks (Terraform, K8s, Helm, etc.).
- Section: **Configured container images** — list + add/remove. Each row: image reference, credential reference (if any), enabled toggle.
- Section: **Registry credentials** — list + add/remove. Adding shows registry-type dropdown, URL field for custom registries, credential entry (encrypted before send via TLS to backend, encrypted-at-rest with AES-256-GCM).

### Project cards (existing list views)
- Add infrastructure-type badges next to ecosystem badges. Same pattern as existing `framework-icon.tsx` extension.
- Use Simple Icons: `SiTerraform`, `SiKubernetes`, `SiHelm`, `SiAmazonaws`, `SiMicrosoftazure`, `SiDocker`. Add to `frontend/src/components/framework-icon.tsx`.

### CreateProjectSidebar (existing)
- Repo-scan preview adds detected `infra_types` alongside the existing ecosystem/framework preview, so users see "we'll scan your Terraform" before they connect.

## User Flows

### First-time scan (happy path)
1. User connects a repo via existing flow.
2. Extraction worker clones, runs SBOM, tree-sitter, dep-scan, then **(new)** IaC scan + container scan, then Semgrep, TruffleHog, commit.
3. Detection step globs for `Dockerfile`, `*.tf`, `*.tf.json`, `**/*.yaml` matching K8s shapes, `helm/**`, `cloudformation/**`, `*.bicep`, `serverless.yml`, `sam.yaml`, `cdk.json`. Populates `projects.infra_types`.
4. Trivy + Checkov run with 10-min timeout each. On timeout: log `warn` to `extraction_step_errors`, pipeline continues.
5. Container scan: parse Dockerfile `FROM`, pull base image, scan; pull each `project_configured_images` entry, scan. Cache lookup against `container_image_scan_cache` by digest before each pull.
6. Findings written under fresh `extraction_id`; soft-switch atomic commit flips `projects.active_extraction_id`. User decisions (ignore/risk-accept) carry forward via stable `(rule_id, file_path)` and `(image_digest, package, version, osv_id)` keys.
7. User opens security page; filters to "IaC" or "Container"; sees ranked findings.

### Configuring a private registry image
1. User goes to Project Settings → Scanners.
2. Adds a registry credential: type=ghcr, paste PAT, save. Backend encrypts via `AI_ENCRYPTION_KEY`.
3. Adds a configured image: `ghcr.io/foo/bar:v1.2.3`, links to the credential just added.
4. Clicks "Trigger rescan" or waits for next push.
5. Worker pulls the image with the decrypted credential, scans, stores findings under the project.

### Scanner override (project with Terraform but security team doesn't care about it)
1. User goes to Project Settings → Scanners.
2. Toggles off "Terraform" in the IaC frameworks override list.
3. Next extraction skips Terraform scanning; existing Terraform findings are not deleted but stop refreshing.

## Edge Cases & Error Handling
- **No infra detected** → friendly empty state with rescan + add-image CTAs.
- **Trivy / Checkov binary missing** → existing pattern (mirrors Semgrep / TruffleHog): worker logs structured warning to `extraction_step_errors`, continues.
- **Scan timeout** (10 min): step marked `timeout` in `extraction_step_errors`, pipeline continues, findings preserved from previous run via soft-switch.
- **Container pull fails** (network, auth, image gone): log to `extraction_step_errors`, mark image scan as `failed` for that extraction, continue. Surface the failure in the Scanners settings tab so the user knows their credential is broken.
- **Image digest cache hit but stale** (>7 days): treat as miss, re-pull.
- **Malformed IaC file**: scanner emits a warning; we log it and skip that file. No pipeline failure.
- **Huge repo** (1000+ IaC files): scanners handle natively. We respect the 10-min timeout. Document repo-size guidance later.
- **Registry credential rotation**: user updates via Settings; encryption_key_version tracked for future bulk re-encrypt.
- **`AI_ENCRYPTION_KEY` not set**: registry-credentials endpoint returns 400; user prompted to ask org admin to configure (mirrors BYOK error behavior).
- **Concurrent re-extractions**: existing soft-switch handles this — both write under their own `extraction_id`, last commit wins via atomic pointer flip.

## Non-Functional Requirements

### Performance targets
- Most repos: combined IaC + container scan adds <5 min wall-clock to extraction.
- Worst case: 10 min per scanner before skip-on-timeout.
- Image digest cache hit rate target: >50% across the org (most repos use shared base images).

### Data volume
- Typical project: 5-50 IaC findings + 100-500 container findings (most are LOW severity OS package CVEs).
- Worst case: 1000+ IaC findings, 5000+ container findings on one large project.
- Unified security table needs to handle 5000+ rows performantly — use the existing pagination pattern in `VulnerabilityExpandableTable.tsx`. Consider virtual scrolling for >1000.

### Scalability
- `container_image_scan_cache` is global — high cardinality but bounded (millions of unique image digests at scale, indexed by digest).
- `project_iac_findings` and `project_container_findings` grow with users × projects × findings — partition by `project_id` index from day one. Reuse existing `extraction_run_id` upsert-then-delete-stale pattern to avoid unbounded growth.

### Reliability
- Pipeline failures in scanners are non-fatal (step `warn`, continue). The atomic commit means findings are never partially written.
- Eventual consistency is fine — users don't expect findings to update in real-time during a scan.

## RBAC Requirements
Existing organization permissions cover this v1. No new permissions needed.

- **View IaC + container findings**: anyone with project access (existing).
- **Suppress / risk-accept findings**: existing project-level write permission (same as suppressing CVEs).
- **Configure scanners + registry credentials**: existing `manage_projects` team permission OR `manage_teams_and_projects` org permission.
- **View encrypted credentials (decrypted)**: server-only; never returned via API.

## Dependencies
- **Soft-switch atomic commit pattern** — already shipped (Phase 19 / reachability Phase 1, PR #4 merged 2026-04-21). New tables fit the pattern.
- **`extraction_step_errors`** — already shipped. New scanners log via the existing helper.
- **`AI_ENCRYPTION_KEY`** — already required for BYOK. Reused for registry credentials.
- **GitHub App** — already installed. We extract the GHCR token from the App's existing credentials when the project is GitHub-connected.
- **Existing depscore rubric** — extended to handle IaC misconfigs (CIS severity × asset_tier multiplier). Container CVEs use the existing rubric unchanged.
- **`framework-icon.tsx`** — extended with infra icons.
- **`VulnerabilityExpandableTable.tsx`** (or successor) — extended to render new finding types with type filter chips.
- **Trivy + Checkov binaries** — added to `backend/extraction-worker/Dockerfile`.

## Success Criteria
- All major IaC formats (Terraform, K8s, Helm, CloudFormation, ARM, Bicep, Serverless, SAM, CDK, Dockerfile) are scanned end-to-end against fixture repos covering each.
- Container images pulled from public registries, ghcr.io (via GitHub App), and one private registry (via per-project credentials) all scan successfully.
- Findings appear in the unified security table with correct depscore, severity, type filter, and ignore/risk-accept all working.
- User-decision preservation across re-extractions verified: ignore a finding, re-scan, finding remains ignored.
- Timeout behavior: artificially-slow fixture repo causes scanner timeout, pipeline completes, `extraction_step_errors` row recorded.
- Image digest cache: scanning the same image across two projects pulls once, scans once.
- Empty state shows correctly on a project with no IaC and no configured images.
- All four entry points to project infra (project card, project overview, security page, settings) reflect detected infra types coherently.

## Open Questions
- **Trivy version pin** — pin to a specific Trivy release (current stable: 0.50+) and bump deliberately, or always latest? Likely pin, with version recorded in `container_image_scan_cache.scanner_version`.
- **Custom Checkov policies** — Checkov supports user-defined Python policies; do we expose this in v1 or defer entirely? Leaning defer (Round 1 picked Foundation only); Custom IaC Policy via existing engine is one of the deferred v2 candidates.
- **Helm rendering** — Checkov can scan Helm charts directly (template + scan), but rendered output may differ. Do we render with default `values.yaml` only, or accept a project-supplied values file? Defer values file support to v2 unless this lands as a major false-negative source.
- **Compliance framework mapping** — Trivy / Checkov emit CIS / SOC2 / NIST refs. Do we surface these on finding cards in v1 (low effort, useful) or defer to a dedicated compliance-mapping pass? Probably surface as raw `compliance_refs` in v1; richer compliance UI is its own roadmap item.
- **GitHub Actions** — explicitly skipped per Round 4 despite Round 1 picking "everything." This contradicts the Round 1 scope choice; we honor the more recent decision (skip), but flag this as a known omission to revisit when GitHub Actions becomes a v2 differentiator concept.
- **Path-based asset-tier inference** (prod/staging/dev) — deferred to v2. Project-level tier only at v1.

## Scope

### MVP (v1, this brief)
Foundation only with broad coverage:
- Trivy + Checkov bundled in extraction worker.
- Coverage: Terraform, K8s, Helm, CloudFormation, ARM, Bicep, Serverless, SAM, CDK, Dockerfile (no GitHub Actions).
- Container scan from Dockerfile-derived + per-project configured registry images.
- Hybrid auto-detect + per-project override.
- Three-tier registry auth: public + GitHub App + per-project encrypted creds.
- Unified security table with finding-type filter chips.
- New "Scanners" tab in Project Settings.
- Depscore extension for IaC; existing depscore for container CVEs.
- 10-min per-scanner timeout, skip-on-timeout, image-digest caching.
- Pipeline order: clone → SBOM → tree-sitter → dep-scan → **iac + container** → Semgrep → TruffleHog → commit.
- Findings emit existing `vulnerability_found` (containers) + new `iac_misconfig_found` events.
- User-decision preservation across re-extractions.
- Friendly empty state.

### Explicitly out of scope for v1 (deferred to v2+)
- Container reachability classification (filter CVEs by which OS packages the app actually calls)
- Aegis IaC auto-fix agent
- Aegis chat tools for IaC findings
- Custom IaC policy via existing JS policy engine
- PR blocking (waits for in-flight flow builder)
- CI-built artifact upload (Action / CLI / S3)
- GitHub Actions workflow scanning (depth = Scorecards/StepSecurity)
- Per-finding asset-tier inference from path heuristics
- IaC ↔ application-code reachability via cross-file taint (moonshot, requires Phase 6)
- Custom Checkov policy authoring
- Compliance dashboard mapping (raw refs only at v1)
- Public coverage / benchmark stat (marketing wedge)

### v2 ordering hint
Once Foundation is dogfooded, the natural v2 sequence is: (1) Container Reachability → (2) Aegis IaC auto-fix → (3) Aegis chat tools → (4) Custom IaC policy via existing engine → (5) GitHub Actions deep checks. PR blocking joins whenever flow builder lands.

## Recommended Next Step
Run `/plan-feature` against this brief to produce the implementation plan with milestones (M1 schema + worker bundle, M2 detection + pipeline integration, M3 unified table + finding cards, M4 scanner config + registry creds settings, M5 GitHub App ghcr.io path + per-project encrypted creds, M6 image-digest cache + soft-switch verification, M7 fixtures + tests).
