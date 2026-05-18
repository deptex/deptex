# IaC + Container Scanning v2 — Phase 1 (Complete Coverage) — Implementation Plan

> **Historical context (2026-05-09):** This plan was authored when AI was BYOK (per-org customer keys via `organization_ai_providers` + AES-256-GCM envelope). BYOK was retired in `phase29_drop_byok.sql` / commit `6705149`. Where this plan references BYOK, `organization_ai_providers`, `encryption.ts` for AI keys, monthly BYOK budget caps, or `AI_ENCRYPTION_KEY` for AI key envelopes, treat those as historical implementation details — current AI runs on platform keys (`OPENAI_API_KEY` / `ANTHROPIC_API_KEY` / `GOOGLE_AI_API_KEY` from worker env). `AI_ENCRYPTION_KEY` itself is still in use, but only for `organization_registry_credentials` (IaC v2 Phase 1).

> Implements Phase 1 of `feature-brief-iac-container-v2.md`. Phases 2-4 (Reachability / Policy / Aegis) get their own brainstorm + plan-feature when their turn comes.

## Overview

Phase 1 is the "complete coverage" plumbing pass. Three goals: (1) extend IaC scanning from v1's three formats (Terraform / Kubernetes / Dockerfile) to **nine formats** (adding Helm, CloudFormation, ARM, Bicep, Serverless, AWS SAM via CFN Transform header, GitHub Actions; Kustomize folded into the existing kubernetes detector; CDK explicitly out of scope until we run `cdk synth`); (2) extend container scanning from v1's two registry surfaces (public + ghcr.io via GitHub App) to **nine registries** including ECR / GCR / ACR / Docker Hub / Quay / Harbor / JFrog / custom via per-project encrypted creds + a global digest cache; (3) extend `project_configured_images` so users can scan registry images that aren't referenced by a Dockerfile `FROM`.

**Phase split (Debate D):** Phase 1 ships as **two sequential PRs** — Phase 1a (formats) goes first to keep the review surface focused, Phase 1b (registries + creds + cache) follows. Both ship under this single plan; see §Phase Split below for the milestone allocation.

This phase ships **no reachability work, no Aegis integration, no custom policy authoring** — those are Phases 2/3/4. The bar is: when Phase 1 ships, every IaC format and registry that Snyk / Aikido / Trivy supports is covered, and the scan-cache infrastructure is in place so Phase 2 reachability can assume cache hits as the hot path.

The work touches three packages: `backend/depscanner/` (scanner adapter + orchestrator extensions, Dockerfile, tree-sitter / detect-infra extensions), `backend/src/` (new CRUD routes, encryption helpers reused), and `frontend/src/` (ScannersPanel sections, VulnerabilityExpandableTable framework chips, InfraFindingCard compliance badges).

## Competitive Research & Design Rationale

Already locked in `feature-brief-iac-container-v2.md`. Key Phase 1 anchors:

- **Checkov framework keys (verified 2026-05-02):** `helm`, `cloudformation`, `arm`, `bicep`, `serverless`, `github_actions`, `kustomize` are all first-class. Phase 1 exposes 6 of these as new framework values (helm/cfn/arm/bicep/serverless/github_actions); kustomize files are scanned but surface as `kubernetes` framework (Debate F — free coverage, no separate UI surface). **`sam` and `cdk` are NOT separate Checkov keys** — Checkov scans SAM via its CFN `Transform: AWS::Serverless-2016-10-31` header. CDK is **not in Phase 1** — CDK code is TS/Python that requires `cdk synth` to compile to CFN, which Phase 1 doesn't run. UI copy: "AWS SAM is scanned via CloudFormation"; CDK gets explicit "not yet supported" copy. (CR-2.)
- **Trivy IaC config scanner** continues to handle Dockerfile (Checkov also handles it but emits noisier rules; v1 keeps Trivy for Dockerfile and Checkov for everything else — Phase 1 preserves this split).
- **DOCKER_AUTH_CONFIG** is the canonical cross-registry auth envelope. v1 already uses it for ghcr.io ([Trivy docs](https://trivy.dev/)). Per-registry auth shape (verified):
  - **ECR**: short-lived token (12h expiry) minted at scan-time via AWS STS or static keys → `aws ecr get-authorization-token`. Auth value: base64(`AWS:<token>`).
  - **GCR / Artifact Registry**: service-account JSON key. Auth value: base64(`_json_key:<sa-json>`).
  - **ACR**: service principal. Auth value: base64(`<sp-app-id>:<sp-secret>`). ([MS docs](https://learn.microsoft.com/en-us/azure/container-registry/container-registry-auth-service-principal))
  - **Docker Hub / Quay / Harbor / JFrog / custom**: username + PAT/token. Auth value: base64(`<user>:<pass>`).
- **Pre-pull digest probe**: `crane digest <image>` (from go-containerregistry, ~5MB) returns the registry-resolved digest via a HEAD request without pulling the image. Lets Phase 1 hit the cache before the expensive Trivy pull. Without it, every cache check still pays the pull cost. (Open question on alternatives below.)

**Rationale on Decision 5 (GitHub Actions native-only, no Scorecards):** Checkov's `github_actions` framework covers the highest-value patterns (action pinning to mutable refs, `pull_request_target` with checkout, broad `permissions: write-all`, missing `harden-runner`). Real coverage gap vs StepSecurity is supply-chain runtime EDR (which we don't ship anyway). Adding a third scanner now means a Go binary, a new findings type, more cache-key dimensions — disproportionate to the marginal coverage gain. Revisit at v2 Phase 5+ if FN data justifies.

**Rationale on cache being Postgres not Redis (Decision 7):** scan results are large JSONB blobs (5-50KB per image) and need durability across redis flushes. The cache is content-addressed so multi-tenant safe by construction. Postgres is the right substrate.

## Codebase Analysis

### v1 surface this builds on (all in main)

| File | Role | Phase 1 change |
|---|---|---|
| `backend/database/phase25_iac_container_scanning.sql` | v1 tables, enforce_finding_org_id trigger, finalize_extraction extension | Read-only — Phase 1 adds new migrations on top, doesn't edit v1 |
| `backend/depscanner/src/scanners/types.ts` | `IaCFramework` discriminated union (3 values), `IaCFinding`, `ContainerFinding`, `SkippedImage` types | **Extend** `IaCFramework` to 9 values, add `ConfiguredImage`, `RegistryCredential` types, add `compliance_refs` to `IaCFinding` |
| `backend/depscanner/src/scanners/detect-infra.ts` | `detectInfraTypes` (3 detectors), `findDockerfiles` | **Extend** with 7 new detectors |
| `backend/depscanner/src/scanners/checkov.ts` | Checkov subprocess + parser. Hardcodes `FRAMEWORK_TO_CHECKOV` for 3 values; only accepts `terraform`/`kubernetes`/`dockerfile` from `CHECK_TYPE_TO_FRAMEWORK` | **Extend** both maps; add `compliance_refs` extraction from `metadata.benchmark` |
| `backend/depscanner/src/scanners/trivy.ts` | Trivy config scanner + image scanner. `KNOWN_REGISTRY_HOSTS` set + `classifyImageRef` switch (only ghcr returns auth metadata) | **Replace** `classifyImageRef` with a per-registry-type resolver that consults `organization_registry_credentials`; **extend** `runTrivyImage` to accept multi-registry `DOCKER_AUTH_CONFIG` |
| `backend/depscanner/src/scanners/orchestrator.ts` | `runIaCAndContainerScans` step entry. Currently only iterates Dockerfile-derived images. Reads ghcr.io creds from GitHub App | **Extend** to: (a) read configured-images list, (b) read per-registry creds, (c) check image-digest cache before Trivy, (d) populate cache after scan |
| `backend/depscanner/src/scanners/storage.ts` | Bulk upsert `project_iac_findings` + `project_container_findings`. Patches A/B (GENERATED columns), Patch D (org_id trigger) | **Extend** to write `compliance_refs`; **add** `lookupContainerScanCache(imageDigest)` and `upsertContainerScanCache(imageDigest, parsed)` |
| `backend/depscanner/Dockerfile` | Base image with checkov-venv + trivy + guarddog-venv. Built nightly | **Add** `crane` (5MB Go binary). Defer cfn-lint/kubeconform/arm-ttk to Phase 4 (per OQ2 resolution below) |
| `backend/depscanner/src/pipeline.ts:2129` | Pipeline integration calling `runIaCAndContainerScans` | **No change** — the orchestrator interface stays the same |
| `backend/src/routes/scanner-findings.ts` | Findings CRUD. v1 `framework` filter only allows `terraform` / `kubernetes` / `dockerfile` (line 83) | **Extend** filter whitelist to 9 frameworks |
| `backend/src/index.ts:139` | `app.use('/api/organizations', scannerFindingsRouter)` | **Add** mounts for new `registryCredentialsRouter` + `configuredImagesRouter` |
| `backend/src/lib/ai/encryption.ts` | AES-256-GCM helpers for `organization_ai_providers`. `encryptApiKey` / `decryptApiKey` / `rotateEncryptionKeys` | **Reuse** as-is. No fork. The "ai" naming is historical; the helper encrypts arbitrary strings keyed by `AI_ENCRYPTION_KEY`. |
| `frontend/src/components/security/ScannersPanel.tsx` | Read-only summary | **Extend** with two new editable sections: registry credentials + configured images |
| `frontend/src/components/security/InfraFindingCard.tsx` | Card with severity + framework label hardcoded for 3 values | **Extend** `frameworkLabel` switch; add compliance refs badge strip |
| `frontend/src/components/security/VulnerabilityExpandableTable.tsx` | Unified table. Has IaC + container row variants | **Extend** filter chip set with 7 new framework chips |
| `frontend/src/components/framework-icon.tsx` | Icon registry | **Extend** with helm / cfn / arm / bicep / serverless / gh-actions icons |
| `frontend/src/lib/api.ts` | API client + types | **Add** `RegistryCredential`, `ConfiguredImage` types + 8 new client methods |

### Reusable patterns I'm borrowing without modification

- **Per-finding tenancy enforcement**: `enforce_finding_org_id` trigger pattern (phase25). Reused for new tables — caller passes `project_id`, trigger derives `organization_id` from `projects`.
- **Encrypted column shape**: `organization_ai_providers.encrypted_api_key TEXT` + `encryption_key_version INTEGER`. Reused for `organization_registry_credentials.encrypted_credentials`.
- **Partial UNIQUE on fingerprint**: phase25 used `UNIQUE NULLS NOT DISTINCT` for fingerprint partial unique. Same approach for new image-digest cache.
- **`finalize_extraction` carry-forward**: phase25 added IaC + container fingerprint carry-forward. Phase 1 doesn't need to re-amend (the existing carry-forward handles all `iac_fingerprint` values, including newly-introduced framework values).
- **Active-extraction-run scoping**: routes use `getActiveExtractionId(supabase, projectId)` (`backend/src/lib/active-extraction.ts`). Reused as-is.
- **RBAC pattern**: `checkProjectAccess` (read) + `checkProjectManagePermission` (mutation). Phase 1 routes use the exact same pattern.
- **Pagination shape**: `parsePagination` (1-200 per_page, 1-indexed page). Reused.
- **Soft-fail / structured warning pattern**: `extraction_step_errors` rows + `summary.warnings.push(...)`. New scanners log via the same helper.
- **Discriminated-union exhaustiveness**: `assertNever` in `VulnerabilityExpandableTable` (per `feedback_audit_vs_grep.md` precedent). Phase 1 framework chips extend the union; the assertNever check enforces every case is handled.

### Integration points with Phase 6.5 / Track A

**None.** Phase 1 doesn't touch the reachability engine, atom retirement, taint stitching, or anything in `taint-engine/`. Phase 1 can ship in parallel with Phase 6.5 and post-6.5 hardening with zero conflict surface. (Confirmed in brief Decision 3.)

### Conflicts to watch

- **schema.sql redumps on main**: per `feedback_schema_dump_rebase.md`, if main redumps `backend/database/schema.sql` while this branch is in flight, the rebase silently drops our schema diff. Mitigation: re-run `cd backend/depscanner && npm run schema:dump` after every rebase against main.
- **Active sprint capacity**: `active_sprint.md` says current sprint is 3 concurrent (Pipeline 6.5, Frontend ironing, Aegis). Phase 1 makes it 4. The `active_sprint.md` UPDATE-don't-spawn rule means the sprint memory should be updated when Phase 1 starts.

## Phase Split (1a + 1b)

Phase 1 ships as two sequential PRs (Debate D locked). Rationale: bundling formats + registries + cache into one PR concentrated 131 R1 review findings; split keeps each PR's review surface tractable.

**Phase 1a — Formats (~1.5 weeks, single PR):**
- Adds 6 new IaC framework values (helm/cfn/arm/bicep/serverless/github_actions). Kustomize files surface as `kubernetes`. Compliance refs ship in 1a (Debate E).
- Touches: detect-infra, checkov adapter, scanner-findings filter, frontend chips/icons/cards.
- Database: `phase27a_iac_v2_formats.sql` — framework CHECK widening (3 → 9 values) + `compliance_refs JSONB` column. NO new tables.
- Ships independent value: every customer's IaC surface area expands the day 1a lands. Container scanning continues to work as v1.

**Phase 1b — Registries + creds + cache (~4-5 weeks, single PR, opens immediately after 1a merges):**
- Adds **org-scoped** encrypted creds, per-project configured images, and the global digest cache subsystem with all 17 P0 hardening patches plus their P1 supporting items.
- Touches: encryption helper sync, registry-auth resolver, trivy image runner, scan-cache storage, orchestrator (M8 with 7-phase sub-step taxonomy), Dockerfile (crane install with checksum), 2 new API route files (one org-scoped for creds, one project-scoped for configured-images), 2 new frontend sections.
- Database: `phase27b_iac_v2_registries.sql` — `organization_registry_credentials`, `project_configured_images`, `container_image_scan_cache`, helper trigger, composite same-org FK, `image_source` CHECK widening, cache reaper function.
- The hard prerequisite is `phase27a` (framework values must exist before configured-image scans can write findings).
- Estimate uplift vs the original plan's "3 weeks" reflects the cache-cluster hardening: digest normalization helper, integrity hash, scanner discriminator + composite key, cache write contract, ephemeral DOCKER_CONFIG dir, crane checksum verification, sub-step taxonomy with 7-phase try/catch envelope. Each individually is a small change; the collection is real engineering time.

### Milestone allocation

| Milestone | Phase | Notes |
|---|---|---|
| M1a — DB migration formats (S) | 1a | `phase27a_iac_v2_formats.sql` + schema:dump. Just framework CHECK + compliance_refs. |
| M1b — DB migration tables (S) | 1b | `phase27b_iac_v2_registries.sql` + schema:dump. New tables, triggers, image_source CHECK, reaper. |
| M2 — Backend types extension | 1a | IaCFramework union to 9 values + `IAC_FRAMEWORKS as const` export + compliance_refs on IaCFinding. RegistryCredential/ConfiguredImage types defer to M2b. |
| M2b — Worker types | 1b | RegistryCredential, CredentialPlaintext, ConfiguredImage types (worker-only decrypted shape backend-side). |
| M2.5 — Encryption helper sharing (S) | 1b | OQ-A resolution. Only needed once 1b's worker code starts decrypting. |
| M3 — Detect-infra extension (M) | 1a | All 6 new detectors + kustomization-as-kubernetes. |
| M4 — Checkov adapter extension (M) | 1a | Framework maps + compliance_refs extraction. |
| M5 — Registry auth resolver (M) | 1b | All 5 minters. |
| M6 — Trivy image runner extension (M) | 1b | normalizeDigest helper, resolvePullStrategy, crane probe with auth. |
| M7 — Scan-cache storage layer (S) | 1b | lookupContainerScanCache + upsertContainerScanCache + 4-guard cache write contract. |
| M8 — Orchestrator extension (L) | 1b | Sub-step taxonomy, kill switches, lazy decrypt, scanOneImage envelope, classifyError extension, DOCKER_CONFIG dir. |
| M9 — Dockerfile update (S) | 1b | Crane install with checksum + multi-arch + CI sync-check. |
| M10 — Registry credentials API route (M) | 1b | All routes incl. /test and /rotate. |
| M11 — Configured images API route (M) | 1b | Same-project FK validation + 20-image cap. |
| M12 — scanner-findings filter extension (S) | 1a | Whitelist 9 values. |
| M13a — Frontend types + API client (formats) | 1a | IaCFinding shape + 9-value framework union on the client. |
| M13b — Frontend types + API client (registries) | 1b | RegistryCredential, ConfiguredImage types + 8 client methods. |
| M14 — Framework-icon registry extension (S) | 1a | 6 new icons (helm/cfn/arm/bicep/serverless/gh-actions). |
| M15 — VulnerabilityExpandableTable filter chips extension (S) | 1a | 6 new chips. |
| M16 — InfraFindingCard label + compliance refs (M) | 1a | Switch + badge strip. |
| M17 — RegistryCredentialsSection (L) | 1b | New ScannersPanel section + dialog. |
| M18 — ConfiguredImagesSection (M) | 1b | New ScannersPanel section + dialog. |
| M19a — Multi-iac fixtures (M) | 1a | TF + K8s + Helm + CFN + ARM + Bicep + Serverless + Dockerfile + GH Actions + kustomization fixture. |
| M19b — Configured-image fixtures (M) | 1b | Cache hit/miss + cred CRUD fixtures. |
| M20a — End-to-end smoke (1a) (M) | 1a | Multi-iac extraction + UI chips + compliance badges render. |
| M20b — End-to-end smoke (1b) (M) | 1b | Registry cred CRUD via UI + configured-image scan + cache miss → cache hit. |

### Success criteria split

- **1a green when:** every IaC format detector produces findings, compliance badges render where Checkov supplies refs, kustomization.yaml-as-kubernetes scans correctly, no regression in v1 TF/K8s/Dockerfile carry-forward.
- **1b green when:** every Phase 1 success criterion (registry parity, cache works, configured images, RBAC, kill switches, ghcr.io fallback preserved, all 17 P0 patches verified, image-size delta within budget). 1a must already be green; 1b inherits 1a's invariants.

### What if 1b slips?

The split itself is the contingency. 1a's user-visible value (helm/CFN/ARM/Bicep/Serverless/SAM/GH-Actions findings + compliance badges) lands independently. If 1b's hardening discovers further P0s during implementation, 1a stays in production while 1b iterates.

## Tenancy Invariants

These are load-bearing rules. Violations break multi-tenant isolation; reviews of any code in this Phase MUST grep these against the diff. (Patch 10 — WPA-r2-1 / DMA-1 / MTD-3, top consensus cluster; rescoped to org per cred-scope decision 2026-05-02.)

1. **Worker-side service-role reads:**
   - `organization_registry_credentials` reads MUST chain `.eq('organization_id', orgId)` (resolved from the project's `organization_id`).
   - `project_configured_images` reads MUST chain `.eq('project_id', projectId)`.
   The depscanner uses the service-role key, so RLS does not gate these reads. A literal `supabase.from('organization_registry_credentials').select('*')` returns **all creds across all orgs** into worker memory. Spy-supabase mock in `orchestrator.test.ts` enforces both filters.

2. **Cred plaintext is never produced at step start.** M8 step 1 reads metadata only. Decryption happens lazily inside `scanOneImage`, scoped to a single image, with a try/catch envelope. (FMH-P0-3.)

3. **Cred attachment to a configured image MUST be same-org.** Enforced at three layers: (a) DB composite FK `(credentials_id, organization_id) REFERENCES organization_registry_credentials(id, organization_id)`; (b) route-layer `cred.organization_id === image.organization_id` validation; (c) `pci_null_credentials_id_on_org_move` trigger drops `credentials_id` if the row reparents to a different org. (DMA-1 / MTD-3.)

4. **The cache table is content-addressed by digest.** No org_id column; no per-org scope. Forensics columns (`first_scanned_by_org_id`) are NEVER returned via API. (MTD-1.)

5. **Service-role admin scripts and future internal RPCs are subject to (1)-(3) by construction** — there is no `getAllCredsAcrossOrgs` helper anywhere in the codebase. Reviewers reject PRs that introduce one. ESLint guard (`rbac-r2-7` follow-up): backend route files MAY NOT import `decryptApiKey`.

6. **Cred mutations are gated by `checkOrgManageIntegrations` (org-level), not `checkProjectManagePermission` (team-level).** Equal blast-radius to BYOK provider keys. Cred routes live at `/api/organizations/:id/registry-credentials/...` (no project segment). (rbac-1.)

7. **Triggers use `BEFORE INSERT OR UPDATE` (no column list)** on `project_configured_images`. Re-derives `organization_id` on every UPDATE so a stale or surgical-set value cannot survive. (Patch 5 / MTD-2.) `organization_registry_credentials` doesn't need a derivation trigger — `organization_id` is a direct user input there, not derived.

8. **Decryption has no HTTP surface.** `decryptApiKey` is callable from worker code (`backend/depscanner/src/lib/encryption.ts`) and from the rotation script in `backend/src/lib/ai/encryption.ts`, but never from a route handler. The `/test` endpoint decrypts inside its own helper and returns only `{ ok, error_class? }`; plaintext never leaves the server-side function scope. (rbac-4 explicit doc.)

## Rollout Sequence

Two-wave deploy (one wave per PR). Each wave's order keeps partial deploy states valid. (Patch 17 — MSA-3.)

**Wave 1 — Phase 1a deploy (formats):**
1. Apply `phase27a_iac_v2_formats.sql` via Supabase MCP. CHECK widening + compliance_refs column. v1 writers see no behavior change (superset CHECK).
2. Deploy `backend` (Vercel) with `scanner-findings.ts` framework filter whitelist extended to 9 values (M12). Backend now serves the wider filter; worker still runs v1 image so writers haven't started emitting new framework values yet.
3. Deploy `depscanner` (Fly) with M3 detectors + M4 Checkov adapter. Worker now writes the new framework values + compliance_refs. Backend already accepts them.
4. Deploy `frontend` (Vercel) with M13a/M14/M15/M16. Users see new chips + compliance badges.

Each Wave 1 step is reversible:
- (1) → run `phase27a` rollback (DELETE v2-only rows then re-narrow CHECK; Patch 16 pattern).
- (2) → redeploy previous backend; filter narrows again, but DB rows in new framework values stay (`scanner-findings.ts` simply won't return them).
- (3) → redeploy previous depscanner; new framework values stop being written, existing rows preserved.
- (4) → redeploy previous frontend; chips/badges revert.

**Wave 2 — Phase 1b deploy (registries + creds + cache):** opens immediately after 1a is observed-stable (24h smoke window).
1. Apply `phase27b_iac_v2_registries.sql` via Supabase MCP. New tables + triggers + FKs + `image_source` CHECK widening + cache reaper function. (Document the BEGIN/COMMIT contract per Patch 16; populated-table rollback handling per MSA-2.)
2. Deploy `backend` with M10/M11 routes + extended `rotateEncryptionKeys` (M2.5) + new audit-log emission. Backend serves cred endpoints; worker still runs v1a image so creds aren't being read by scanners yet.
3. Deploy `depscanner` with M5 (registry-auth resolver) + M6 (Trivy runner extension + crane probe) + M7 (cache storage) + M8 (orchestrator extension) + M9 (crane install in Dockerfile). Worker now reads PRC + PCI, mints registry auth, probes digests, hits cache, runs Trivy on miss, upserts cache.
4. Deploy `frontend` with M13b/M17/M18. Users see RegistryCredentialsSection + ConfiguredImagesSection.
5. Schedule the `cleanup_container_image_scan_cache(30)` reaper via pg_cron or QStash (one-line config; doesn't gate the deploy).

Each Wave 2 step is reversible identically (rollback migration → previous backend → previous depscanner image → previous frontend).

**Cross-wave invariants:**
- 1b's migration MUST not run before 1a's. 1b's worker MUST not deploy before 1b's migration.
- After every rebase against main: re-run `cd backend/depscanner && npm run schema:dump` and force-add the diff to the next commit (`feedback_schema_dump_rebase.md`).
- Wave 1 → Wave 2 minimum gap: 24h soak. Real production data through 1a paths in real customer projects before Wave 2 lands.

## Data Model

### Migrations (split per Phase 1a / 1b)

The migration is split across two files matching the PR split (Debate D). Both files use the same atomicity + populated-table rollback pattern. `phase27a_iac_v2_formats.sql` ships with Phase 1a's PR; `phase27b_iac_v2_registries.sql` ships with Phase 1b's PR (and depends on 27a being applied first — the framework values it'll write must already be allowed by the CHECK).

#### `backend/database/phase27a_iac_v2_formats.sql` (Phase 1a)

```sql
-- Phase 27a: IaC + Container Scanning v2 — Formats
-- Adds:
--   - project_iac_findings.framework CHECK extension (3 → 9 values)
--   - project_iac_findings.compliance_refs JSONB
--
-- Independent of phase27b; if 1a stalls, 27a stays in production.

BEGIN;

ALTER TABLE project_iac_findings DROP CONSTRAINT IF EXISTS project_iac_findings_framework_check;
ALTER TABLE project_iac_findings ADD CONSTRAINT project_iac_findings_framework_check
  CHECK (framework IN (
    'terraform', 'kubernetes', 'dockerfile',
    'helm', 'cloudformation', 'arm', 'bicep', 'serverless',
    'github_actions'
  ));
-- 'kustomize' deliberately omitted — kustomization.yaml surfaces as 'kubernetes' (Debate F).

ALTER TABLE project_iac_findings ADD COLUMN IF NOT EXISTS compliance_refs JSONB;
-- GIN index gated to v3 (project-scoped lists in v2, no cross-org rollups).

COMMIT;
```

**Rollback `phase27a_iac_v2_formats_rollback.sql`:**
```sql
BEGIN;
DELETE FROM project_iac_findings
  WHERE framework NOT IN ('terraform', 'kubernetes', 'dockerfile');
ALTER TABLE project_iac_findings DROP CONSTRAINT IF EXISTS project_iac_findings_framework_check;
ALTER TABLE project_iac_findings ADD CONSTRAINT project_iac_findings_framework_check
  CHECK (framework IN ('terraform', 'kubernetes', 'dockerfile'));
ALTER TABLE project_iac_findings DROP COLUMN IF EXISTS compliance_refs;
COMMIT;
```

#### `backend/database/phase27b_iac_v2_registries.sql` (Phase 1b)

```sql
-- Phase 27b: IaC + Container Scanning v2 — Registries + creds + cache
-- Hard prereq: phase27a must already be applied (framework values it writes
-- via configured-image scans must be allowed by the CHECK).
-- Adds:
--   - organization_registry_credentials (ORG-scoped encrypted creds for ECR/GCR/ACR/...)
--   - project_configured_images (per-project scan-target list referencing org creds)
--   - container_image_scan_cache (global digest-keyed result cache)
--   - project_container_findings.image_source CHECK extension (1 → 2 values)
--   - cleanup_container_image_scan_cache() reaper function
--
-- Cred scope decision (locked 2026-05-02): creds live at the ORGANIZATION level,
-- mirroring the BYOK provider precedent (organization_ai_providers). One cred
-- shared across all projects in the org. Cred CRUD is org-routed; cross-org
-- attachment from project_configured_images is blocked by composite FK.
--
-- No changes to phase25_iac_container_scanning.sql artifacts. v1 carry-forward
-- continues to work unchanged.
--
-- Atomicity: this entire migration MUST run in a single transaction.
-- Do NOT split table creation from trigger creation across PRs.

BEGIN;

-- ============================================================
-- Organization-scoped encrypted registry credentials
-- ============================================================
CREATE TABLE IF NOT EXISTS organization_registry_credentials (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  registry_type TEXT NOT NULL CHECK (
    registry_type IN ('ghcr','ecr','gcr','acr','dockerhub','quay','harbor','jfrog','custom')
  ),
  -- registry_url required for: harbor, jfrog, custom; nullable for cloud-managed.
  registry_url TEXT,
  display_name TEXT NOT NULL,
  -- credential_shape discriminates the JSON structure stored under encrypted_credentials.
  -- Set of allowed shapes (validated server-side at insert time):
  --   username_password         { "username": "...", "password": "..." }
  --   aws_keys                  { "access_key_id": "...", "secret_access_key": "...", "session_token"?, "region": "..." }
  --   gcp_service_account_key   { "service_account_json": "{...}" }
  --   azure_service_principal   { "client_id": "...", "client_secret": "...", "tenant_id": "..." }
  --   token                     { "token": "..." }
  credential_shape TEXT NOT NULL CHECK (
    credential_shape IN ('username_password','aws_keys','gcp_service_account_key','azure_service_principal','token')
  ),
  -- Composite CHECK enumerating valid (registry_type, credential_shape) pairs.
  -- Catches mismatched shapes at INSERT (DMA-r2-4 / DMA-6) before scan-time.
  CONSTRAINT orc_registry_shape_pair_check CHECK (
    (registry_type, credential_shape) IN (
      ('ghcr',       'username_password'),
      ('ghcr',       'token'),
      ('ecr',        'aws_keys'),
      ('gcr',        'gcp_service_account_key'),
      ('acr',        'azure_service_principal'),
      ('acr',        'username_password'),
      ('dockerhub',  'username_password'),
      ('dockerhub',  'token'),
      ('quay',       'username_password'),
      ('quay',       'token'),
      ('harbor',     'username_password'),
      ('jfrog',      'username_password'),
      ('jfrog',      'token'),
      ('custom',     'username_password'),
      ('custom',     'token')
    )
  ),
  encrypted_credentials TEXT NOT NULL,
  encryption_key_version INTEGER NOT NULL DEFAULT 1,
  last_used_at TIMESTAMPTZ,  -- updated by worker after successful auth (DMA-7)
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Composite UNIQUE so project_configured_images can FK on (id, organization_id)
  -- and Postgres enforces same-org cred attachment regardless of code path.
  -- (Patch 1 — DMA-1 / MTD-3, 9/13 consensus; rescoped to org per 2026-05-02.)
  CONSTRAINT orc_id_org_uq UNIQUE (id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_orc_org ON organization_registry_credentials(organization_id);

-- No org_id derivation trigger needed: organization_id is set directly by the
-- route layer (which authenticateUser already validated org membership against
-- the :id path segment). The composite UNIQUE + composite FK on
-- project_configured_images below prevent cross-org cred reuse downstream.

-- Helper trigger used by project_configured_images below. Mirrors
-- enforce_finding_org_id() (phase25). BEFORE INSERT OR UPDATE (no column list)
-- so org re-derives on every UPDATE; Patch 5 / MTD-2.
CREATE OR REPLACE FUNCTION enforce_project_scoped_org_id() RETURNS TRIGGER AS $$
BEGIN
  NEW.organization_id := (SELECT organization_id FROM projects WHERE id = NEW.project_id);
  IF NEW.organization_id IS NULL THEN
    RAISE EXCEPTION 'enforce_project_scoped_org_id: project % not found', NEW.project_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ============================================================
-- Manually configured container images (scan targets beyond Dockerfile FROM)
-- ============================================================
CREATE TABLE IF NOT EXISTS project_configured_images (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  image_reference TEXT NOT NULL,
  credentials_id UUID,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Composite FK: enforces cred.organization_id MUST match image.organization_id
  -- at the DB layer. A POST/PATCH that attaches Org A's cred to Org B's image
  -- fails here regardless of code path (route bypass, service-role insert,
  -- future internal RPC, etc.). (Patch 1 — DMA-1 / MTD-3, 9/13 consensus;
  -- rescoped to org per 2026-05-02 cred-scope decision.)
  -- ON DELETE SET NULL: deleting a cred soft-detaches its images; UI surfaces
  -- "N images affected; they will become public-pull-only" before confirming.
  CONSTRAINT pci_credentials_same_org_fk
    FOREIGN KEY (credentials_id, organization_id)
    REFERENCES organization_registry_credentials(id, organization_id)
    ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pci_project_image
  ON project_configured_images(project_id, image_reference);
CREATE INDEX IF NOT EXISTS idx_pci_project_enabled
  ON project_configured_images(project_id, enabled) WHERE enabled = true;
CREATE INDEX IF NOT EXISTS idx_pci_org ON project_configured_images(organization_id);

DROP TRIGGER IF EXISTS project_configured_images_enforce_org_id ON project_configured_images;
CREATE TRIGGER project_configured_images_enforce_org_id
  BEFORE INSERT OR UPDATE ON project_configured_images
  FOR EACH ROW EXECUTE FUNCTION enforce_project_scoped_org_id();

-- Cross-org move guard: if a configured image's project gets reparented to a
-- project in a different org (rare but possible during admin restructuring),
-- drop its credentials_id. The composite FK above already prevents the move
-- from succeeding with a non-NULL credentials_id whose org doesn't match, but
-- the explicit NULL is clearer than a constraint-violation crash. Same-org
-- project moves DO NOT drop the cred (creds are org-shared). (Patch 1.)
CREATE OR REPLACE FUNCTION pci_null_credentials_id_on_org_move() RETURNS TRIGGER AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND NEW.organization_id != OLD.organization_id THEN
    NEW.credentials_id := NULL;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pci_null_creds_on_org_move ON project_configured_images;
CREATE TRIGGER pci_null_creds_on_org_move
  BEFORE UPDATE ON project_configured_images
  FOR EACH ROW EXECUTE FUNCTION pci_null_credentials_id_on_org_move();

-- ============================================================
-- Global image-digest scan cache.
--
-- Content-addressed: the digest commits the exact image bytes, so sharing the
-- row across orgs is safe by construction. NO org_id column. NO user-controlled
-- pull-string column. Forensics columns (first_scanned_by_org_id, run_id) are
-- INSERT-only and NEVER returned via API. (Patch 4 — MTD-1 / DMA-r2-5.)
--
-- Composite PK includes scanner discriminator + Trivy DB-version-day so
-- multi-scanner Phase 2 (Grype/Syft) and CVE-DB freshness within the 7-day TTL
-- are addressed. (DMA-r2-2 / MTD-r2-5 / skeptic-f7.)
--
-- Worker writes only when ALL of: Trivy exit=0, no warnings, structurally-valid
-- parse, crane probe digest matches Trivy's RepoDigest. Cache write contract is
-- enforced by callers, not the table itself. (Patch 7 — FMH-P0-2.)
-- A nightly reaper drops rows older than 30 days. (MSA-7 — see below.)
-- ============================================================
CREATE TABLE IF NOT EXISTS container_image_scan_cache (
  -- Bare 64-hex digest (no 'sha256:' prefix, no 'repo@' prefix), optional
  -- platform suffix for manifest-list resolution. Patch 3 — normalizeDigest()
  -- helper produces this canonical form at every reader/writer.
  image_digest TEXT NOT NULL CHECK (image_digest ~ '^[a-f0-9]{64}(\+linux/(amd64|arm64))?$'),
  -- Discriminator so Grype/Syft (Phase 2+) don't collide on PK with Trivy.
  scanner TEXT NOT NULL CHECK (scanner IN ('trivy')),
  -- Trivy/Checkov binary version that produced this scan.
  scanner_version TEXT NOT NULL,
  -- Trivy CVE DB date (UTC YYYY-MM-DD). Within the 7-day TTL the CVE DB can
  -- update; including it in the PK forces a re-scan when the DB rolls over.
  trivy_db_version_day TEXT NOT NULL CHECK (trivy_db_version_day ~ '^\d{4}-\d{2}-\d{2}$'),
  -- Scan result body. STORAGE EXTENDED + 1MB cap; parser truncates to top-N
  -- findings sorted by severity desc if larger. (DMA-r2-3 / FMH-P1-7.)
  scan_results JSONB NOT NULL CHECK (octet_length(scan_results::text) <= 1048576),
  -- sha256 of canonicalized scan_results JSON. Verified on every read; mismatch
  -- → log warning + treat as cache miss. Defends against silent DB corruption.
  -- (FMH-r2-3.)
  scan_results_hash TEXT NOT NULL CHECK (scan_results_hash ~ '^[a-f0-9]{64}$'),
  -- Forensics-only attribution. NEVER read by user-facing code paths. Recovery
  -- of pull-string for debugging happens via extraction_logs WHERE
  -- organization_id = ? joined by digest at debug time. (Patch 4.)
  first_scanned_by_org_id UUID REFERENCES organizations(id) ON DELETE SET NULL,
  first_scanned_run_id TEXT,
  scanned_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (image_digest, scanner, scanner_version, trivy_db_version_day)
);

ALTER TABLE container_image_scan_cache
  ALTER COLUMN scan_results SET STORAGE EXTENDED;

CREATE INDEX IF NOT EXISTS idx_cisc_scanned_at
  ON container_image_scan_cache(scanned_at);

-- ============================================================
-- 30-day cache reaper. Implemented as a SQL function called by a Supabase
-- pg_cron schedule (or QStash daily at 03:00 UTC if pg_cron unavailable).
-- (MSA-7 / FMH-P1-15 — claimed in v1 design but not built; ship in same PR.)
-- ============================================================
CREATE OR REPLACE FUNCTION cleanup_container_image_scan_cache(
  retention_days INTEGER DEFAULT 30
) RETURNS INTEGER AS $$
DECLARE
  rows_deleted INTEGER;
BEGIN
  DELETE FROM container_image_scan_cache
    WHERE scanned_at < NOW() - (retention_days || ' days')::INTERVAL;
  GET DIAGNOSTICS rows_deleted = ROW_COUNT;
  RETURN rows_deleted;
END;
$$ LANGUAGE plpgsql;

-- pg_cron schedule (apply as part of phase27 if pg_cron extension installed):
-- SELECT cron.schedule('container-image-scan-cache-reaper', '0 3 * * *',
--   'SELECT cleanup_container_image_scan_cache(30);');
-- Otherwise wire via QStash schedule in backend/src/lib/cron.ts.

-- ============================================================
-- Extend project_container_findings.image_source to allow configured-image
-- scans. Phase 25 only allowed 'dockerfile_base'; M8 emits configured-image
-- findings that need 'configured_image' to satisfy the row contract.
-- WITHOUT this widening, M8 cannot land — every configured-image insert
-- violates 23514. (Patch 2 — skeptic-f1 / DMA-r2-1 / MSA-r2-1, 6/13 consensus.)
-- ============================================================
ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
  CHECK (image_source IN ('dockerfile_base', 'configured_image'));

COMMIT;
```

### Schema dump

After applying *either* migration, run `cd backend/depscanner && npm run schema:dump` per CLAUDE.md. Same commit. CI will fail otherwise (`.github/workflows/schema-check.yml`). Phase 1a's PR redumps after 27a; Phase 1b's PR redumps after 27b is added on top.

### Migration file ordering

- `phase27a_iac_v2_formats.sql` — sorts after `phase26_*`. Ships with 1a.
- `phase27b_iac_v2_registries.sql` — sorts after 27a (lexicographically and by dependency: 27b's `image_source` widening is independent of 27a, but 27b's M8 worker code writes findings using framework values that 27a opens). Ships with 1b.

Naming follows the historical-prefix convention; a/b suffix is the v2 micro-phase split. (CLAUDE.md notes prefixes are stable but carry no load-bearing ordering beyond what filenames imply.)

### Rollback `phase27b_iac_v2_registries_rollback.sql`

Mirrors phase25's pattern. Atomic; handles populated tables before re-narrowing CHECKs so the rollback runs cleanly on any DB where 1b has emitted v2-only rows. (Patch 16 — MSA-1 / MSA-2, 3/13 consensus.)

```sql
BEGIN;

-- Drop new triggers first so DROP TABLE doesn't trip them.
DROP TRIGGER IF EXISTS pci_null_creds_on_org_move ON project_configured_images;
DROP TRIGGER IF EXISTS project_configured_images_enforce_org_id ON project_configured_images;

-- FK-aware drop order. CASCADE absorbs any external references created by
-- future phases that we don't know about here.
DROP TABLE IF EXISTS container_image_scan_cache CASCADE;
DROP TABLE IF EXISTS project_configured_images CASCADE;
DROP TABLE IF EXISTS organization_registry_credentials CASCADE;

-- Reverse image_source CHECK widening — DELETE v2-only rows first or the
-- narrow CHECK fails. Documented behavior: rollback discards configured-image
-- container findings. (Patch 2 mirror.)
DELETE FROM project_container_findings WHERE image_source = 'configured_image';
ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
  CHECK (image_source IN ('dockerfile_base'));

-- Drop helper functions (no remaining dependents after table drops).
DROP FUNCTION IF EXISTS cleanup_container_image_scan_cache(INTEGER);
DROP FUNCTION IF EXISTS pci_null_credentials_id_on_org_move();
-- enforce_project_scoped_org_id() left in place — could be used by future
-- phases. Drop it explicitly only if no other phase has adopted it.

COMMIT;
```

(For the Phase 1a rollback see the inline `phase27a_iac_v2_formats_rollback.sql` block above — it independently reverses the framework CHECK widening and drops `compliance_refs`.)

## API Design

### Endpoints

Cred CRUD is gated by **org-level `manage_integrations`** (matching the BYOK
provider precedent in `organizations.ts → hasManageIntegrations()`), not the
project-team `manage_projects` role. Rationale: equal blast-radius. AWS root
keys / GCP SA / Azure SP have at least the same destructive potential as a
BYOK Anthropic key, so they belong under the same gate. Configured-images stay
project-scoped because they don't carry secrets. (Patch 18 — rbac-1, 3/13.)

PATCH bodies use a per-route allow-list (`pickAllowed(body, ['display_name'])`)
to block field smuggling — `.update(req.body)` patterns 400 on extra keys.
(MTD-9 / rbac-r2-3.)

**Cred routes are org-scoped** (no `/projects/:projectId` segment) — matches BYOK provider routes. **Configured-image routes stay project-scoped** because images are per-project scan targets that happen to reference an org-shared cred.

| Method | Route | Auth | Permission | Allow-list | Description |
|---|---|---|---|---|---|
| GET | `/api/organizations/:id/registry-credentials` | authenticateUser | `checkOrgAccess` | n/a | List creds for the org (metadata only — encrypted blob never returned). |
| POST | `/api/organizations/:id/registry-credentials` | authenticateUser | **`checkOrgManageIntegrations`** | full body validated | Create cred. Body: `{ registry_type, registry_url?, display_name, credential_shape, plaintext_credentials }`. Server validates shape, encrypts, inserts. |
| PATCH | `/api/organizations/:id/registry-credentials/:credId` | authenticateUser | **`checkOrgManageIntegrations`** | `['display_name']` | Update display_name only. |
| PATCH | `/api/organizations/:id/registry-credentials/:credId/rotate` | authenticateUser | **`checkOrgManageIntegrations`** | `['credentials']` | Rotate cred in place. Body: `{ credentials: CredentialPlaintext }`. Re-encrypts and bumps `encryption_key_version`. Image references stay attached. (architect-r2-f16 / DMA-4.) |
| DELETE | `/api/organizations/:id/registry-credentials/:credId` | authenticateUser | **`checkOrgManageIntegrations`** | n/a | Delete cred. Configured images across all projects in the org that reference it have `credentials_id` set NULL via the composite FK's `ON DELETE SET NULL`. |
| POST | `/api/organizations/:id/registry-credentials/:credId/test` | authenticateUser | **`checkOrgManageIntegrations`** | n/a | One-shot decrypt + auth-mint dry-run; returns `{ ok, error_class? }` without scanning. (TSA-r2-7 / opportunity-scout-f2.) |
| GET | `/api/organizations/:id/projects/:projectId/configured-images` | authenticateUser | `checkProjectAccess` | n/a | List images for this project. Joins `organization_registry_credentials` for cred metadata (display_name + registry_type, never decrypted). |
| POST | `/api/organizations/:id/projects/:projectId/configured-images` | authenticateUser | `checkProjectManagePermission` | full body validated | Add image. Body: `{ image_reference, credentials_id?, enabled? }`. `credentials_id` (if provided) MUST belong to the same org as the project. Enforces per-project cap of 20 enabled images. |
| PATCH | `/api/organizations/:id/projects/:projectId/configured-images/:imageId` | authenticateUser | `checkProjectManagePermission` | `['enabled', 'credentials_id']` | Toggle enabled or swap to a different same-org cred. |
| DELETE | `/api/organizations/:id/projects/:projectId/configured-images/:imageId` | authenticateUser | `checkProjectManagePermission` | n/a | Delete. |
| GET | `/api/organizations/:id/projects/:projectId/iac-findings` | authenticateUser | `checkProjectAccess` | n/a | **Existing** — extend `framework` filter whitelist to 9 values. |

**New helper** (`backend/src/lib/rbac.ts`): `checkOrgManageIntegrations(userId, orgId)` mirrors `hasManageIntegrations()` in `routes/organizations.ts`. Single-source for both BYOK provider routes and registry-credentials routes.

**Audit log emission** (rbac-r2-4 / opportunity-scout-f9): every cred POST / PATCH / PATCH-rotate / DELETE / test emits an `organization_activities` row with `actor_user_id`, `target_credential_id`, `event_type`, redacted before insert. Worker-side per-scan decrypt also emits `cred_used` (one row per scan, not per image — keeps volume bounded).

### Types (TypeScript, frontend `lib/api.ts` + backend `routes/`)

```typescript
// Shared shape — never expose plaintext_credentials except in POST body.
// Org-scoped: no project_id field.
export interface RegistryCredential {
  id: string;
  organization_id: string;
  registry_type: 'ghcr' | 'ecr' | 'gcr' | 'acr' | 'dockerhub' | 'quay' | 'harbor' | 'jfrog' | 'custom';
  registry_url: string | null;
  display_name: string;
  credential_shape: 'username_password' | 'aws_keys' | 'gcp_service_account_key' | 'azure_service_principal' | 'token';
  // ⚠️ encrypted_credentials NOT in the API response shape.
  encryption_key_version: number;
  last_used_at: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

export type CredentialPlaintext =
  | { shape: 'username_password'; username: string; password: string }
  | { shape: 'aws_keys'; access_key_id: string; secret_access_key: string; session_token?: string; region: string }
  | { shape: 'gcp_service_account_key'; service_account_json: string }
  | { shape: 'azure_service_principal'; client_id: string; client_secret: string; tenant_id: string }
  | { shape: 'token'; token: string };

export interface CreateRegistryCredentialBody {
  registry_type: RegistryCredential['registry_type'];
  registry_url?: string | null;
  display_name: string;
  credentials: CredentialPlaintext;  // server validates shape match, encrypts, drops plaintext
}

export interface ConfiguredImage {
  id: string;
  project_id: string;
  organization_id: string;
  image_reference: string;
  credentials_id: string | null;
  credentials_display?: { display_name: string; registry_type: RegistryCredential['registry_type'] } | null;
  enabled: boolean;
  created_by: string | null;
  created_at: string;
  updated_at: string;
}

// IaCFinding shape extension — already has `metadata`, adds `compliance_refs`
export interface IaCFinding {
  // ... existing fields ...
  framework:
    | 'terraform' | 'kubernetes' | 'dockerfile'
    | 'helm' | 'cloudformation' | 'arm' | 'bicep'
    | 'serverless' | 'github_actions';
  compliance_refs: Record<string, string[]> | null;
}
// kustomize NOT in the union — kustomization.yaml files surface as 'kubernetes'.
```

### Error cases

- 400 — `credential_shape` mismatches `registry_type` (e.g., `ecr` paired with `username_password` is rejected).
- 400 — `registry_url` missing for `harbor`/`jfrog`/`custom`.
- 400 — `image_reference` doesn't match a docker-pullable shape (regex: `^[a-z0-9._\-/:]+(@sha256:[a-f0-9]{64})?$`).
- 400 — `AI_ENCRYPTION_KEY` not configured (mirrors BYOK path).
- 403 — RBAC fail (write without `manage_projects`).
- 404 — cred / image / project not found.
- 500 — encryption / decryption failure (raw error stays in `console.error`, generic message returned per `feedback_no_raw_errors_to_users.md`).

### Performance

- All list endpoints scoped by `project_id` index; <50 rows expected per project. No pagination needed at v1.
- Mutation endpoints touch one row each.
- Encryption: ~1ms per credential. Decryption only happens worker-side, not on the API path.

## Frontend Design

### Pages & routes

No new routes. Phase 1 work lives entirely inside the existing **Project Settings → Scanners** route (registered in `frontend/src/app/routes.tsx` for v1 already).

### Component tree

```
ScannersPanel (existing — extend)
├── Auto-detected Coverage section (existing)
├── IaC + Container Findings rollup (existing)
├── Last scan + Trigger rescan (existing)
│
├── ──── NEW PHASE 1 SECTIONS ────
│
├── RegistryCredentialsSection (new)
│   ├── List of RegistryCredentialRow
│   ├── "Add credential" button → AddRegistryCredentialDialog
│   └── Empty state ("No private registries configured")
│
└── ConfiguredImagesSection (new)
    ├── List of ConfiguredImageRow
    ├── "Add image" button → AddConfiguredImageDialog
    └── Empty state ("Only Dockerfile-derived base images are scanned by default")

VulnerabilityExpandableTable (existing — extend)
├── Framework filter chips (3 → 9)
└── Row variants (extend frameworkLabel)

InfraFindingCard (existing — extend)
├── Framework label (extend switch)
├── Severity + depscore (existing)
├── Code snippet (existing)
├── ──── NEW: Compliance refs strip (CIS / SOC2 / NIST badges) ────
├── Rule doc link (existing)
└── Suppress / risk-accept (existing)

framework-icon.tsx (existing — extend)
└── Add 6 new icon components (Helm, CFN, ARM, Bicep, Serverless, GH Actions)
```

### Design specifications

Following `.cursor/skills/frontend-design/SKILL.md` and `.cursor/skills/ui-principles/SKILL.md`:

- **RegistryCredentialsSection card:** `rounded-lg border border-border bg-background-card p-6`, identical chrome to existing IaC + Container Scanners card above it. Section heading `text-base font-semibold text-foreground`, subhead `text-sm text-foreground-secondary`. Subhead text: "Registry credentials are shared across all projects in this organization." — sets correct expectation that creating one cred makes it available everywhere.
- **RegistryCredentialRow:** flex row with registry-type icon (24×24 svg from `simple-icons` — `SiAmazonaws`, `SiGooglecloud`, `SiMicrosoftazure`, etc.) + `display_name` (foreground) + `registry_type` chip (zinc/border style matching existing infra-type chips) + masked URL hint + delete button (outline variant, destructive on hover) per `feedback_dialog_pattern.md`.
- **AddRegistryCredentialDialog:** two-tone popup, `hideClose`, registry-type select first → renders shape-aware credential form. Outline cancel + bordered destructive primary, matching `aegis/ThreadList.tsx` template.
- **ConfiguredImageRow:** image_reference monospaced + cred-link chip (clickable to scroll to that cred row) + enabled toggle (Switch component from radix) + delete.
- **Compliance refs strip on InfraFindingCard:** small pill-style badges, `text-[10px] font-medium`. Shape: `[CIS AWS 1.5] [CIS K8s 5.1.3] [SOC 2 CC6.6]`. Subtle border, no fill. If `compliance_refs` is null or empty, render nothing.
- **Framework chips in VulnerabilityExpandableTable:** existing pattern (zinc-bordered pill). Add 6 new chips in a stable order: `[Terraform] [Kubernetes] [Dockerfile] [Helm] [CloudFormation] [ARM] [Bicep] [Serverless] [GitHub Actions]`. (No Kustomize chip — surfaces as Kubernetes per Debate F.)

### Loading / empty / error states

- **RegistryCredentialsSection** — skeleton shimmer matching the row shape; empty: "No private registries configured. The Phase 1 scanner pulls public images and ghcr.io repos owned by your installed GitHub App without any setup." with a "+ Add credential" CTA.
- **ConfiguredImagesSection** — empty: "Only Dockerfile-derived base images are scanned by default. Add a registry image to scan it on every extraction."
- **AddRegistryCredentialDialog** — error toast on backend rejection (per `feedback_no_raw_errors_to_users.md` — never show raw backend message; render the validation hint only).
- **InfraFindingCard compliance strip** — render nothing when null/empty (no "no compliance" message — that's noise).

### Performance

- ScannersPanel is <100 rows total across both new sections; no virtual scrolling needed.
- VulnerabilityExpandableTable already paginates server-side; no change.
- Framework icons lazy-load via the existing `framework-icon.tsx` registry (one Simple Icons component per framework, code-split per Vite default).

### Reference patterns

- **AddRegistryCredentialDialog** — same modal shape as `AegisProviderDialog.tsx` (existing BYOK provider add-modal). Discriminated union → shape-aware form. Steal the validation pattern.
- **ConfiguredImageRow toggle** — same toggle pattern as project-settings notification toggles (`frontend/src/app/pages/projects/settings/notifications.tsx`).
- **Compliance badge strip** — visual reference: GitHub's "compliance" badges on advisories.

## Implementation Tasks

Ordered for incremental verifiability. Each task has acceptance criteria, complexity (S/M/L), and primary file paths.

### M1a — DB migration formats + schema dump (S) [Phase 1a]

**Files:** `backend/database/phase27a_iac_v2_formats.sql` + `phase27a_iac_v2_formats_rollback.sql` + `backend/database/schema.sql` (regenerated).

**Steps:**
1. Apply phase27a via Supabase MCP. Just framework CHECK widening + `compliance_refs JSONB`.
2. Run `cd backend/depscanner && npm run schema:dump`.

**Acceptance:** Migration applies cleanly to a fresh Supabase project; rollback reverses cleanly (incl. populated-table DELETE); CI `schema-check.yml` passes.

### M1b — DB migration registries+cache + schema dump (S) [Phase 1b]

**Files:** `backend/database/phase27b_iac_v2_registries.sql` + `phase27b_iac_v2_registries_rollback.sql` + `backend/database/schema.sql` (regenerated).

**Prereq:** M1a applied.

**Steps:**
1. Apply phase27b via Supabase MCP. New tables (`organization_registry_credentials`, `project_configured_images`, `container_image_scan_cache`), helper trigger, composite same-org FK, image_source CHECK widening, reaper function.
2. Run `cd backend/depscanner && npm run schema:dump`.

**Acceptance:** Migration applies cleanly atop phase27a; rollback reverses cleanly with populated-table handling; CI `schema-check.yml` passes; 4 BEGIN/COMMIT pairs balanced.

### M2 — Backend types extension (formats only) (S) [Phase 1a]

**Files:** `backend/depscanner/src/scanners/types.ts`, `frontend/src/lib/api.ts`.

**Steps:**
1. Extend `IaCFramework` union from 3 to 9 values. Export as `IAC_FRAMEWORKS as const` from one location (`backend/depscanner/src/scanners/types.ts`); all readers import from there. Single-source-of-truth blocks framework-enum drift across the 4-7 places it's currently duplicated. (architect-r2-f17.)
2. Add `compliance_refs: Record<string, string[]> | null` to `IaCFinding`.

**Acceptance:** `tsc --noEmit` clean across all three packages. Grep confirms no inline-literal framework lists remain anywhere except the canonical export.

### M2b — Worker types (registries) (S) [Phase 1b]

**Files:** `backend/depscanner/src/scanners/types.ts`, `frontend/src/lib/api.ts`.

**Steps:**
1. Add `RegistryCredential` (org-scoped, no `project_id`), `CredentialPlaintext` (5-shape discriminated union), `ConfiguredImage` types (frontend + a worker-only decrypted shape backend-side).
2. Helper type `DecryptedCredential` lives in `backend/depscanner/src/scanners/registry-auth.ts`; never imported into route files (rbac-r2-7 invariant).

**Acceptance:** `tsc --noEmit` clean.

### M2.5 — Encryption helper sharing (S) — resolves OQ-A

**Files:**
- `scripts/sync-encryption.ts` (new)
- `backend/depscanner/src/lib/encryption.ts` (new — generated, .gitignored OR committed-and-CI-checked, see step 2)
- `.github/workflows/encryption-sync-check.yml` (new)
- `backend/src/lib/ai/encryption.ts` (extend `rotateEncryptionKeys` only)

**Steps:**
1. `scripts/sync-encryption.ts` copies `backend/src/lib/ai/encryption.ts` → `backend/depscanner/src/lib/encryption.ts` at `docker:prepare`. Mirrors the schema.sql staging pattern (CLAUDE.md). Decision: commit the copy (not gitignored) so depscanner package is buildable from a fresh checkout without running the script.
2. New CI workflow `encryption-sync-check.yml` mirroring `schema-check.yml`: re-runs the sync script and fails the PR if the depscanner copy diverges from source. Catches "fixed in one place but not the other" rotation bugs at PR review time, not at scan-time.
3. Round-trip unit test in BOTH packages running against a checked-in fixture file (`fixtures/encryption-roundtrip.json`) containing known plaintext + known ciphertext. Both packages must decrypt to the same value. Catches encryption-key-version-handling drift.
4. Extend `backend/src/lib/ai/encryption.ts` `rotateEncryptionKeys()` to also enumerate `organization_registry_credentials` (currently only walks `organization_ai_providers`). Without this, rotation silently leaves PRC rows under the old key. (MSA-9 / WPA-r2-7.) Integration test with populated PRC table.

**Acceptance:**
- Both packages compile with the encryption helper available.
- Round-trip tests green in both packages.
- `encryption-sync-check.yml` red when the source diverges from the copy without resync.
- `rotateEncryptionKeys` test confirms PRC rows re-encrypt with the new key version.

(Patch 14 — architect-r2-f11 / skeptic-f5 / WPA-r2-7, 5/13 consensus.)

### M3 — Detect-infra extension (M)

**File:** `backend/depscanner/src/scanners/detect-infra.ts`.

**Detectors to add:**
- `helm` — file basename `Chart.yaml` (top-level Helm chart marker)
- `cloudformation` — YAML/JSON with `AWSTemplateFormatVersion:` OR `Resources:` with at least one `Type: AWS::*` value (head-of-file scan, 4kb cap as v1)
- `arm` — JSON with `$schema` matching `https://schema.management.azure.com/schemas/.../deploymentTemplate.json#`
- `bicep` — file extension `.bicep`
- `serverless` — basename `serverless.yml` / `serverless.yaml` / `serverless.json`
- `github_actions` — files under `.github/workflows/*.yml` or `.yaml` at the repo root only (no `**/.github/workflows/` glob — per MTD-r2-8, restrict to root to avoid scanning vendored sub-repos' workflows)

**Kustomize:** kustomization.yaml / kustomization.yml files are detected and tagged as the existing **`kubernetes`** framework — no separate `kustomize` framework value (Debate F). Checkov's `kubernetes` framework scans them correctly. Free coverage; no extra UI surface.

**Note:** SAM and CDK do NOT get separate detectors (per Checkov's coverage). The `cloudformation` detector picks up SAM via the `Transform: AWS::Serverless-2016-10-31` header. CDK is **not** scanned in Phase 1 — CDK code is TypeScript/Python that compiles to CloudFormation via `cdk synth`, which we don't run. UI copy must say "AWS SAM is scanned via CloudFormation"; CDK gets explicit "not yet supported" copy. (CR-2.)

**Acceptance:** Unit tests in `__tests__/detect-infra.test.ts` cover each detector + a multi-format fixture repo + a no-infra repo.

### M4 — Checkov adapter extension (M)

**File:** `backend/depscanner/src/scanners/checkov.ts`.

**Steps:**
1. Extend `FRAMEWORK_TO_CHECKOV` map: 7 new entries.
2. Extend `CHECK_TYPE_TO_FRAMEWORK` reverse-map: 7 new entries (Checkov's `check_type` values match framework keys).
3. Add `extractComplianceRefs(c.metadata)` helper — pulls from `metadata.benchmark` / `metadata.guideline` / similar fields. Output: `{ "cis_aws": [...], "cis_kubernetes": [...], "soc2": [...], "nist_800_53": [...] }`. NULL when no refs found.
4. Wire `compliance_refs` into the emitted `IaCFinding`.

**Acceptance:** Unit tests in `__tests__/checkov.test.ts` covering each new framework + compliance-ref extraction with realistic Checkov output fixtures.

### M5 — Registry auth resolver (M)

**Files (new):** `backend/depscanner/src/scanners/registry-auth.ts` + `__tests__/registry-auth.test.ts`.

**Functions:**
- `decryptCredential(blob: string, version: number): CredentialPlaintext` — imports `decryptApiKey` from the synced-at-build-time `backend/depscanner/src/lib/encryption.ts` (per M2.5). No relative-import-into-backend hack; no package extraction.
- `mintEcrAuth({ access_key_id, secret_access_key, session_token?, region }): Promise<DockerAuthEntry>` — calls AWS STS / ECR token endpoint via `@aws-sdk/client-ecr`; tokens expire in 12h, mint fresh per scan.
- `mintGcpAuth({ service_account_json }): DockerAuthEntry` — base64(`_json_key:<sa-json>`).
- `mintAzureAuth({ client_id, client_secret, tenant_id }, registry_url): Promise<DockerAuthEntry>` — exchanges service principal for ACR refresh token via `https://<registry>.azurecr.io/oauth2/exchange`.
- `mintBasicAuth({ username, password }): DockerAuthEntry` — base64(`<user>:<pass>`).
- `buildDockerAuthConfig(entries: Array<[hostname, DockerAuthEntry]>): string` — produces the JSON envelope worker sets to `DOCKER_AUTH_CONFIG`.

**Acceptance:** Unit tests for each minter with mock AWS / Azure responses. ECR mint mocks the STS client; doesn't make real network calls.

### M6 — Trivy image runner extension (M)

**File:** `backend/depscanner/src/scanners/trivy.ts`.

**Steps:**
0. **Add digest normalization helper** (Patch 3 — architect-f4 / DMA-2 / MTD-4 / WPA-6, 5/13 consensus). The cache key is the canonical 64-hex digest (no `sha256:` prefix, no `repo@` prefix). `crane digest` returns `sha256:<hex>`; `parseTrivyImageOutput.imageDigest` sources from `Metadata.RepoDigests[0]` which is `<repo>@sha256:<hex>`. Without normalization, lookups miss every time.
   ```typescript
   export function normalizeDigest(s: string): string {
     // Accepts: bare hex, sha256:<hex>, <repo>@sha256:<hex>, <registry>/<repo>@sha256:<hex>
     const m = s.match(/(?:^|@sha256:|^sha256:)([a-f0-9]{64})$/);
     if (!m) throw new Error(`invalid digest: ${s}`);
     return m[1];
   }
   ```
1. Replace `classifyImageRef` with `resolvePullStrategy(imageRef, configuredCreds)` — returns either `{ kind: 'public' }`, `{ kind: 'authenticated', credId, hostname }`, or `{ kind: 'skip', reason }`. Removes the v1 ghcr-only special case (ghcr now flows through the same per-cred mechanism).
2. Extend `runTrivyImage` options to accept `dockerAuthConfig` AND `dockerConfigDir` (per-scan ephemeral DOCKER_CONFIG dir per Patch 15). Pin `--platform linux/amd64` so manifest-list resolution is deterministic between crane probe and Trivy pull.
3. Add helper `resolveImageDigest(imageRef, dockerAuthConfig?, dockerConfigDir?): Promise<string>` using `crane digest <imageRef>` with auth. Lightweight HEAD-only probe; ~50ms per image. **Subprocess hardening (FMH-r2-4):** `execFile` with explicit timeout (5s), `killSignal: 'SIGKILL'`, `maxBuffer: 65536`. Zombie risk eliminated.
4. **Cache identity is Trivy's RepoDigest, NEVER crane's pre-pull probe.** Crane is a probe to enable cache lookup before paying the pull; on disagreement between crane's probe and Trivy's post-pull RepoDigest, log structured warning `crane_trivy_digest_mismatch` and use Trivy's digest. **Skip cache write when probe and scan disagree** — ambiguous identity. (Patch 3 cache-poisoning side.)
5. Order of operations: `(a) build auth → (b) crane digest WITH auth env → (c) cache lookup → (d) on miss → Trivy with same auth → (e) upsert cache from Trivy's RepoDigests`. Auth-before-probe — private images can't probe without auth. (WPA-r2-3.)

**Acceptance:** Unit tests with mocked `crane` subprocess; integration test in `__tests__/trivy.test.ts` covering each registry-type strategy. Round-trip test: `expect(normalizeDigest('sha256:'+hex)).toBe(normalizeDigest('repo/path@sha256:'+hex)).toBe(normalizeDigest(hex))`. Crane subprocess timeout test (5s elapsed, killed, classified as `registry_unavailable`).

### M7 — Scan-cache storage layer (S)

**File:** `backend/depscanner/src/scanners/storage.ts` (extend).

**Cache key (Patch 3 / DMA-r2-2 / MTD-r2-5):** composite `(normalizeDigest(digest), scanner='trivy', scanner_version, trivy_db_version_day)`. The `trivy_db_version_day` is read from Trivy's metadata at scan-time (UTC YYYY-MM-DD) and ensures CVE-DB freshness within the 7-day TTL — when Trivy rolls its DB, the next scan misses cache and re-runs.

**Cache write contract (Patch 7 — FMH-P0-2, 5/13 consensus):** `upsertContainerScanCache` is called ONLY when ALL of:
  1. Trivy exit code === 0
  2. `summary.warnings` empty for this image
  3. parser produced structurally-valid result (no truncation marker)
  4. crane probe digest (when probe ran) matches `parseTrivyImageOutput`'s normalized digest

The function itself trusts callers; the orchestrator's M8 sub-step `cache_upsert` enforces the four guards before invoking. Comment in source warns reviewers.

**Functions to add:**
- `lookupContainerScanCache(supabase, normalizedDigest, scannerVersion, trivyDbDay): Promise<{ findings: ContainerFinding[]; scanner_version: string } | null>` — selects with composite PK match + `scanned_at >= NOW() - INTERVAL '7 days'`. Verifies `scan_results_hash` matches `sha256(canonicalize(scan_results))`; mismatch → log warning `cache_integrity_mismatch` + return `null` (treat as miss). (FMH-r2-3.)
- `upsertContainerScanCache(supabase, key, parsedFindings, scannerVersion, trivyDbDay, orgId, runId): Promise<void>` — upsert on composite PK. Computes `scan_results_hash` before insert. `first_scanned_by_org_id` and `first_scanned_run_id` populated only on initial INSERT (not in UPSERT SET clause).
- Truncate scan_results to top-N findings sorted by severity desc when JSON exceeds 1MB; emit warning `cache_row_truncated`. (DMA-r2-3.)

**Acceptance:**
- Hit / miss / stale-row paths.
- Integrity-hash mismatch test: seed row with mismatched hash, assert `lookupContainerScanCache` returns null + warning.
- Composite PK: same digest + same scanner + different `trivy_db_version_day` produces two rows; lookup against the older day misses.
- Cache row >1MB triggers truncation + warning.
- `cleanup_container_image_scan_cache(retention_days)` SQL function callable + returns row count + only deletes rows older than retention.

### M8 — Orchestrator extension (L)

**File:** `backend/depscanner/src/scanners/orchestrator.ts`.

**Tenancy invariants** (load-bearing — see §Tenancy Invariants below):
- All worker reads of `organization_registry_credentials` MUST chain `.eq('organization_id', orgId)`; reads of `project_configured_images` MUST chain `.eq('project_id', projectId)`. The depscanner uses the service-role key (no RLS); a literal `.from('organization_registry_credentials').select('*')` returns ALL creds across ALL orgs into worker memory. (Patch 10 — WPA-r2-1.)
- Cred metadata is read at step start; **plaintext is not produced** until the per-image scope inside `scanOneImage`. (Patch 8 — FMH-P0-3.)

**M8.0 — Sub-step taxonomy (define before any M8 code lands).** Each per-image scan is structured as 7 named sub-steps; every kill switch / log line / classifyError tag / extraction_step_errors row attributes to one. Failure must be identifiable from `extraction_step_errors` alone, no log-grep. (Patch 11 — architect-r2-f12, top concern of architect's vote.)

```
container_scan.<phase>  where phase ∈ {
  decrypt_creds,        — single-cred AES-256-GCM decrypt for this image
  build_auth_envelope,  — assemble per-host DOCKER_CONFIG entries
  digest_probe,         — `crane digest` HEAD probe
  cache_lookup,         — DB SELECT against container_image_scan_cache
  mint_auth,            — STS / oauth2 / exchange to short-lived registry token
  trivy_pull,           — `trivy image` subprocess
  cache_upsert          — DB UPSERT after successful scan, gated by 4-guard contract
}
```

Each sub-step:
- Owns its try/catch with per-sub-step warning log
- Owns its kill-switch consultation (where applicable — digest_probe + cache_lookup + cache_upsert all gate on `digestCacheKilled`)
- Owns its classifyError contribution (each sub-step has known failure classes)
- `logger.warn({ phase: 'container_scan.cache_lookup', reason: ... }, 'soft-fail')`

**Kill switches** (Patch 6 — FMH-P0-1, 4/13 consensus). Step entry MGETs all switches in one Redis round-trip:

| Switch | Effect on scan path |
|---|---|
| `kill:scanner:trivy` (v1) | All trivy work skipped — full container_scan step short-circuits |
| `kill:scanner:checkov` (v1) | All checkov work skipped — full IaC step short-circuits |
| `kill:scanner:configured_images` | Skip configured-image list; Dockerfile-derived images still scan |
| `kill:scanner:registry_auth` | Forces public/anon path; private images skip with `auth_disabled` |
| `kill:scanner:digest_cache` | Bypass crane probe + cache lookup + cache upsert; Trivy runs every time (degraded but correct) |
| `kill:scanner:cred_decrypt` | Short-circuit decryptCredential; treat all creds as absent (preserves Dockerfile + ghcr-via-App paths) |

**DOCKER_CONFIG dir lifecycle** (Patch 15 — MTD-r2-1 / CR-1, 3/13 consensus). Replaces the v1 `DOCKER_AUTH_CONFIG` env-string approach. Per-step ephemeral directory:

```typescript
// At step entry (after kill-switch resolution, before step 1):
const dockerConfigDir = await mkdtemp(path.join(os.tmpdir(), 'deptex-scan-'));
await fs.chmod(dockerConfigDir, 0o700);
try {
  // build auth envelope into this dir from successfully-decrypted creds
  // (per-cred decrypt failure → skip cred + log warning + continue per Patch 8)
  // crane + Trivy invoked with DOCKER_CONFIG=$dockerConfigDir set explicitly
  // (no inheritance from worker process env)
  for (const image of plan) {
    await scanOneImage(image, { ...ctx, dockerConfigDir });
  }
} finally {
  // shred-then-rmtree on success/failure/timeout — survives SIGKILL via
  // periodic cleanup cron that wipes /tmp/deptex-scan-* older than 1h
  await fs.rm(dockerConfigDir, { recursive: true, force: true });
}
```

The auth envelope is built ONCE per step entry from all successfully-decrypted creds, reused across all crane + Trivy calls in the loop (WPA-3). One scan = one DOCKER_CONFIG dir = no concurrent-scan collision.

**Step 1 — read metadata only (no decryption):**
```ts
// Resolve org first — projects.organization_id is the load-bearing scope.
const { organization_id: orgId } = await supabase
  .from('projects')
  .select('organization_id')
  .eq('id', projectId)
  .single();

const credList = await supabase
  .from('organization_registry_credentials')
  .select('id, registry_type, registry_url, credential_shape, encryption_key_version')  // metadata only — no encrypted_credentials yet
  .eq('organization_id', orgId);

const configuredImages = await supabase
  .from('project_configured_images')
  .select('id, image_reference, credentials_id, enabled')
  .eq('project_id', projectId)
  .eq('enabled', true);
```

**Step 2 — build per-image scan plan:** dockerfile-derived images (existing v1 flow) + enabled configured images (new flow). Each plan entry references its `credentials_id` (or null for public).

**Step 3 — per-image scan via `scanOneImage(image, ctx)`:** wrap each image in a dedicated function with a try/catch covering ALL sub-steps. Outer loop sees only `{findings} | {skipped}`; **scanOneImage NEVER rethrows.** A throw in any one image cannot abort subsequent images, the IaC path, or the rest of the step. (Patch 12 — FMH-r2-1.)

```ts
async function scanOneImage(image, ctx): Promise<{findings: ContainerFinding[]} | {skipped: SkippedImage}> {
  try {
    // Lazy decrypt: only the cred this image needs, only at this moment.
    const plaintext = image.credentials_id
      ? await decryptCredentialOrSkip(image.credentials_id, ctx)
      : null;
    if (image.credentials_id && !plaintext) {
      return { skipped: { image_reference: image.image_reference, reason: 'cred_decrypt_failed' } };
    }
    const auth = plaintext ? await mintAuth(plaintext, image, ctx) : null;
    // Digest probe + cache lookup + cache upsert sub-steps gated on Debate A.
    const findings = await runTrivyImage(image, auth, ctx);
    return { findings };
  } catch (err) {
    const cls = classifyError(err);  // see classifyError extension below
    logger.warn({ phase: cls.phase, reason: cls.reason }, 'scanOneImage soft-fail');
    return { skipped: { image_reference: image.image_reference, reason: cls.skipReason } };
  }
}
```

**Step 4 — aggregate `skippedImages` with per-reason categorization;** every skip reason is one of the typed values from `classifyError`.

**Step 5 — total wall-clock cap:** `CONTAINER_SCAN_TOTAL_BUDGET_MS` env (default 25min). Loop breaks early when exceeded; remaining images marked `skipped: budget_exhausted`. Combined with the per-image cap of 20 (M11) gives 20 × ≤90s headroom inside Fly's machine slot. (Patch 9 — WPA-1.)

**Step 6 — decrypt budget:** cap at 200 decrypts per orchestrator-run via in-process counter; protects neighbour tenants on the same Fly machine from a runaway loop. (MTD-r2-6.)

**Step 7 — `classifyError` extension** (P0 #17, Patch from review). Extend `with-timeout.ts → classifyError` with:

| Tag | Retryable? | Cache write? | Skip reason |
|---|---|---|---|
| `auth_throttled` | yes (exp backoff, max 3) | no | `auth_throttled` |
| `auth_config_invalid` | no | no | `auth_invalid` |
| `registry_unavailable` | yes (1 retry) | no | `registry_5xx` |
| `image_unavailable` | no | no | `manifest_not_found` |
| `partial_trivy_output` | no | **NEVER** | `trivy_partial` |
| `cred_decrypt_panic` | **PERMANENT TERMINAL** (don't retry SCAN_JOB) | no | `cred_decrypt_failed` |
| `cred_auth_mint_panic` | **PERMANENT TERMINAL** | no | `auth_mint_failed` |
| `helm_no_default_values` | no | n/a | `helm_no_defaults` |

**Critical:** the v1 ghcr.io special-case (Patch C namespace check) is REPLACED by the new credentialed flow. The new flow allows ghcr.io credentials to be either (a) the GitHub App token (preserved as a v1 fallback when no `ghcr` cred exists for the project) or (b) an explicit `ghcr` cred (PAT for cross-org pulls). **The namespace check MUST be preserved on the App-token fallback path; explicit creds bypass it.** 4-state matrix unit-tested: (no cred, App available) / (no cred, no App) / (explicit cred, App available) / (explicit cred, no App). (architect-f7 / MTD-7 / WPA-5 / FMH-P1-12.)

**Maintain v1 invariants:** kill switches (`kill:scanner:trivy` still short-circuits before any work), env-flag fallback (`SCANNERS_CONTAINER_ENABLED=false`), heartbeat, structured warnings. All four new kill switches (`configured_images`, `registry_auth`, `digest_cache`, `cred_decrypt`) ship with M8 per Patch 6.

**Acceptance:**
- End-to-end test with a fixture repo exercising a Dockerfile + a configured-image entry.
- Spy `supabase.from(...).select(...)` mock asserts every cred-list / configured-image-list query carries `.eq('project_id', ...)`.
- Inject throw into each sub-step inside `scanOneImage`; assert (a) the image is skipped with the right reason, (b) other images in the same project still scan, (c) IaC paths complete normally.
- One bad cred (decrypt panic) does NOT abort the IaC + container step.
- 21st enabled image POST returns 400; 20-image x 90s extraction finalizes within `CONTAINER_SCAN_TOTAL_BUDGET_MS`.
- `classifyError` parameterized test: each new tag's `retryable` / `cache_write` / `skip_reason` matches the table.

### M9 — Dockerfile update (S) — supply-chain hardened

**File:** `backend/depscanner/Dockerfile`.

**Crane runs IN the worker that holds decrypted AWS root keys + GCP SA + Azure SP.** A compromised crane binary = full credential exfiltration across every customer. Existing depscanner Dockerfile pins TruffleHog with `sha256sum -c` per house style; crane install must match. (Patch 13 — FMH-r2-2 / WPA-r2-10.)

**Steps:**
1. Pin crane release + verify checksum + cosign signature:
   ```dockerfile
   # Crane (go-containerregistry) for HEAD-only manifest digest probe.
   # Pinned tarball + checksum + cosign signature. Multi-arch via $TARGETARCH.
   ARG CRANE_VERSION=v0.20.2
   ARG CRANE_SHA256_AMD64=<actual-sha256>
   ARG CRANE_SHA256_ARM64=<actual-sha256>
   ARG TARGETARCH
   RUN set -eux; \
     case "$TARGETARCH" in \
       amd64) CRANE_ARCH=x86_64 CRANE_SHA256=$CRANE_SHA256_AMD64 ;; \
       arm64) CRANE_ARCH=arm64  CRANE_SHA256=$CRANE_SHA256_ARM64 ;; \
       *) echo "Unsupported arch: $TARGETARCH"; exit 1 ;; \
     esac; \
     curl -sSfL https://github.com/google/go-containerregistry/releases/download/${CRANE_VERSION}/go-containerregistry_Linux_${CRANE_ARCH}.tar.gz \
       -o /tmp/crane.tar.gz; \
     echo "${CRANE_SHA256}  /tmp/crane.tar.gz" | sha256sum -c -; \
     tar -xzf /tmp/crane.tar.gz -C /usr/local/bin crane; \
     rm /tmp/crane.tar.gz; \
     chmod +x /usr/local/bin/crane; \
     crane version
   # cosign verify-blob is the next-tier hardening. go-containerregistry
   # releases ARE cosign-signed (Sigstore keyless). Add when cosign is in the
   # base image:
   #   RUN cosign verify-blob \
   #     --certificate-identity-regexp='https://github.com/google/go-containerregistry' \
   #     --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
   #     /tmp/crane.tar.gz
   ```
2. CI workflow `crane-pin-check.yml`: fails the PR if `CRANE_VERSION` changes without an accompanying `CRANE_SHA256_AMD64` / `CRANE_SHA256_ARM64` change. Mirrors `schema-check.yml` enforcement style.
3. **Do NOT** add cfn-lint / kubeconform / arm-ttk in Phase 1 (defer to Phase 4 — see OQ resolution below).

**Acceptance:** Image builds clean; `crane version` smoke runs in CI; image-size delta < +20MB; deliberately wrong SHA256 in the Dockerfile fails the build with a clear sha256sum-c error message; CI sync-check fails when CRANE_VERSION changes without matching SHA bump.

### M10 — Registry credentials API route (M)

**Files (new):** `backend/src/routes/registry-credentials.ts` + `__tests__/registry-credentials.test.ts`. Mount in `backend/src/index.ts`.

**Routes:** as per API table above.

**Validation:**
- Server validates `credentials.shape === credential_shape`.
- Server validates `(registry_type, credential_shape)` pair against the same composite CHECK enumerated in the migration (mirrors DB enforcement; produces a 400 with a useful message instead of a constraint-violation 500).
- Server validates `registry_url` required for `harbor`/`jfrog`/`custom`.
- Server encrypts before insert via `encryptApiKey` from `lib/ai/encryption.ts`. Stores `JSON.stringify(plaintextCredentials)` as the plaintext input.
- GET endpoint never returns `encrypted_credentials`.
- PATCH uses `pickAllowed(req.body, ['display_name'])` — extra keys 400 with `{ error: 'unknown_field' }`. PATCH-rotate uses `pickAllowed(req.body, ['credentials'])` separately. (MTD-9 / rbac-r2-3.)
- POST `/registry-credentials/:credId/test`: decrypts, mints auth, performs a HEAD probe against the cred's host, returns `{ ok, error_class? }`. Does not store the result. (TSA-r2-7.)
- ECR-credential STS Redis cache key: `<credId>:<account_id>:<region>` — includes `credId` so cross-org STS attribution survives in audit trails (MTD-r2-4). Single-flight via Redis SETNX with 8s lock to prevent thundering herd on cache miss (FMH-r2-5).
- All cred mutations write an `organization_activities` row (rbac-r2-4): `actor_user_id`, `target_credential_id`, `event_type ∈ {created, rotated, deleted, tested}`, `redacted_diff`. Worker emits `cred_used` once per scan run.

**Cred deletion semantics:** the composite FK `pci_credentials_same_project_fk` on `project_configured_images.credentials_id` uses `ON DELETE SET NULL`, so deleting a cred soft-detaches its images. UI surfaces "N images affected; they will become public-pull-only" before confirming. (architect-r2-f16.)

**Error mapping:** all decrypt / encryption / rotate failures log to `console.error` with full stack; user response is generic `{ error: 'credential_operation_failed' }`. (`feedback_no_raw_errors_to_users.md`.)

**Acceptance:** Route tests covering: list, create with each valid (registry_type, shape) pair, create with mismatched shape (400), create with extra key in body (400), create without org `manage_integrations` perm (403), delete with cascade-set-null verification, rotate end-to-end (encryption_key_version increments), test endpoint dry-run, audit-log row appears for each mutation. PLUS the cross-org tests from Patch 19 §Test Strategy.

### M11 — Configured images API route (M)

**Files (new):** `backend/src/routes/configured-images.ts` + `__tests__/configured-images.test.ts`. Mount in `backend/src/index.ts`.

**Routes:** as per API table above.

**Validation:**
- POST/PATCH validate `cred.organization_id === image.organization_id` (image.organization_id derived from project) server-side BEFORE attempting insert; 400 with `{ error: 'cred_wrong_org' }`. The composite FK is the DB-level safety net — this 400 is the clean UX before the constraint trips. (Patch 1, rescoped.)
- POST enforces a per-project cap: `SELECT COUNT(*) FROM project_configured_images WHERE project_id = ? AND enabled = true >= 20` → 400 with `{ error: 'image_cap_reached', message: 'Project limit of 20 enabled configured images reached. Disable or delete entries before adding more.' }`. Cap chosen to fit Fly machine slot math (20 × 90s ≤ slot). (Patch 9.)
- PATCH uses `pickAllowed(req.body, ['enabled', 'credentials_id'])`. (MTD-9.)
- `image_reference` matches docker-pullable shape (regex from existing v1 list).

**Acceptance:** Route tests covering: list with cred-display join, create, toggle enabled, delete, RBAC, **cred-from-other-org rejected (400 not 500)**, same-org cred-swap on PATCH succeeds, 21st enabled POST returns 400, PATCH with extra key returns 400. PLUS cross-org tests from Patch 19.

### M12 — scanner-findings filter extension (S)

**File:** `backend/src/routes/scanner-findings.ts`.

**Steps:**
1. Replace the hardcoded `['terraform','kubernetes','dockerfile']` whitelist (line 83) with the 9-value union.

**Acceptance:** Filter test covering each new framework value.

### M13a — Frontend types + API client (formats) (S) [Phase 1a]

**Files:** `frontend/src/lib/api.ts`.

**Steps:**
- Update `IaCFinding.framework` to the 9-value union.
- Add `compliance_refs: Record<string, string[]> | null` to `IaCFinding`.

**Acceptance:** `tsc --noEmit` clean; existing IaC list paths continue to work.

### M13b — Frontend types + API client (registries) (S) [Phase 1b]

**Files:** `frontend/src/lib/api.ts`.

**Methods to add (cred routes are org-scoped, no projectId; configured-image routes are project-scoped):**
- `listRegistryCredentials(orgId)`
- `createRegistryCredential(orgId, body)`
- `updateRegistryCredentialDisplayName(orgId, credId, displayName)`
- `rotateRegistryCredential(orgId, credId, newPlaintext)`
- `testRegistryCredential(orgId, credId)`
- `deleteRegistryCredential(orgId, credId)`
- `listConfiguredImages(orgId, projectId)`
- `createConfiguredImage(orgId, projectId, body)`
- `toggleConfiguredImage(orgId, projectId, imageId, enabled)`
- `deleteConfiguredImage(orgId, projectId, imageId)`

**Acceptance:** Types + methods; no UI yet.

### M14 — Framework-icon registry extension (S)

**File:** `frontend/src/components/framework-icon.tsx`.

**Steps:** Add icon mappings for: helm (`SiHelm`), cloudformation (`SiAmazonaws`), arm (`SiMicrosoftazure`), bicep (`SiMicrosoftazure`), serverless (custom inline svg or `SiServerless`), github_actions (`SiGithubactions`), terraform (existing), kubernetes (existing), dockerfile (existing). No separate kustomize icon — kustomization.yaml renders under the kubernetes icon.

**Acceptance:** Visual smoke — each framework icon renders.

### M15 — VulnerabilityExpandableTable filter chips extension (S)

**File:** `frontend/src/components/security/VulnerabilityExpandableTable.tsx`.

**Steps:** Extend the framework filter chip array; preserve `assertNever` exhaustiveness. Update any hardcoded label arrays.

**Acceptance:** All 10 filter chips render; selecting each correctly filters the table; `tsc --noEmit` clean.

### M16 — InfraFindingCard label + compliance refs (M)

**File:** `frontend/src/components/security/InfraFindingCard.tsx`.

**Steps:**
1. Extend `frameworkLabel` switch from 3 to 9 values.
2. Add a compliance refs section between the existing severity/framework header and the code-snippet block. Render only if `compliance_refs` non-empty.

**Acceptance:** Visual smoke; no regressions on v1 IaC + container cards.

### M17 — RegistryCredentialsSection (L)

**Files (new):** `frontend/src/components/security/RegistryCredentialsSection.tsx` + `AddRegistryCredentialDialog.tsx`.

**Steps:**
1. List view with row component, empty state, error state, loading skeleton.
2. Add dialog: registry-type select drives shape-aware form (5 form variants, one per `credential_shape`).
3. Delete with confirmation (two-tone dialog, hideClose, outline cancel + destructive primary per `feedback_dialog_pattern.md`).
4. Mount inside `ScannersPanel` below existing summary card.

**Acceptance:** Browser smoke — add a fake `username_password` cred, see it in the list, delete it. RBAC: read-only view for users without `manage_projects` (no add/delete buttons).

### M18 — ConfiguredImagesSection (M)

**Files (new):** `frontend/src/components/security/ConfiguredImagesSection.tsx` + `AddConfiguredImageDialog.tsx`.

**Steps:**
1. List view with row component, empty state, error state, loading skeleton.
2. Add dialog: image_reference text input + credentials_id select (from listed creds; "None — public image" option).
3. Toggle enabled (radix Switch).
4. Delete with confirmation.
5. Mount inside `ScannersPanel` below RegistryCredentialsSection.

**Acceptance:** Browser smoke — add an image referencing a previously-added cred; toggle disabled; delete.

### M19a — Multi-iac fixtures (M) [Phase 1a]

**Files (new):** `backend/depscanner/src/scanners/__tests__/orchestrator.integration.test.ts` + fixture repo under `backend/depscanner/src/scanners/__tests__/fixtures/multi-iac-fixture/`.

**Fixtures to author:**
- `multi-iac-fixture/` — TF + K8s + Helm + CFN + ARM + Bicep + Serverless + Dockerfile + GH Actions workflow + a `kustomization.yaml` (must surface as `kubernetes` framework, not separate).

**Ambiguity-fixture additions** (TSA-r2-10): JSON file with both ARM and CFN markers; Helm chart with K8s YAML in `templates/`; kustomization.yaml inside a Helm chart.

**Acceptance:** Tests run against the fixture and validate findings counts per framework.

### M19b — Configured-image fixtures (M) [Phase 1b]

**Files (new):** `backend/depscanner/src/scanners/__tests__/configured-image-orchestrator.test.ts` + fixture under `__tests__/fixtures/configured-image-fixture/`.

**Fixtures to author:**
- `configured-image-fixture/` — Dockerfile + a `.deptex/configured-images.example.json` documentation file (the actual scan target list lives in DB, not in repo).
- `cred-isolation-fixture/` — DB seed with two orgs each having their own ECR cred + a configured image; orchestrator run for org A must never read org B's cred.

**Acceptance:** Cache hit/miss + cred CRUD test scenarios pass; cross-org cred-isolation regression test asserts spy mock filters are present.

### M20a — End-to-end smoke 1a (M) [Phase 1a]

**Steps:**
1. Run a full extraction against the multi-iac fixture; confirm findings written across all framework types with `compliance_refs` populated where Checkov emits them.
2. Confirm kustomization.yaml file produces `framework='kubernetes'` rows (not 'kustomize').
3. Browser test: ScannersPanel filter chips include 6 new chips; InfraFindingCard renders compliance badges for CIS-benchmarked rules.

**Acceptance:** All 1a paths green; no console errors.

### M20b — End-to-end smoke 1b (M) [Phase 1b]

**Steps:**
1. Add a registry cred at the org level + a configured image in the UI; trigger a rescan; confirm the configured image is scanned (cache miss) → re-trigger → confirm cache hit.
2. Verify `cleanup_container_image_scan_cache(30)` deletes only old rows.
3. Browser test: RegistryCredentialsSection renders org-shared cred list across multiple projects in the same org; ConfiguredImagesSection per-project; cred-from-other-org cannot be selected in the configured-image cred dropdown.

**Acceptance:** All 1b paths green; no console errors; image-size delta within budget.

## Testing & Validation Strategy

The consensus-P0 cluster of cross-tenant / supply-chain / failure-isolation bugs needs explicit test coverage to keep regressions out. This section is the load-bearing test surface; a milestone is incomplete until its referenced tests below are green. (Patch 19 — TSA-r2 cluster, 4 personas.)

### Backend — unit / parser layer

- **detect-infra**: each new detector (helm / cfn / arm / bicep / serverless / github_actions) + kustomization.yaml-detected-as-kubernetes test + ambiguity fixtures (TSA-r2-10): JSON with both ARM and CFN markers, Helm chart with K8s YAML in `templates/`, kustomization.yaml inside a Helm chart.
- **checkov adapter**: each new framework + compliance-refs extraction with realistic Checkov 3.2.420 fixtures. Compliance-ref parser is defensive (always nullable; never crashes on missing `metadata.benchmark`).
- **registry-auth minters**: each of the 5 shape minters (mock AWS STS, mock Azure exchange endpoint). No real network calls in unit suite.
- **encryption round-trip** (TSA-r2-11 / WPA-r2-7): both packages decrypt a checked-in `fixtures/encryption-roundtrip.json` to the same known plaintext. Catches encryption_key_version handling drift.
- **digest normalization round-trip** (TSA-r2-3): 4 input shapes (bare hex, `sha256:hex`, `repo@sha256:hex`, `registry/repo@sha256:hex`) all produce identical canonical key. *(Activated only if cache stays per Debate A.)*
- **classifyError extension**: parameterized test over each new tag in the M8 step 7 table; assert recovery-cron behavior matches policy.

### Backend — routes / RBAC

- **CRUD matrix** for registry-credentials + configured-images: no-access user (404 not 403 — cross-org), read-only user (200 GET, 403 POST/PATCH/DELETE), full-perm user (all OK).
- **Cred redaction** (test-strategy-auditor-f3): parameterized test over `forbiddenKeys = ['encrypted_credentials', 'password', 'access_key_id', 'secret_access_key', 'session_token', 'service_account_json', 'client_id', 'client_secret', 'tenant_id', 'token', 'username']`. Recursive deep-absence check on POST / LIST / PATCH / TEST responses.
- **Cross-org tenant isolation** (test-strategy-auditor-f4): every list/get/delete returns 404-not-403 when the `:projectId` path segment belongs to another org. URL-with-mismatched-org test.
- **Same-org FK enforcement** (TSA-r2-4, rescoped): three separate tests — POST configured-image with cred from another org (400), PATCH configured-image to swap to other-org cred (400), direct service-role insert with mismatched (cred.organization_id, image.organization_id) trips the composite FK at DB layer.
- **PATCH allow-list** (TSA-r2-5): forbidden-field array iterated via parameterized test; each rejected with 400.
- **Per-project image cap** (TSA-r2-8): boundary tests at 19 / 20 / 21 enabled images. Disabled-don't-count policy documented.
- **ghcr precedence 5-case matrix** (TSA-r2-f12 / WPA-5): (no cred / no App), (no cred / App), (explicit ghcr cred / App available), (explicit ghcr cred / no App), (explicit non-ghcr cred / App available pulling ghcr).
- **Audit log emission** (rbac-r2-4): each cred mutation produces exactly one `organization_activities` row with the right shape; redacted_diff doesn't leak plaintext.

### Worker — orchestrator / pipeline

- **Tenancy invariant assertion**: spy supabase mock asserts every `organization_registry_credentials.select(...)` carries `.eq('organization_id', orgId)` and every `project_configured_images.select(...)` carries `.eq('project_id', projectId)`.
- **Per-image isolation envelope** (Patch 12): inject throw into each sub-step inside `scanOneImage`; assert (a) image skipped with right reason, (b) other images in same project still scan, (c) IaC + container step doesn't abort.
- **One bad cred doesn't abort step**: populate PRC with one row whose ciphertext is corrupted; verify the project's other images scan and the IaC pass completes.
- **Cache poisoning regression** (TSA-r2-2 — *cache-keep only*): parameterized over Trivy failure modes (exit=1+valid JSON, exit=0+truncated, timeout, kill-switch mid-scan, manifest-not-found, auth-401-mid-pull, crane/Trivy digest disagreement); assert cache write spy called with `call_count = 0`.
- **STS rate-limit / throttle** (TSA-r2-7): mock STS 429; assert exponential backoff 3 attempts then soft-fail with `auth_throttled` skip reason.
- **Wall-clock budget**: mocked extraction with 20 images each 90s asserts step finalizes inside `CONTAINER_SCAN_TOTAL_BUDGET_MS`; 21st image marked `budget_exhausted`.
- **DOCKER_AUTH_CONFIG/DOCKER_CONFIG envelope composition** (TSA-r2-6): 3 mock creds (ECR + GCR + Docker Hub); spy crane and Trivy invocations; assert per-host correctness.
- **Migration on populated table** (TSA-r2-f8): seed 10000 v1 rows; apply phase27 migration; assert all pass; insert helm finding succeeds; insert non-real-framework gets 23514.
- **Rollback on populated table** (TSA-r2-f9): seed v2 rows; run rollback; verify v2-only rows DELETEd before narrow CHECK re-applied; document chosen behavior in rollback header.
- **Kill switch matrix** (TSA-r2-1): N-row truth table over the kill switches that ship — 2 v1 + 3 obvious new (`configured_images`, `registry_auth`, `cred_decrypt`) + optional 4th (`digest_cache`, contingent on Debate A) — assert scan paths run / DB writes / skip-reasons.

### Frontend

- **Smoke**: ScannersPanel renders without errors across {no creds, no images} × {no creds, has images} × {has creds, no images} × {has creds, has images}.
- **Interaction**: add cred → list updates; add image → list updates with cred-display chip; toggle enabled; delete with two-tone confirmation dialog (`feedback_dialog_pattern.md`).
- **Form-shape switch** (test-strategy-auditor-f10): registry_type ecr → gcr toggles AWS fields → SA JSON; AWS values cleared from form state on switch.
- **Frontend credential field redaction** (TSA-r2-9): no GET response shape leaks plaintext; the dev-only "Reveal" button is gated by an explicit `manage_integrations` perm AND the field that reveals is `null` (post-encryption it's never re-decryptable client-side anyway).
- **TypeScript exhaustiveness**: `assertNever` across the framework union catches a missed case at compile time.

### Performance targets

- Detect-infra walk on a 10k-file repo: <2s wall-clock (matches v1).
- Checkov on a 100-file IaC mix: <60s (Checkov's bottleneck).
- Trivy image cache hit: <100ms total (`crane digest` + DB lookup + decode). *(Cache-keep only.)*
- Trivy image cache miss: <120s typical (existing v1 number).
- Registry-credentials list endpoint: <100ms p95.

### Regression checks

- v1 carry-forward of TF/K8s/Dockerfile findings unaffected — existing Phase 25 tests + multi-iac fixture's TF/K8s subset.
- ghcr.io path with GitHub App fallback (no explicit `ghcr` cred) continues to work — orchestrator test covering this case.
- `framework-icon.tsx` doesn't break existing icon usage — visual diff against pre-Phase-1.

## Risks & Open Questions

### Risks

- **R1: ECR token minting at scan-time adds latency.** STS + `get-authorization-token` is ~500ms per call. Per-scan cost; not per-image. Mitigation: mint once per pipeline run, cache in-memory for 12h.
- **R2: AWS SDK + Azure SDK image-size cost.** `@aws-sdk/client-ecr` is ~3MB; `@azure/identity` + `@azure/arm-containerregistry` is ~5MB. Combined ~10MB additional in the depscanner image. Acceptable per the v1 image-size hard gate (currently 6.96GB; +10MB is rounding error).
- **R3: `crane digest` fails for some private registries.** The HEAD probe needs the same auth as the pull. Mitigation: pass the same `DOCKER_AUTH_CONFIG` to crane via env. Some legacy registries don't support HEAD on manifests; for those, fall back to a Trivy run without cache.
- **R4: Cache-key collision risk if Trivy version changes mid-extraction.** Mitigation: include `scanner_version` in cache row; treat `WHERE scanner_version != current` as cache miss.
- **R5: Helm chart rendering at scan-time uses default `values.yaml`.** False-negatives for charts that change behavior under custom values. Brief OQ1 acknowledges this; revisit if FN data justifies a project-supplied values file feature.
- **R6: Compliance refs extraction is parser-fragile.** Checkov's `metadata.benchmark` shape isn't formally documented. Mitigation: defensive coding (always nullable, never crashes); regression-test against pinned Checkov 3.2.420 fixtures.

### Open Questions

- **OQ-A (RESOLVED 2026-05-02 by Patch 14):** Encryption helper sharing — build-time copy via `scripts/sync-encryption.ts` + CI sync-check workflow. See M2.5.
- **OQ-B (resolves at M9 — Dockerfile choice, *contingent on Debate A — cache cut would moot this*):** Use `crane` (Go binary, ~5MB, easy install) or `skopeo` (similar; OCI tools' standard) for the digest probe? **Lean crane** — simpler single-static-binary install, well-maintained by Google, used by Trivy itself.
- **OQ-C (resolves at M8 — orchestrator):** When BOTH a `ghcr` cred AND a GitHub App installation exist for a project pulling a ghcr.io image, which auth wins? **Lean cred-wins** (explicit user config trumps implicit fallback). Decision is local to the orchestrator; doesn't affect the schema.
- **OQ-D (informational):** When ARE we bundling cfn-lint / kubeconform / arm-ttk? **Resolution: defer to Phase 4 (Aegis IaC autofix).** Rationale: Phase 1 doesn't use them; arm-ttk requires PowerShell on Linux which is non-trivial; the ~60MB image cost is meaningful when amortized only across Phase 4's scope. Refresh this decision at Phase 4's plan-feature run.
- **OQ-E (informational):** Should the security-tab → "issues" rename (per `security_tab_progress.md`) land before, during, or after Phase 1? **Recommend: independently of Phase 1.** Phase 1 doesn't touch the route or the page name; the rename is a pure refactor. Coordinating them slows both.

### Open Debates — RESOLVED 2026-05-02

All six debates from `.cursor/plans/review-iac-container-v2-phase1.md` are locked. Captured here as a record of decisions and their rationale.

- **Debate A — Cache + crane:** **KEEP, fully hardened in Phase 1b.** All 7 cache-cluster patches applied (3 digest normalization, 4 forensics columns, 6 digest_cache kill switch, 7 write contract, 11 sub-step taxonomy includes cache phases, 13 crane checksum + cosign + multi-arch, 15 ephemeral DOCKER_CONFIG dir). Plus DMA-r2-2 scanner discriminator, DMA-r2-3 row-size cap, MTD-r2-5 composite key, FMH-r2-3 integrity hash, MSA-7 reaper, FMH-r2-4 crane subprocess hardening.
- **Debate B — Cred shapes:** **KEEP 5 distinct shapes.** Cloud-native auth genuinely requires it (you can't paste basic at ECR). Composite CHECK on `(registry_type, credential_shape)` enumerates valid pairs.
- **Debate C — Registry list:** **KEEP schema slots for all 9** (`ghcr`/`ecr`/`gcr`/`acr`/`dockerhub`/`quay`/`harbor`/`jfrog`/`custom`); Phase 1 success criterion #2 lives-tests only big-4 + ghcr + custom. Adding Quay/Harbor/JFrog later is non-migration.
- **Debate D — Phase split:** **YES, 1a (formats) + 1b (registries+creds+cache).** Each PR is independently reviewable; 1a's user-visible value lands ~1.5 weeks earlier; 1b inherits 1a's invariants and ships separately. See §Phase Split.
- **Debate E — Compliance refs:** **KEEP in Phase 1a.** Cheapest enterprise-pitch differentiator; failure mode is graceful (column nullable; badges just don't render if extraction fails).
- **Debate F — Kustomize:** **FOLD into kubernetes detector.** kustomization.yaml files surface as `kubernetes` framework — coverage for free, no extra UI surface. Framework union back to 9 values.

## Dependencies

- **v1 IaC + Container Scanning** (PR #21, merged 2026-04-30) — schema, scanner orchestrator, ScannersPanel, InfraFindingCard, VulnerabilityExpandableTable.
- **`AI_ENCRYPTION_KEY`** — already required for BYOK (`organization_ai_providers`). Reused for `organization_registry_credentials.encrypted_credentials`. No new env var.
- **GitHub App installation** — preserved as v1 fallback for ghcr.io. Optional now (not required).
- **Supabase MCP** — for migration application.
- **CI `schema-check.yml`** — already in place; Phase 1 must keep it green.

**Not depended on:**
- Phase 6 cross-file taint engine — fully decoupled.
- Phase 6.5 cutover — runs in parallel.
- Aegis Fix Agent — no integration in Phase 1.
- Custom policy engine — no integration in Phase 1.

## Success Criteria

### Phase 1a (formats) ships when ALL of the following are true:

1. **Coverage parity:** A multi-format fixture repo (TF + K8s + Dockerfile + Helm + CFN + ARM + Bicep + Serverless + GH Actions + a kustomization.yaml that surfaces as `kubernetes`) yields findings in `project_iac_findings` for every format Checkov emits findings for.
2. **Compliance refs:** A finding from a CIS-benchmarked rule renders with at least one compliance badge in the InfraFindingCard.
3. **No v1 regressions:** v1 carry-forward of TF/K8s/Dockerfile findings continues to work; existing phase25 tests + multi-iac fixture's TF/K8s subset green.
4. **CI clean:** `schema-check.yml` passes; unit + route tests green; no image-size delta (no Dockerfile changes in 1a).

### Phase 1b (registries + creds + cache) ships when ALL of the following are true:

5. **Registry coverage:** Test creds for ECR + GCR + ACR + Docker Hub + custom + ghcr each successfully (a) auth, (b) pull, (c) scan a known test image. Schema slots for Quay/Harbor/JFrog exist but live-test deferred. ghcr.io continues to work via GitHub App fallback when no explicit cred exists.
6. **Cache works:** Same image digest scanned across two projects pulls + scans once, then hits cache. Cache miss after 7-day TTL re-pulls. Crane probe digest mismatch with Trivy RepoDigest skips cache write. Reaper deletes rows older than 30 days.
7. **Cache integrity:** Manually-corrupted `scan_results_hash` row returns `null` from `lookupContainerScanCache` with `cache_integrity_mismatch` warning.
8. **Configured images:** A registry image NOT referenced by any Dockerfile, added via UI, gets scanned at the next extraction. 21st enabled image POST returns 400.
9. **Tenancy invariants:** Cross-tenant cred attachment (Org A's cred on Org B's image) fails at every layer (DB composite FK, route validator, trigger). Service-role reads spy-asserted to filter on `.eq('project_id', ...)`. (See §Tenancy Invariants.)
10. **RBAC:** A user without `manage_integrations` cannot CRUD creds; without `manage_projects` cannot CRUD configured images. List endpoints redact every key in `forbiddenKeys`.
11. **Kill switches:** All 6 switches (v1's 2 + 4 new) gate independently per the M8 truth-table; pairwise interactions documented and tested.
12. **Per-image isolation:** Inject throw into each of the 7 sub-steps inside `scanOneImage`; assert image skipped with right reason, other images still scan, IaC + container step doesn't abort.
13. **Crane supply-chain:** Deliberately wrong SHA256 in Dockerfile fails the build; CI sync-check fails when CRANE_VERSION changes without matching SHA bump.
14. **v1 invariants preserved:** Kill switches still gate; fingerprint carry-forward still works; finalize_extraction migration unaffected; all phase25 + 1a tests still pass.
15. **Audit log:** Each cred mutation produces exactly one `organization_activities` row; redacted_diff doesn't leak plaintext.
16. **CI clean:** `schema-check.yml` passes; all unit + route + integration tests green; image-size delta within budget (<+20MB on the depscanner image).

## Recommended Next Step

Plan has been patched per `/review-plan` output (2026-05-02): all 19 suggested patches applied + 6 open debates locked + new sections for §Phase Split / §Tenancy Invariants / §Rollout Sequence + Patch 11 sub-step taxonomy + Patch 19 test gaps. Cache cluster (Patches 3, 4, 6, 7, 11 cache phases, 13, 15) applied per Debate A "ship full" decision.

Run `/review-plan iac-container-v2-phase1 --no-debate` to confirm the post-patch verdict flips to READY or REVISE-with-trivial-patches. (`--no-debate` skips Round 2 to save tokens — most P0s should now resolve cleanly so the cheaper review is appropriate.)

If READY: `/implement` against Phase 1a's milestone subset first; ship 1a's PR. After 1a is observed-stable for 24h, `/implement` Phase 1b.

If REVISE: apply the small remaining patches and proceed.
