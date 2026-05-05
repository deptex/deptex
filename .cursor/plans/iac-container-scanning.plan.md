# IaC + Container Scanning v1 — Foundation Lite — Implementation Plan

> **Patched 2026-04-29 from `/review-plan` (round 1 + round 2).**
>
> Round 1 (REWORK → REVISE): scope cut from 22d → ~11d. Cut encrypted credential store, image-digest cache, scanner-config overrides, configured-images CRUD, AI explainer button, `compliance_refs` JSONB, 6 of 10 IaC frameworks. Added fingerprint columns + finalize_extraction RPC carry-forward. Added Rollback & Rollout section.
>
> Round 2 (REVISE → READY-track): applied 9 P0 patches:
> - **Patch A** — `start_line_key INTEGER GENERATED STORED` column so plain column-list `onConflict` can target the UNIQUE (functional indexes can't be targeted by supabase-js).
> - **Patch B** — Storage layer scrubs `vulnerability_id` (GENERATED ALWAYS) from upsert payloads.
> - **Patch C** — Dockerfile FROM namespace check against project's GitHub App installation; rejects `FROM ghcr.io/different-org/...` cross-tenant pull vector.
> - **Patch D** — `BEFORE INSERT` trigger derives `organization_id` from `projects` row, neutralizing caller-supplied tampering.
> - **Patch E** — Multi-stage Dockerfile parser selects FINAL stage image (production-shipping), not first FROM.
> - **Patch F** — Down-migration self-sufficient: prior `finalize_extraction` body captured verbatim into rollback file at M1; single-transaction rollback with verification step.
> - **Patch G** — Endpoints "(7 total)", tenant-isolation enumeration covers all 7 routes incl. scanner-summary, 5 new test mapping rows for kill-switch/feature-flag/allowlist/RPC/redis-fallback.
> - Plus alignment fixes: scanner column added to fingerprint partial UNIQUE; `infra_types` write moved to worker-after-RPC explicitly; `runScannerSubprocess` signature includes `logger` + `verboseLogStep`; helm CLI added to Dockerfile (Checkov requires it for Helm rendering); `DOCKER_AUTH_CONFIG` env (not CLI flag) for ghcr.io token; Redis kill-switch fallback semantics; bad-data recovery preserves user decisions.
>
> Full review at `.cursor/plans/review-iac-container-scanning.md`. Open scope-trim candidates left for Henry: cut M0 benchmark (saves 0.5d), cut Helm framework (saves a fixture), cut `SCANNERS_ROLLOUT_ALLOWLIST` (1-user v1).

## Overview

Bundle Trivy + Checkov as binaries in the extraction-worker Dockerfile. Add a detection step that populates `projects.infra_types`. Run Checkov for Terraform / Kubernetes / Helm IaC misconfig; run Trivy for Dockerfile + container image CVE scanning. Container scans pull the Dockerfile's base image from public registries (or ghcr.io via the existing GitHub App credentials). Write findings to two new tables (`project_iac_findings`, `project_container_findings`) following Phase 6 + Phase 19 patterns. Surface findings in the existing unified security table by extending the `SecurityTableRow` discriminated union. Add a read-only "Scanners" panel to Project Settings showing detected coverage + last scan timestamp + rescan button. **No** encrypted credential store, **no** configured-images CRUD, **no** scanner-config overrides, **no** image-digest cache, **no** AI explainer button at v1 — those are v1.5 candidates.

## v1.5 Deferral List (carved out of original v1)

Documented up-front so `/implement` doesn't drift back into them:
- **Encrypted registry credential store** (`project_registry_credentials` + ECR/GCR/ACR/Quay/Harbor/JFrog support) — eliminates IDOR class entirely.
- **Per-project configured container images** (`project_configured_images` + add/remove modal) — Dockerfile FROM covers 95% of v1 use.
- **Per-project scanner config overrides** (`project_scanner_config`) — auto-detect only at v1.
- **Global cross-org image-digest cache** (`container_image_scan_cache`) — eliminates cross-tenant leak + atomic-commit-violation risk.
- **AI explainer button** on finding cards (Tier 1 Gemini) — no backend wiring exists; defer to v2.3 Aegis chat tools.
- **`compliance_refs` JSONB** column — no v1 reader; defer to v2.9 compliance dashboard.
- **6 IaC framework parsers** (CloudFormation, ARM, Bicep, Serverless, SAM, CDK) — defer to v1.5 once Henry has a real repo using them.

## Competitive Research & Design Rationale

Full research at `.cursor/plans/research-iac-containers.md`. Brief at `.cursor/plans/feature-brief-iac-container-scanning.md`. Distilled patterns kept for v1:

- **Trivy + Checkov as the engine pair** — Apache 2.0; bundle both. Per skeptic-f11: each scanner is gated to its strongest domain — **Checkov** runs Terraform / Kubernetes / Helm misconfig (Checkov has the deeper rule library on these); **Trivy** runs Dockerfile misconfig + container image CVE. No overlap, no duplicate findings.
- **Aikido auto-detect** — globs at clone time; no onboarding config.
- **Endor's container reachability** — explicitly NOT v1; v2.1 candidate.

Where we're intentionally not matching at v1:
- No Rego custom policies, no AI fix PRs, no code-to-cloud drift, no multi-registry credentials, no GitHub Actions workflow scanning.

## Codebase Analysis

### Existing patterns we're following

**Findings table pattern** (`backend/database/phase6_security_tables.sql` + `backend/database/findings_status.sql` + `backend/database/findings_depscore.sql`)
- `extraction_run_id TEXT NOT NULL` + UNIQUE including extraction_run_id for upsert-then-delete-stale rotation.
- `status TEXT NOT NULL DEFAULT 'open'` for ignore.
- `depscore INTEGER` for unified ranking.
- Suppress / risk-accept columns added via `ALTER TABLE`.
- **Critically:** the actual `project_semgrep_findings` UNIQUE includes `extraction_run_id` (verified in `schema.sql`). The brief's claim of `(rule_id, file_path, start_line)` as the stable key was wrong; status carryover happens via `semgrep_fingerprint` partial UNIQUE index, not via the main UNIQUE. Plan now matches.

**finalize_extraction carry-forward** (`backend/database/phase19_3_finalize_extraction_rpc.sql`)
- The RPC has hard-coded per-table carry-forward CTEs for `project_dependency_vulnerabilities`, `project_semgrep_findings`, `project_secret_findings`. **New finding tables get no carry-forward unless this RPC is amended** — patched in M2.

**Pipeline pattern** (`backend/extraction-worker/src/pipeline.ts`)
- `withTimeout(...)` + `logStepError(...)` + `classifyError(...)` from `with-timeout.ts`.
- Subprocess template from `runDepScan()` (lines 234-309): spawn + heartbeat (interval-based, independent of stdout — confirmed via re-read) + abort signal + SIGTERM cleanup.
- `binaryAvailable(name)` for friendly missing-binary errors.

**Frontend security table** (`frontend/src/components/security/VulnerabilityExpandableTable.tsx`)
- `SecurityTableRow` is already a discriminated union `vulnerability | secret | semgrep | license`. Additive.
- Existing `VulnerabilityOrgSidebarExpandedContent` shape reused for new finding cards.

**Filter pattern** (`frontend/src/components/security/SecurityFilterBar.tsx`)
- `SecurityFilters` interface; URL-param sync.

### Reusable code identified

- `extraction-worker/with-timeout.ts` → wrap Trivy + Checkov subprocess calls.
- `extraction-worker/runDepScan` shape → factored into a shared `runScannerSubprocess` helper as part of M2 (per architect-f5; small refactor that pays back at v2.1 / v2.6).
- Soft-switch atomic commit (Phase 19) → both new finding tables fit the pattern **after** the `finalize_extraction` RPC is amended (M2).

### Files modified

Backend:
- `backend/src/index.ts` — register new router.
- `backend/extraction-worker/src/pipeline.ts` — add detection + scan steps; factor `runScannerSubprocess` helper.
- `backend/extraction-worker/src/with-timeout.ts` — add `runScannerSubprocess` shared helper.
- `backend/extraction-worker/Dockerfile` — install Trivy + Checkov.
- `backend/database/schema.sql` — refresh via `npm run schema:dump` per CLAUDE.md.

Frontend:
- `frontend/src/components/security/VulnerabilityExpandableTable.tsx` — extend `SecurityTableRow`; add `assertNever(row)` to all switch defaults to make missing variants compile errors.
- `frontend/src/components/security/SecurityFilterBar.tsx` — add finding-type chips for `iac` + `container`.
- `frontend/src/components/framework-icon.tsx` — infra icon map.
- `frontend/src/components/CreateProjectSidebar.tsx` — show detected `infra_types` in scan preview.
- `frontend/src/lib/api.ts` — add `IaCFinding`, `ContainerFinding`, `ScannerSummary` types + fetch helpers.
- `frontend/src/app/pages/ProjectSettingsContent.tsx` — add read-only Scanners panel.

### Files created

Backend:
- `backend/database/phase23_iac_container_scanning.sql` — full migration including `finalize_extraction` amendment.
- `backend/database/phase23_iac_container_scanning_rollback.sql` — manual-only down-migration.
- `backend/src/routes/scanner-findings.ts` — IaC + container findings endpoints + summary endpoint.
- `backend/extraction-worker/src/scanners/trivy.ts` — Trivy invocation + result parsing (Dockerfile config + container image vuln).
- `backend/extraction-worker/src/scanners/checkov.ts` — Checkov invocation + result parsing (TF/K8s/Helm).
- `backend/extraction-worker/src/scanners/detect-infra.ts` — filesystem glob detection + adversarial-fixture-tested.
- `backend/extraction-worker/src/scanners/storage.ts` — upsert-then-delete-stale for new tables.

Frontend:
- `frontend/src/components/security/InfraFindingCard.tsx` — single component for both iac + container expanded rows (pragmatist-f7: 80% shared shape).

## Data Model

### Migration: `backend/database/phase23_iac_container_scanning.sql`

```sql
-- Phase 23: IaC + Container scanning v1 (Foundation Lite)
-- New tables: project_iac_findings, project_container_findings
-- New column: projects.infra_types
-- Amends: finalize_extraction RPC for new-table carry-forward

-- ============================================================
-- IaC findings (Checkov + Trivy Dockerfile misconfigurations)
-- ============================================================
CREATE TABLE IF NOT EXISTS project_iac_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,  -- denormalized for org-rollup queries
  extraction_run_id TEXT NOT NULL,
  scanner TEXT NOT NULL CHECK (scanner IN ('trivy', 'checkov')),
  scanner_version TEXT,                        -- 'trivy@0.50.4' / 'checkov@3.2.x' — for bad-data-recovery purges
  rule_id TEXT NOT NULL,
  framework TEXT NOT NULL CHECK (framework IN ('terraform', 'kubernetes', 'helm', 'dockerfile')),
  file_path TEXT NOT NULL,
  start_line INTEGER,                          -- nullable: scanners often emit resource-level findings without specific line
  -- Patch A: stored generated key so plain column-list onConflict can target the UNIQUE.
  -- Functional indexes (e.g. COALESCE(start_line, -1)) cannot be targeted by supabase-js .upsert onConflict.
  start_line_key INTEGER NOT NULL GENERATED ALWAYS AS (COALESCE(start_line, -1)) STORED,
  end_line INTEGER,
  severity TEXT,                               -- 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  depscore INTEGER,                            -- extended scoring: CIS severity × asset_tier multiplier (existing rubric)
  message TEXT,
  description TEXT,
  cwe_ids TEXT[],
  code_snippet TEXT,
  rule_doc_url TEXT,
  iac_fingerprint TEXT,                        -- scanner-stable identifier for status carryover (mirrors semgrep_fingerprint pattern)
  metadata JSONB,
  status TEXT NOT NULL DEFAULT 'open',         -- 'open' | 'ignored'
  suppressed BOOLEAN DEFAULT false,
  suppressed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  suppressed_at TIMESTAMPTZ,
  risk_accepted BOOLEAN DEFAULT false,
  risk_accepted_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  risk_accepted_at TIMESTAMPTZ,
  risk_accepted_reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Patch A: plain column-list UNIQUE so supabase-js onConflict can target it.
-- start_line_key is the stored generated column above (COALESCE(start_line, -1)).
CREATE UNIQUE INDEX idx_piacf_unique
  ON project_iac_findings (project_id, rule_id, file_path, start_line_key, extraction_run_id);

-- Patch 2: fingerprint partial UNIQUE for line-drift-tolerant status carryover.
-- skeptic-f2 fix: include `scanner` column to defend against fingerprint format collisions
-- between Trivy (`trivy:AVD-...`) and Checkov (`checkov:CKV_...`) writers on the same table.
CREATE UNIQUE INDEX idx_piacf_fingerprint
  ON project_iac_findings (project_id, scanner, iac_fingerprint) WHERE iac_fingerprint IS NOT NULL;

-- Composite index for delete-stale sweep `WHERE project_id = $1 AND extraction_run_id <> $2`
CREATE INDEX IF NOT EXISTS idx_piacf_project_run ON project_iac_findings(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_piacf_org_status_depscore ON project_iac_findings(organization_id, status, depscore DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_piacf_severity ON project_iac_findings(severity);
CREATE INDEX IF NOT EXISTS idx_piacf_framework ON project_iac_findings(framework);

-- ============================================================
-- Container CVE findings (Trivy on pulled Dockerfile base images)
-- ============================================================
CREATE TABLE IF NOT EXISTS project_container_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  scanner_version TEXT,
  image_reference TEXT NOT NULL,
  image_digest TEXT NOT NULL,
  image_source TEXT NOT NULL CHECK (image_source IN ('dockerfile_base')),  -- only source at v1; expanded in v1.5
  os_package_name TEXT NOT NULL,
  os_package_version TEXT NOT NULL,
  os_package_ecosystem TEXT,
  osv_id TEXT,
  cve_id TEXT,
  -- Patch 2: GENERATED column resolves NULL osv_id/cve_id pair to a stable non-null value for UNIQUE inclusion
  vulnerability_id TEXT NOT NULL GENERATED ALWAYS AS (
    COALESCE(osv_id, cve_id, 'unknown:' || md5(image_digest || ':' || os_package_name || ':' || os_package_version))
  ) STORED,
  severity TEXT,
  cvss_score NUMERIC(4, 1),
  epss_score NUMERIC(8, 6),
  is_kev BOOLEAN DEFAULT false,
  fix_versions TEXT[],
  layer_digest TEXT,
  depscore INTEGER,                            -- existing rubric (these ARE CVEs)
  description TEXT,
  rule_doc_url TEXT,
  -- Patch 2: digest-independent fingerprint survives base-image bumps
  container_fingerprint TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  suppressed BOOLEAN DEFAULT false,
  suppressed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  suppressed_at TIMESTAMPTZ,
  risk_accepted BOOLEAN DEFAULT false,
  risk_accepted_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  risk_accepted_at TIMESTAMPTZ,
  risk_accepted_reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Patch B note: vulnerability_id is GENERATED ALWAYS — storage layer MUST NOT include it
-- in INSERT/UPDATE payloads (Postgres rejects explicit values). See M2 storage.ts task.
CREATE UNIQUE INDEX idx_pcf_unique
  ON project_container_findings (project_id, image_digest, os_package_name, os_package_version, vulnerability_id, extraction_run_id);

CREATE UNIQUE INDEX idx_pcf_fingerprint
  ON project_container_findings (project_id, container_fingerprint) WHERE container_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pcf_project_run ON project_container_findings(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pcf_org_status_depscore ON project_container_findings(organization_id, status, depscore DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_pcf_severity ON project_container_findings(severity);

-- ============================================================
-- projects.infra_types (auto-populated by detect-infra step)
-- Note: no GIN index at v1 (no query needs it). When v1.5 adds an org-wide
-- "projects by framework" query, add the GIN index in a separate migration via
-- CREATE INDEX CONCURRENTLY (cannot run inside a transaction; must be standalone).
-- ============================================================
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS infra_types TEXT[] DEFAULT '{}'::TEXT[];

-- ============================================================
-- Patch D: enforce organization_id on findings server-side (mis-attribution defense).
-- Worker passes only project_id; trigger derives organization_id from projects.
-- Tampered/incorrect organization_id values from the caller are silently overwritten.
-- ============================================================
CREATE OR REPLACE FUNCTION enforce_finding_org_id() RETURNS TRIGGER AS $$
BEGIN
  NEW.organization_id := (SELECT organization_id FROM projects WHERE id = NEW.project_id);
  IF NEW.organization_id IS NULL THEN
    RAISE EXCEPTION 'enforce_finding_org_id: project % not found', NEW.project_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER project_iac_findings_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON project_iac_findings
  FOR EACH ROW EXECUTE FUNCTION enforce_finding_org_id();

CREATE TRIGGER project_container_findings_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON project_container_findings
  FOR EACH ROW EXECUTE FUNCTION enforce_finding_org_id();

-- ============================================================
-- Patch 3: amend finalize_extraction RPC for new-table carry-forward
-- (mirrors existing project_semgrep_findings carry-forward by fingerprint)
-- ============================================================
-- Implementation note: CREATE OR REPLACE FUNCTION block that adds two new
-- carry-forward CTEs to the existing RPC body, both keyed on the fingerprint
-- partial-unique indexes above. Status, suppressed_*, risk_accepted_* fields
-- carry forward when (project_id, scanner, iac_fingerprint) matches across runs;
-- container findings carry forward on (project_id, container_fingerprint).
--
-- Each CTE includes the explicit partial-index predicate
-- `WHERE prev.iac_fingerprint IS NOT NULL AND new.iac_fingerprint IS NOT NULL
--  AND prev.scanner = new.scanner AND prev.iac_fingerprint = new.iac_fingerprint`
-- so PostgREST/Postgres uses the partial-UNIQUE index (raw SQL, not ORM helper).
--
-- INTENTIONAL DIVERGENCE FROM SEMGREP PATTERN (architect-f2):
-- Existing semgrep carry-forward in phase19_3 has both a fingerprint-match CTE AND
-- a tuple-fallback CTE for fingerprint-NULL rows. We deliberately ship fingerprint-only
-- here. Rationale: Trivy/Checkov rule_ids tied to file_path are not as semantically
-- stable as Semgrep rule signatures (e.g., a user renames a Terraform resource block —
-- file_path stays, but it's a different finding). A tuple-fallback would silently
-- carry decisions across what users perceive as different findings. We accept that
-- fingerprint-NULL rows lose their decisions across re-extractions; M5 alarm test
-- raises a warn if >5% of rows in a run lack fingerprint (early-signal of parser regression).
--
-- See backend/database/phase19_3_finalize_extraction_rpc.sql for the existing
-- function body to extend.
--
-- Patch F: M1 captures the prior body verbatim into the rollback file (see Down-migration).
```

### Compute fingerprints in scanners

- `iac_fingerprint`:
  - Checkov: `checkov:${bc_check_id}:${resource_address || file_path}` (e.g., `checkov:CKV_AWS_20:aws_s3_bucket.my_bucket`)
  - Trivy Dockerfile: `trivy:${rule_id}:${cause_resource_id}` (e.g., `trivy:AVD-DS-0001:Dockerfile:RUN`)
- `container_fingerprint`:
  - `${os_package_name}@${vulnerability_id}` (digest-independent — survives base-image rebuilds where same package+CVE reappears)

**Fingerprint NULL policy (data-model-auditor-f4):** if the scanner output lacks the stable identifier needed (e.g., empty `resource_address`, missing `cause_resource_id`), emit `iac_fingerprint = NULL` — do NOT synthesize from line/file alone, because that defeats the line-drift tolerance the fingerprint exists to provide. NULL-fingerprinted findings re-appear each run as new rows; their ignore/risk-accept decisions are NOT carried forward. M5 unit test asserts: a finding with empty resource_address has `iac_fingerprint = null`, never a degenerate string like `checkov::Dockerfile`.

### Down-migration: `backend/database/phase23_iac_container_scanning_rollback.sql`

**Patch F: self-sufficient rollback.** The rollback file ships with the prior `finalize_extraction` body captured verbatim (no manual paste during incident). M1 acceptance includes a real `psql -f` end-to-end run against a staging copy.

The rollback file structure (filled in at M1 by reading the live RPC source and copying its body verbatim into the heredoc — exact text, not a reference):

```sql
-- MANUAL-ONLY rollback for phase23. Do not auto-run.
-- Order of ops: kill scanners (Redis kill switches) → wait one extraction cycle → run this.
-- Single transaction: RPC restore happens BEFORE table drops so the RPC never references
-- a dropped table.

BEGIN;

-- 1. Restore finalize_extraction RPC to its pre-phase23 body.
-- NOTE: at M1 paste the actual current body of finalize_extraction (read from
-- backend/database/phase19_3_finalize_extraction_rpc.sql or pg_proc) into this heredoc.
-- Do NOT leave a `...` placeholder — this file must be runnable without further edits.
CREATE OR REPLACE FUNCTION finalize_extraction(...)
RETURNS ... AS $$
-- <<< prior body captured verbatim at M1 >>>
$$ LANGUAGE plpgsql;

-- 2. Drop triggers added by phase23 (must come before table drops).
DROP TRIGGER IF EXISTS project_iac_findings_enforce_org_id ON project_iac_findings;
DROP TRIGGER IF EXISTS project_container_findings_enforce_org_id ON project_container_findings;
DROP FUNCTION IF EXISTS enforce_finding_org_id();

-- 3. Drop tables (CASCADE handles dependent indexes/constraints).
DROP TABLE IF EXISTS project_container_findings CASCADE;
DROP TABLE IF EXISTS project_iac_findings CASCADE;

-- 4. Drop column.
ALTER TABLE projects DROP COLUMN IF EXISTS infra_types;

COMMIT;
```

**M1 acceptance for the rollback file** (in addition to the forward migration acceptance):
- Read live `finalize_extraction` body via `SELECT prosrc FROM pg_proc WHERE proname = 'finalize_extraction'` (or read `phase19_3_finalize_extraction_rpc.sql` if that's the latest source) and paste verbatim into the heredoc above.
- Run `psql -f phase23_iac_container_scanning_rollback.sql` against a staging copy that has phase23 applied. Single command, no manual paste.
- After rollback, run one extraction against a fixture and assert it completes without errors and produces no rows in dropped tables.
- After rollback, `SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='infra_types'` returns 0 rows.

### Schema dump
After applying: `cd backend/extraction-worker && npm run schema:dump` per CLAUDE.md. After any rebase against main, re-dump (memory `feedback_schema_dump_rebase.md`); never force-diff with whitespace.

## API Design

### Endpoints (7 total)

| Method | Route | Auth | Permission | Description |
|---|---|---|---|---|
| GET | `/api/projects/:projectId/iac-findings` | authenticateUser | project member | Paginated list, filters: severity, status, framework, depscore_min |
| POST | `/api/projects/:projectId/iac-findings/:findingId/ignore` | authenticateUser | project member | Toggle status open ↔ ignored. Server validates `findingId.project_id == :projectId`. |
| POST | `/api/projects/:projectId/iac-findings/:findingId/risk-accept` | authenticateUser | project member | Body: `{ reason }`. Same project-id validation. |
| GET | `/api/projects/:projectId/container-findings` | authenticateUser | project member | Paginated list |
| POST | `/api/projects/:projectId/container-findings/:findingId/ignore` | authenticateUser | project member | |
| POST | `/api/projects/:projectId/container-findings/:findingId/risk-accept` | authenticateUser | project member | |
| GET | `/api/projects/:projectId/scanner-summary` | authenticateUser | project member | Rollup `{ iac: {critical, high, medium, low, ignored}, container: {...}, infra_types: [...], last_scan_at }` (opportunity-scout-f6) |

All routes use `authenticateUser` + project-membership middleware. Mutation endpoints scope WHERE clauses with `id = :findingId AND project_id = :projectId`; list endpoints filter by `project_id` AND verify project belongs to caller's org membership server-side.

### Types (TypeScript)

```typescript
// frontend/src/lib/api.ts + backend/src/lib/types.ts

export interface IaCFinding {
  id: string;
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  scanner: 'trivy' | 'checkov';
  scanner_version: string | null;
  rule_id: string;
  framework: 'terraform' | 'kubernetes' | 'helm' | 'dockerfile';
  file_path: string;
  start_line: number | null;
  end_line: number | null;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  depscore: number | null;
  message: string | null;
  description: string | null;
  cwe_ids: string[];
  code_snippet: string | null;
  rule_doc_url: string | null;
  status: 'open' | 'ignored';
  suppressed: boolean;
  risk_accepted: boolean;
  risk_accepted_reason: string | null;
  created_at: string;
}

export interface ContainerFinding {
  id: string;
  project_id: string;
  organization_id: string;
  extraction_run_id: string;
  scanner_version: string | null;
  image_reference: string;
  image_digest: string;
  image_source: 'dockerfile_base';
  os_package_name: string;
  os_package_version: string;
  os_package_ecosystem: string | null;
  osv_id: string | null;
  cve_id: string | null;
  vulnerability_id: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | null;
  cvss_score: number | null;
  epss_score: number | null;
  is_kev: boolean;
  fix_versions: string[];
  layer_digest: string | null;
  depscore: number | null;
  description: string | null;
  rule_doc_url: string | null;
  status: 'open' | 'ignored';
  suppressed: boolean;
  risk_accepted: boolean;
  risk_accepted_reason: string | null;
  created_at: string;
}

export interface ScannerSummary {
  iac: { critical: number; high: number; medium: number; low: number; ignored: number };
  container: { critical: number; high: number; medium: number; low: number; ignored: number };
  infra_types: string[];
  last_scan_at: string | null;
}
```

## Frontend Design

### Routes & Pages

No new top-level routes. Two existing pages extended:
- **Project Security page** — extend the unified table.
- **Project Settings page** — add read-only "Scanners" panel.

### Component Tree (deltas)

```
ProjectSecurityPage (existing)
└── VulnerabilityExpandableTable (extended)
    ├── SecurityFilterBar (extended with iac + container chips)
    ├── TypeIcon (extended; assertNever(row) replaces default fallthrough)
    └── InfraFindingCard (NEW — single component for both iac + container expanded rows)

ProjectSettingsContent (existing)
└── ScannersPanel (NEW, read-only)
    ├── DetectedCoverageSection (chip list of projects.infra_types)
    └── LastScanSection (timestamp + Trigger rescan button)

CreateProjectSidebar (existing)
└── Existing scan preview — show detected_infra_types badges next to ecosystem badges

ProjectOverviewPage (existing)
└── Add InfraScannerTile fed by GET /scanner-summary (rollup tile)
```

### Discriminated-union exhaustiveness (architect-f7)

```typescript
function assertNever(value: never): never {
  throw new Error(`Unreachable: unexpected variant ${JSON.stringify(value)}`);
}

// In every switch on row.type:
switch (row.type) {
  case 'vulnerability': return ...;
  case 'secret': return ...;
  case 'semgrep': return ...;
  case 'license': return ...;
  case 'iac': return ...;
  case 'container': return ...;
  default: return assertNever(row);  // compile error if a variant is missed
}
```

Audit consumers with grep before M3:
```
grep -rn "row\.type ===" frontend/src
grep -rn "row\.type !==" frontend/src
```

### Design specifications

Follow `.cursor/skills/frontend-design/SKILL.md`:
- Cards: `rounded-lg border border-border bg-background-card shadow-sm`
- Tables: `bg-background-card-header` headers, `divide-y divide-border` body
- Severity badges: existing CRITICAL/HIGH/MEDIUM/LOW palette
- Finding-type filter chips: `bg-foreground/5 text-foreground-secondary border-border`
- Framework chips (Terraform / K8s / etc.): same styling as existing ecosystem badges
- Infra icons: `SiTerraform`, `SiKubernetes`, `SiHelm`, `SiDocker` from `@icons-pack/react-simple-icons` — add to `framework-icon.tsx` as `infraIcons` map + `InfraIcon` export
- Rescan button: `outline` variant per memory `feedback_button_style.md`
- Empty state: `text-foreground-secondary text-sm` with `outline` rescan button

### Loading / empty / error states

- **Loading**: existing skeleton patterns.
- **Empty (no infra detected)**: card `No infrastructure files detected. Last scan: <timestamp>` + outline Trigger rescan button.
- **Empty (infra detected, no findings)**: success-tone card `<infra_type> scan complete — no misconfigurations found.`
- **Error**: existing toast pattern.

## User Flows

### First-time scan (happy path)
1. User connects a repo via existing flow.
2. Extraction worker clones, runs SBOM, tree-sitter, dep-scan, then **(new)** detect-infra → IaC scan (Checkov for TF/K8s/Helm; Trivy for Dockerfile) → container scan (Trivy on Dockerfile **final-stage** image) → Semgrep → TruffleHog → finalize.
3. Detection step globs for `Dockerfile`, `*.tf`, `*.tf.json`, K8s YAML, `helm/**`. Produces `string[]` of detected frameworks.
4. **`projects.infra_types` is written by the worker via plain `UPDATE projects SET infra_types = $1 WHERE id = $2` immediately AFTER `finalize_extraction` returns success** (architect-f5 / skeptic-f4 resolved: worker-after-RPC, not inside RPC). Failure window: if the worker crashes between RPC return and the UPDATE, `infra_types` lags one extraction; recovers next run. Acceptable since `infra_types` is consumed by UI tiles, not security-critical paths.
5. Trivy + Checkov run with per-scanner timeouts (see Pipeline section). On timeout: `step warn` to `extraction_step_errors`, pipeline continues.
6. Container scan (**Patch E — multi-stage handling**): parse Dockerfile `FROM` directives. **v1 selects the FINAL stage image** (the last `FROM`) — that is what ships to production. Intermediate builder-stage images (`FROM node:20 AS builder`) are NOT scanned at v1. Apply Patch C namespace check, then pull the final-stage image (public registries directly; ghcr.io via existing GitHub App credentials only) and scan. **No image-digest cache** — each extraction pulls fresh. (Trivy daemon's per-machine layer cache amortizes warm pulls within a worker's lifetime.)
7. `finalize_extraction` carries forward ignored/risk-accepted findings via fingerprint match.
8. User opens security page; filters to "IaC" or "Container"; sees ranked findings.

### Re-extraction (status carryover)
1. User ignores a finding via the row's ignore button.
2. Next extraction runs.
3. `finalize_extraction` carries `status='ignored'` from the previous extraction's row to the new row when `iac_fingerprint` (or `container_fingerprint`) matches.
4. Line drift in IaC files preserved — Checkov's `bc_check_id:resource_address` fingerprint is line-independent.
5. Base-image bumps preserved for container findings — `container_fingerprint = package@vulnerability_id` is digest-independent.

## Pipeline Integration

### Order

```
clone → resolveDeps → SBOM (cdxgen) → tree-sitter → dep-scan
  → detect-infra (compute frameworks; do NOT write to projects.infra_types yet)
  → IaC scan (Checkov for TF/K8s/Helm + Trivy for Dockerfile, parallel)
  → container scan (Trivy on Dockerfile FINAL-stage image, with FROM namespace check — Patch C+E)
  → Semgrep → TruffleHog
  → finalize_extraction (carries forward ignore/risk-accept on new tables)
  → worker UPDATE projects SET infra_types = $detected[]   -- post-RPC (architect-f5 fix)
```

### Timeout budgets (justified)

Per skeptic-f2 + worker-pipeline-auditor-f1:
- **Checkov**: 5 min — file parsing only, no network. Tunable via `DEPTEX_CHECKOV_TIMEOUT_MS`.
- **Trivy config (Dockerfile)**: 3 min — file parsing only.
- **Trivy image**: 8 min per image — wall-clock dominated by registry pull (typical 1GB image: 1-3 min cold). Tunable via `DEPTEX_TRIVY_IMAGE_TIMEOUT_MS`. v1 only pulls one image (Dockerfile FROM), so total budget = 8 min.
- **Project-wide IaC + container cap**: 25 min via outer `withTimeout`.

Benchmarks to record at M0 against `deptex-test-iac` and `deptex-test-container` fixtures and pin the budgets to 2× p95.

### Subprocess pattern

`runScannerSubprocess({ exe, args, cwd, logger, heartbeatIntervalMs = 60000, onHeartbeat, timeoutMs, signal, verboseLogStep? })` extracted into `with-timeout.ts` (architect-f5 + architect-r2-f4). Returns `{ stdout, stderr, exitCode }` — parsing happens in each scanner's own module, not in the shared helper. Logger and `verboseLogStep` mirror `runDepScan`'s `DEPSCAN_VERBOSE_LOG` pattern so a per-scanner `DEPTEX_TRIVY_VERBOSE_LOG` env can stream stdout to `extraction_logs` for in-flight debugging. All three scanner invocations use it.

Heartbeat is **interval-based (60s setInterval)**, independent of stdout chunks (matches existing `runDepScan` pattern). SIGTERM cleanup of `/tmp/trivy` layer downloads on abort.

Trivy invocation flags (worker-pipeline-auditor-f6):
- IaC: `trivy config --format json --skip-db-update --scanners=misconfig <repo>`
- Image: `trivy image --format json --scanners=vuln <imageRef>` (explicit `--scanners=vuln` — disables Trivy's default secret + license overlap with TruffleHog/cdxgen)
- ghcr.io auth uses `DOCKER_AUTH_CONFIG` env (multi-tenant-design-auditor-f5) — never `--username/--password` flags, which would put the GitHub App token in argv.

Checkov invocation:
- `checkov -d <repo> --framework terraform,kubernetes,helm -o json --quiet --skip-download`

### Patch C — Container scan tenant safety (Dockerfile FROM namespace validation)

A malicious user in Org A who controls a project's Dockerfile can write `FROM ghcr.io/victim-org/private-image:latest`. Without validation, the worker would attempt the pull using the project's GitHub App installation token and either (a) succeed if the installation has read access, or (b) leak existence/manifest metadata via error logs. This is the cross-tenant leak surface that returns through the FROM line after Patch 1 cut the cache.

For **each** FROM image resolved during container scan (after multi-stage final-stage selection):

1. **`docker.io/library/*` and bare-name public images** (`node:18`, `nginx:alpine`, etc.) → pull anonymously, scan.
2. **`ghcr.io/<owner>/...`** → resolve `<owner>`. Verify `<owner>` matches the GitHub App installation account login attached to the project (`projects.github_installation_id` → installation.account.login). On mismatch → skip the pull, log `step_metadata.skipped_image=ghcr_namespace_mismatch`, do NOT fall back to anonymous pull.
3. **Any other registry host** (ECR, GCR, Docker Hub private, Quay, Harbor, JFrog) → skip with `step_metadata.skipped_image=private_registry_unsupported_at_v1`. Do NOT retry anonymously — anonymous pulls succeed against some misconfigured private registries and would leak findings.

Skipped images surface in `GET /scanner-summary` as `skipped_images: [{image, reason}]` so the UI can display them rather than silently dropping.

### Skip-on-failure

Each scanner step uses `withTimeout()` + `logStepError()`. On binary missing, malformed output, timeout, or non-zero exit: `step warn` to `extraction_step_errors`, pipeline continues. Soft-switch atomic commit means failed scanner = previous extraction's findings retained for that scanner.

## Rollback & Rollout

(Patch 5 — new section)

### Feature flags (worker env)

- `SCANNERS_IAC_ENABLED` (default `true`) — gates IaC scan step entry. Set to `false` to no-op the step + log warn.
- `SCANNERS_CONTAINER_ENABLED` (default `true`) — same for container scan.

### Kill switches (Redis)

- `kill:scanner:trivy` — set to `1` to short-circuit all Trivy invocations to step warn.
- `kill:scanner:checkov` — same for Checkov.

Worker checks both at step entry. Flipping the Redis key takes effect on the next claimed extraction (no redeploy needed).

### Staged rollout

- `SCANNERS_ROLLOUT_ALLOWLIST` (CSV org IDs; empty = all orgs). When non-empty, only listed orgs run the new scanner steps. Empty/unset = full rollout.
- Recommended sequence: Stage 1 = Henry's org only. Stage 2 = ~5 dogfood orgs. Stage 3 = empty (all orgs).

### Down-migration

- `backend/database/phase23_iac_container_scanning_rollback.sql` — checked in, **manual-only**, **self-sufficient** (Patch F: prior `finalize_extraction` body captured verbatim into the file at M1; no manual paste during incident). Procedure:
  1. Set both kill switches to `1` (Redis).
  2. Wait one extraction cycle (~5 min).
  3. Run rollback SQL via Supabase MCP: `psql -f phase23_iac_container_scanning_rollback.sql` — single transaction, restores RPC + drops triggers + drops tables + drops column.
  4. **Verification step** (rollback-planner-r2-f6): run one fixture extraction, assert it completes without errors; `SELECT 1 FROM information_schema.columns WHERE table_name='projects' AND column_name='infra_types'` returns 0 rows; reload frontend security page and confirm no console errors.

### Kill-switch failure semantics (rollback-planner-r2-f2)

Worker checks Redis kill switches with a 1s timeout + try/catch. On Redis unreachable or timeout: fall back to env-flag value (so kill switches default-open if Redis is down AND `SCANNERS_*_ENABLED=true`). Log warn on every Redis fallback. Matrix:

| Redis | env flag | kill key | Outcome |
|---|---|---|---|
| up | true | unset/0 | Run scanner |
| up | true | 1 | Skip + step warn |
| up | false | * | Skip + step warn |
| down | true | (unread) | Run scanner + log warn `redis_kill_switch_unreachable` |
| down | false | (unread) | Skip + step warn |

### Bad-data recovery

If a parser bug ships, every finding row carries `scanner_version` + `extraction_run_id`. **Important** (rollback-planner-r2-f4): a naive `DELETE WHERE scanner_version = ...` ALSO deletes user decisions (suppressed, risk_accepted, risk_accepted_reason). Two-stage procedure preserves human triage work:

```sql
-- Stage 1 — preservation pass: backup decisions for affected rows.
CREATE TABLE bad_data_decisions_backup_<date> AS
SELECT id, project_id, iac_fingerprint, scanner, status,
       suppressed, suppressed_by, suppressed_at,
       risk_accepted, risk_accepted_by, risk_accepted_at, risk_accepted_reason
FROM project_iac_findings
WHERE scanner = 'checkov' AND scanner_version = 'checkov@3.2.5'
  AND (status = 'ignored' OR suppressed OR risk_accepted);

-- Stage 2 — surgical purge.
DELETE FROM project_iac_findings
  WHERE scanner = 'checkov' AND scanner_version = 'checkov@3.2.5';

-- Stage 3 — restore: a one-off SQL after re-extraction backfills decisions onto
-- re-emitted rows where (project_id, scanner, iac_fingerprint) matches the backup.
-- Same pattern for project_container_findings keyed on container_fingerprint.
```

If a clean reset (decisions intentionally lost) is desired — e.g., the parser bug also corrupted the decisions themselves — skip Stage 1 + Stage 3 and document the user-impactful purge in the incident comms.

### Trivy version rollback

Trivy is pinned in the Dockerfile. Binary-only rollback = revert the Dockerfile commit and redeploy the worker. App code stays the same.

## Implementation Tasks

### M0 — Benchmark [S, ~0.5 day]

- [ ] Pin Trivy 0.50.4 + Checkov 3.2.x in a scratch Dockerfile.
- [ ] Run against fixture targets: `deptex-test-iac` (TF + K8s + Dockerfile) and a representative real repo Henry has handy.
- [ ] Record Checkov, Trivy config, Trivy image wall-clock (cold + warm).
- [ ] Set production timeouts to 2× p95.
- **Acceptance**: M2 timeout values are evidence-based, not aspirational.

### M1 — Schema + Worker Bundle [S, ~1.5 days]

- [ ] Apply migration `backend/database/phase23_iac_container_scanning.sql` via Supabase MCP (memory `feedback_apply_migrations_via_mcp.md`).
- [ ] **Capture prior `finalize_extraction` body verbatim** (Patch F): `SELECT prosrc FROM pg_proc WHERE proname = 'finalize_extraction'` → paste into the heredoc inside `phase23_iac_container_scanning_rollback.sql`. Do NOT leave a `...` placeholder.
- [ ] Apply down-migration sibling `phase23_iac_container_scanning_rollback.sql` (manual-only — checked in, not auto-run).
- [ ] **Verify rollback runs end-to-end against staging copy**: apply phase23 forward migration, then `psql -f phase23_iac_container_scanning_rollback.sql`, then run one fixture extraction asserting it completes successfully (no errors referencing dropped tables; `infra_types` column truly absent).
- [ ] Run `cd backend/extraction-worker && npm run schema:dump`. After any rebase against main, re-dump.
- [ ] Add Trivy + Checkov + helm CLI to `Dockerfile` (worker-pipeline-auditor-f4: helm CLI is required by Checkov for Helm rendering). Pin versions.
- [ ] Verify `binaryAvailable('trivy')` / `binaryAvailable('checkov')` / `binaryAvailable('helm')` at worker startup.
- [ ] Document image-size delta (megabyte count). **HARD GATE** (worker-pipeline-auditor-r1-f2): if combined image > 500MB OR > 1.5× current size, STOP — file a follow-up plan choosing between (a) split container scanning into separate Fly app `extraction-worker-container`, or (b) move Trivy/Checkov to scratch-based sidecar images via Fly machine-exec. Henry decides between (a) and (b) before M2 begins.
- **Acceptance**:
  - Tables exist with correct UNIQUE shape verified via supabase-js: insert two findings with NULL start_line + matching other keys → second is UPDATE not duplicate INSERT (Patch A); insert a row whose payload supplies an explicit `vulnerability_id` value → INSERT rejected (Patch B); insert a row with tampered `organization_id` → trigger overrides to `(SELECT organization_id FROM projects)` value (Patch D).
  - **Automated** RPC carry-forward test (test-strategy-auditor-r2-f3): `backend/database/__tests__/finalize-extraction-phase23.test.sql` covers (i) IaC fingerprint carry-forward, (ii) container fingerprint carry-forward, (iii) regression guard for existing semgrep/secret/dep-vuln carry-forward, (iv) NULL fingerprint policy = treated as new. Runs in CI (no `manual SQL` step).
  - Rollback file runs without manual paste (Patch F verification above).
  - Both binaries + helm runnable in worker shell.
- **Files**: `backend/database/phase23_iac_container_scanning.sql`, `backend/database/phase23_iac_container_scanning_rollback.sql`, `backend/database/__tests__/finalize-extraction-phase23.test.sql`, `backend/extraction-worker/Dockerfile`, `backend/database/schema.sql`

### M2 — Pipeline Integration [M, ~3.5 days]

- [ ] **Read M0 benchmark output** and update `DEPTEX_*_TIMEOUT_MS` env defaults to `ceil(2 × max(fixture_p95, real_repo_p95))`. If either p95 exceeds the documented budget by > 50%, escalate before continuing M2.
- [ ] Extract `runScannerSubprocess({ exe, args, cwd, logger, heartbeatIntervalMs = 60000, onHeartbeat, timeoutMs, signal, verboseLogStep? }) → Promise<{stdout, stderr, exitCode}>` helper into `backend/extraction-worker/src/with-timeout.ts` (architect-r2-f4: `logger` + `verboseLogStep` mirror `runDepScan`'s `DEPSCAN_VERBOSE_LOG` pattern; helper does NOT parse — each scanner module parses its own JSON).
- [ ] Create `scanners/detect-infra.ts`: globs for `Dockerfile`, `*.tf`, `*.tf.json`, K8s YAML (`kind:` heuristic), `helm/**` directories with `Chart.yaml`. Returns `string[]`. Pure function — no DB writes.
- [ ] Create `scanners/checkov.ts`:
  - `runCheckov(repoPath, frameworks, signal, heartbeat, timeoutMs) → IaCFinding[]`
  - Args: `checkov -d <repo> --framework terraform,kubernetes,helm -o json --quiet --skip-download`
  - Parser: extract `bc_check_id`, `resource_address`, severity, file_path, start_line, message. Compute `iac_fingerprint = checkov:${bc_check_id}:${resource_address}`. **Fingerprint NULL policy** (data-model-auditor-f4): if `resource_address` is empty, emit `iac_fingerprint = null` — never synthesize a degenerate string. Unit-test asserts `/^checkov:CKV_[A-Z0-9_]+:[\w./-]+$/` for non-null fingerprints.
- [ ] Create `scanners/trivy.ts`:
  - `runTrivyConfig(repoPath, ...) → IaCFinding[]` for Dockerfile only — `trivy config --format json --skip-db-update --scanners=misconfig <repo>`
  - `parseDockerfileFinalStage(dockerfilePath) → { imageRef, stageIndex, totalStages }` — **Patch E**: parse all `FROM` directives in order; v1 returns the LAST FROM (production-shipping image). Handle `--platform`, `@sha256:` digest pins, `AS <stage>` aliases. Test fixtures: simple single-FROM, two-stage Node→nginx, three-stage with `FROM scratch` intermediate, FROM with platform/digest pin.
  - `runTrivyImage(imageRef, dockerAuthConfig, signal, heartbeat, timeoutMs) → ContainerFinding[]` — `trivy image --format json --scanners=vuln <imageRef>` with `DOCKER_AUTH_CONFIG` env (multi-tenant-design-auditor-f5: never `--username/--password` — keeps token out of argv).
  - Parsers: extract package, version, OSV/CVE id, severity, layer_digest. Compute `container_fingerprint = ${package_name}@${vulnerability_id}`. NULL policy mirrors IaC.
- [ ] Create `scanners/storage.ts`:
  - `upsertIaCFindings(supabase, projectId, runId, findings)` — bulk upsert by `(project_id, rule_id, file_path, start_line_key, extraction_run_id)` — i.e., the plain column-list UNIQUE index (Patch A). `start_line_key` is GENERATED, so DO NOT supply it in payload — Postgres derives it. **Do NOT pass `organization_id`** as a caller parameter (Patch D): the BEFORE INSERT trigger derives it from `projects.organization_id`. Worker must not include `organization_id` in upsert payload (or pass `null` and let trigger overwrite).
  - `upsertContainerFindings(supabase, projectId, runId, findings)` — bulk upsert by `(project_id, image_digest, os_package_name, os_package_version, vulnerability_id, extraction_run_id)`. **Patch B: scrub `vulnerability_id` from payload** before `.upsert()` — it is `GENERATED ALWAYS` and Postgres rejects explicit values. Same Patch D org_id rule.
  - delete-stale via `WHERE project_id = $1 AND extraction_run_id <> $2`.
- [ ] Patch C — namespace check before container pull:
  - For each FROM image: classify as (a) public Docker Hub → pull anonymously, (b) ghcr.io → resolve `<owner>` and verify against `projects.github_installation_id`'s account login, skip + warn if mismatch, (c) any other host → skip + warn `private_registry_unsupported_at_v1`.
  - Surface skipped images in scanner-summary endpoint as `skipped_images: [{image, reason}]`.
- [ ] Wire into `pipeline.ts`:
  - After `dep-scan`, call `detect-infra` (compute only, no DB write yet).
  - Read `SCANNERS_IAC_ENABLED` + `SCANNERS_CONTAINER_ENABLED` env. Read Redis kill switches with 1s timeout + try/catch (rollback-planner-r2-f2: fall back to env-flag value if Redis unreachable; log warn on fallback). Read `SCANNERS_ROLLOUT_ALLOWLIST` and check current org. Skip step if any kill applies.
  - Run Checkov + Trivy config in parallel (Promise.all with their own withTimeout each).
  - For container scan: select FINAL Dockerfile FROM (Patch E), apply Patch C namespace check, then pull + scan via Trivy. v1 source = `dockerfile_base` only.
  - After `finalize_extraction` returns success, worker UPDATEs `projects.infra_types = detected[]` (architect-f5: worker-after-RPC, NOT inside RPC; document the failure window).
- [ ] Each scanner step heartbeat-on-interval, SIGTERM-clean.
- [ ] Trivy DB cache: mount to existing /data volume; seed via dep-scan VDB pattern (don't bake into image).
- **Acceptance**:
  - Extraction on `deptex-test-iac` + `deptex-test-container` fixtures writes findings to both new tables.
  - **Multi-stage Dockerfile fixture** (Patch E): `FROM node:20 AS builder` + `FROM nginx:alpine` produces container findings against nginx, not node.
  - **Dockerfile FROM namespace mismatch** (Patch C): a project whose GitHub App installation is org-A, with `FROM ghcr.io/org-B/foo` in its Dockerfile, produces zero container findings + warn step_error `ghcr_namespace_mismatch`.
  - **organization_id tampering** (Patch D): if storage layer attempts to write findings with a wrong organization_id, the trigger overwrites it to `(SELECT organization_id FROM projects)`. Negative test passes.
  - **vulnerability_id scrub** (Patch B): if storage payload includes `vulnerability_id`, INSERT fails (proves explicit value is rejected); after scrub, INSERT succeeds.
  - `finalize_extraction` carries forward an ignored finding across re-extraction (covered by M1 SQL test + M5 e2e).
  - Kill switch flipping causes step warn next run; Redis-unreachable falls back to env flag.
  - Rollout allowlist excludes a non-listed org.
- **Files**: `backend/extraction-worker/src/with-timeout.ts` (extension), 4 new files in `backend/extraction-worker/src/scanners/`, `backend/extraction-worker/src/pipeline.ts`

### M3 — Backend API Routes [S, ~2 days]

- [ ] Create `backend/src/routes/scanner-findings.ts`:
  - 6 finding endpoints (3 per type) + 1 summary endpoint
  - Reuse existing project-membership middleware
  - Mutation endpoints scope `WHERE id = :findingId AND project_id = :projectId`
- [ ] Register router in `backend/src/index.ts`.
- [ ] Add `scanner-summary` rollup query (existing project overview tile pattern).
- **Acceptance**: each endpoint hits via curl; tenant-isolation tests pass (see Testing); no plaintext sensitive data in any response.
- **Files**: 1 new route file, `backend/src/index.ts`

### M4 — Frontend Unified Table + Settings Panel [M, ~3 days]

- [ ] Extend `frontend/src/lib/api.ts` with `IaCFinding`, `ContainerFinding`, `ScannerSummary` types + fetch helpers.
- [ ] Extend `SecurityTableRow` discriminated union with `iac` + `container` variants.
- [ ] Replace every `default:` return on `row.type` switches with `assertNever(row)`. Audit consumer set with grep before starting.
- [ ] Extend `TypeIcon`, `getRowTitle`, `getRowDescription`, plus discovered consumers.
- [ ] Create `InfraFindingCard.tsx` — single component with kind-specific sub-blocks (file:line for iac, image:package for container).
- [ ] Extend `SecurityFilterBar.tsx` with `iac` + `container` finding-type chips.
- [ ] Add `InfraIcon` map to `framework-icon.tsx`: SiTerraform, SiKubernetes, SiHelm, SiDocker.
- [ ] Update `CreateProjectSidebar.tsx` scan preview with detected `infra_types` badges.
- [ ] Add `InfraScannerTile` to project overview page fed by `GET /scanner-summary`.
- [ ] Empty state with rescan CTA when project has no detected infra.
- [ ] Project Settings: add read-only `ScannersPanel` showing detected coverage + last-scan-at + Trigger rescan button (reuses existing rescan endpoint).
- **Acceptance**: opening project security page shows iac + container findings in unified table; finding-type filter chips work; expanding a row shows code snippet + ignore/risk-accept; empty state renders; rescan button triggers a new extraction; opening project settings → Scanners shows detected coverage chips.
- **Files**: `frontend/src/lib/api.ts`, `frontend/src/components/security/VulnerabilityExpandableTable.tsx`, `frontend/src/components/security/SecurityFilterBar.tsx`, `frontend/src/components/security/InfraFindingCard.tsx` (new), `frontend/src/components/framework-icon.tsx`, `frontend/src/components/CreateProjectSidebar.tsx`, `frontend/src/app/pages/ProjectSettingsContent.tsx`, project overview page consumers

### M5 — Testing & Validation [S, ~1.5 days]

(See Testing & Validation Strategy below for the full enumeration. Every row of the Success Criteria → Test mapping table corresponds to a checkbox here.)

- [ ] Backend unit tests in `backend/src/routes/__tests__/scanner-findings.test.ts`: list filter + pagination, ignore + risk-accept toggle, **tenant isolation cross-project/cross-org test for ALL 7 endpoints (incl. GET /scanner-summary)**, **Patch A duplicate-on-NULL-start_line guard via supabase-js upsert**, scanner-summary correctness incl. skipped_images surface.
- [ ] SQL-level RPC test `backend/database/__tests__/finalize-extraction-phase23.test.sql` (Patch 3): IaC fingerprint carry-forward, container fingerprint carry-forward, **regression guard for existing semgrep/secret/dep-vuln carry-forward**, NULL fingerprint policy.
- [ ] SQL-level trigger test `backend/database/__tests__/finding-org-id-trigger.test.sql` (Patch D): tampered organization_id is overwritten by trigger.
- [ ] Worker integration tests:
  - `extraction-worker/test/detect-infra.test.ts` — 10 adversarial fixtures (5 positive + 5 negative).
  - `extraction-worker/test/dockerfile-multistage.test.ts` (Patch E) — final-stage selection across multi-stage variants.
  - `extraction-worker/test/dockerfile-namespace-check.test.ts` (Patch C) — ghcr.io owner mismatch + non-Hub registry skip.
  - `extraction-worker/test/storage-payload.test.ts` (Patch B) — vulnerability_id scrub from upsert payload.
  - `extraction-worker/test/failure-modes.test.ts` — binary-missing, malformed-output, timeout, OOM.
  - `extraction-worker/test/kill-switch.test.ts`, `feature-flag.test.ts`, `rollout-allowlist.test.ts`, `redis-fallback.test.ts` — Patch G + rollback-planner-r2-f2.
- [ ] **Soft-switch carry-forward test** (`extraction-worker/test/soft-switch-carryforward.test.ts`): ignore a finding, re-extract with line drift, assert ignore preserved via fingerprint match. Same for container with image-digest change. Negative case: NULL fingerprint → status NOT carried.
- [ ] **Docker image smoke test** (`extraction-worker/test/docker-smoke.test.ts`): pinned versions; **DB-mounted Trivy `image --download-db-only` succeeds** (catches missing /data mount); **Checkov 1-rule fixture scan succeeds inside built image** (catches pip-conflict mid-scan); drift-detector vs source-tree e2e; network-isolated IaC findings.
- [ ] **Rollback e2e** (`backend/database/__tests__/rollback-phase23.test.sh`, Patch F): apply phase23 forward against staging copy, run `psql -f phase23_iac_container_scanning_rollback.sql` (single command, no manual paste), run one fixture extraction asserting it completes, verify `infra_types` column absent.
- [ ] Frontend tests: TS-level exhaustiveness of discriminated union (assertNever); optimistic ignore + server-error rollback; URL-param round-trip preserves filter chip state on hard reload.
- [ ] Manual UI walk-through: extract a fixture repo, verify findings, expand cards, ignore one, re-extract, verify persisted.
- **Acceptance**: all tests pass; every Success Criteria row maps to a passing named test.

**Total v1 estimated effort**: ~12 working days post-patch (M0: 0.5, M1: 2, M2: 4, M3: 2, M4: 3, M5: 1.5). M1 and M2 grew slightly from the post-round-1 estimate to absorb: rollback file verbatim capture + e2e verification, Patch A/B/D acceptance tests, multi-stage Dockerfile parser + namespace check fixtures, Redis fallback test. Still down meaningfully from original 22d.

## Testing & Validation Strategy

### Backend
- **List + filter + pagination** per route (mock supabase using `setTableResponse` / `pushTableResponse` per memory `backend_test_mock_patterns.md`).
- **Ignore + risk-accept toggle** round-trip.
- **Tenant isolation (mandatory, enumerated for ALL 7 endpoints)** — for each of: GET /iac-findings, POST /iac-findings/:id/ignore, POST /iac-findings/:id/risk-accept, GET /container-findings, POST /container-findings/:id/ignore, POST /container-findings/:id/risk-accept, **GET /scanner-summary**: user A in org X, project Y in org Z → 403 (or empty 200 for list). For scanner-summary specifically, assert it does NOT return zeroed counts to a foreign caller (must 403, not silently empty). Use `/permission|access/i` matcher.
- **scanner-summary correctness** — `backend/src/routes/__tests__/scanner-findings.test.ts`. Cases: (a) 0 findings → all-zero rollup, (b) mixed severities + ignored → ignored counted only in `ignored` bucket, (c) `infra_types` matches `projects.infra_types`, (d) `last_scan_at` matches latest extraction completion, (e) skipped_images surface (Patch C) when present.

### Worker integration
- **Detect-infra adversarial fixtures (10 cases — 5 positive, 5 negative)** (test-strategy-auditor-r2-f7):
  - Positive: TF-only repo, K8s-only repo, Helm chart with Chart.yaml, single-Dockerfile repo, monorepo with all four detected.
  - Negative: vendored `*.tf` inside `node_modules/` (NOT detected), Helm directory missing `Chart.yaml` (NOT detected as Helm), `*.yml` with `kind: Document` (e.g., AsciiDoc — NOT detected as K8s), Terraform `examples/` subdirectory (decision: detected — document expectation), Dockerfile inside `test/fixtures/` (decision: detected — document expectation).
- **Happy-path scan** on `deptex-test-iac` (Terraform + K8s + Dockerfile) + `deptex-test-container` (with deliberately CVE-prone base image).
- **Multi-stage Dockerfile fixture** (Patch E): `FROM node:20 AS builder` + `FROM nginx:alpine` → container findings reference nginx (final stage), not node. Plus: `FROM scratch` intermediate; `FROM` with `--platform`; `FROM` with `@sha256:` digest pin.
- **Patch C namespace check tests**:
  - Project's GitHub App installs to org-A; Dockerfile has `FROM ghcr.io/org-A/foo` → pull attempted with installation token.
  - Project's GitHub App installs to org-A; Dockerfile has `FROM ghcr.io/org-B/foo` → skip with `step_metadata.skipped_image=ghcr_namespace_mismatch`, NO pull attempt, NO container findings rows.
  - Dockerfile has `FROM ecr.aws/foo` → skip with `private_registry_unsupported_at_v1`.
- **Failure modes** (`extraction-worker/test/failure-modes.test.ts`):
  - Trivy binary renamed → `binaryAvailable` returns false → step warn.
  - Trivy returns malformed JSON → parser throws caught → warn row + Semgrep/TruffleHog still runs.
  - Trivy hangs > 8 min → SIGTERM via abort signal → warn row + pipeline continues.
  - Checkov OOM/exit non-zero → warn row + Trivy results still committed.
- **Kill switch + feature flag tests** (test-strategy-auditor-r2-f1):
  - `extraction-worker/test/kill-switch.test.ts`: set `kill:scanner:trivy=1` in test Redis → next-run Trivy step writes warn row, pipeline continues.
  - `extraction-worker/test/feature-flag.test.ts`: `SCANNERS_IAC_ENABLED=false` → IaC step entry skipped + warn.
  - `extraction-worker/test/rollout-allowlist.test.ts`: org-id not in `SCANNERS_ROLLOUT_ALLOWLIST` → both steps skipped + warn.
  - `extraction-worker/test/redis-fallback.test.ts` (rollback-planner-r2-f2): mock Redis timeout → kill-switch read falls back to env flag value, logs warn `redis_kill_switch_unreachable`.
- **Soft-switch carry-forward**:
  - IaC: ignore finding → re-extract with comment added above (line drift) → ignore preserved via `iac_fingerprint`.
  - Container: risk-accept finding → re-extract after base-image bump (new digest, same package+CVE) → risk-accept preserved via `container_fingerprint`.
  - Risk-accept reason text preserved across re-extraction.
  - **Negative**: finding without fingerprint → re-extract → status NOT carried (intentional per fingerprint-NULL policy).

### Docker image smoke (memory `feedback_docker_vs_source_e2e.md`)
- `docker run <image> trivy --version` → pinned version.
- `docker run <image> trivy image --download-db-only --skip-update <known-image>` → DB present at /data volume (test-strategy-auditor-r2-f5: catches missing-volume-mount regressions).
- `docker run <image> checkov -d /fixtures/single-rule-tf -o json` → exit + 1 finding (test-strategy-auditor-r2-f5: catches pip-conflict mid-scan errors that pass `--version` but throw at runtime).
- Fixture scan inside actual built image vs source-tree e2e — same findings count (drift detector).
- Network-isolated container run — IaC misconfig findings still produced.

### Frontend
- TS-level exhaustiveness assertion: adding a deliberately-unhandled type to `SecurityTableRow` produces a compile error.
- Optimistic ignore → server error → UI state reverts.
- URL hard-reload with `?findingTypes=iac,container&severity=HIGH` re-applies filters.

### Performance targets
- IaC + container combined: ≤ 5 min wall-clock typical.
- Per-scanner timeout: M0 benchmark sets 2× p95.
- API list endpoints: < 200 ms typical (≤ 500 findings).

### Regression
- Existing extraction pipeline unchanged.
- Soft-switch atomic commit honored: re-extracting preserves user decisions on existing finding types.
- Schema dump current; CI schema-check passes.

### Success Criteria → Test mapping (Patch 6 + Patch G)

| Success criterion | Named test | File |
|---|---|---|
| All v1 IaC frameworks scan correctly | `detect-infra.test.ts` + fixture e2e | `extraction-worker/test/detect-infra.test.ts` |
| Container images scan from public + ghcr.io | container fixture e2e | `extraction-worker/test/container-scan.test.ts` |
| **Multi-stage Dockerfile uses final-stage image (Patch E)** | multi-stage fixture | `extraction-worker/test/dockerfile-multistage.test.ts` |
| **Dockerfile FROM namespace check (Patch C)** | namespace mismatch fixture | `extraction-worker/test/dockerfile-namespace-check.test.ts` |
| Findings appear with correct depscore + filter chips | frontend unified-table integration test | `frontend/src/components/security/__tests__/unified-table.test.tsx` |
| User-decision preservation across re-extraction | soft-switch carry-forward test | `extraction-worker/test/soft-switch-carryforward.test.ts` |
| **finalize_extraction RPC carry-forward + regression guard (Patch 3)** | RPC unit test | `backend/database/__tests__/finalize-extraction-phase23.test.sql` |
| Scanner timeout produces warn row | failure-mode fixture | `extraction-worker/test/failure-modes.test.ts` |
| **Kill switch (`kill:scanner:trivy`) flipped → next-run step warn (Patch G)** | kill-switch e2e | `extraction-worker/test/kill-switch.test.ts` |
| **Feature flag (`SCANNERS_*_ENABLED=false`) disables step entry (Patch G)** | flag-gate e2e | `extraction-worker/test/feature-flag.test.ts` |
| **Rollout allowlist excludes non-listed org → step skipped (Patch G)** | allowlist e2e | `extraction-worker/test/rollout-allowlist.test.ts` |
| **Redis-unreachable kill-switch fallback to env flag** | redis-fallback test | `extraction-worker/test/redis-fallback.test.ts` |
| Empty state renders | frontend empty-state test | `frontend/src/components/security/__tests__/empty-state.test.tsx` |
| `infra_types` reflected in 4 entry points | manual smoke + e2e | manual checklist |
| **Tenant isolation on ALL 7 endpoints (incl. scanner-summary)** | per-route 403 test | `backend/src/routes/__tests__/scanner-findings.test.ts` |
| **scanner-summary returns correct rollup counts (incl. skipped_images surface)** | rollup correctness | `backend/src/routes/__tests__/scanner-findings.test.ts` |
| **Patch A — duplicate-on-NULL-start_line guard** | supabase-js upsert test | `backend/src/routes/__tests__/scanner-findings.test.ts` |
| **Patch B — vulnerability_id scrub** | storage payload test | `extraction-worker/test/storage-payload.test.ts` |
| **Patch D — organization_id trigger overwrite** | trigger test | `backend/database/__tests__/finding-org-id-trigger.test.sql` |
| **Patch F — rollback runs end-to-end without manual paste** | rollback e2e | `backend/database/__tests__/rollback-phase23.test.sh` |
| Encryption round-trip | n/a — no cred store at v1 | (deferred to v1.5) |
| Image-digest cache | n/a — no cache at v1 | (deferred to v1.5) |

## Risks & Open Questions

### Risks (post-patch)
- **Trivy CLI shape changes** — pin to 0.50.x in Dockerfile; bump deliberately. `scanner_version` column on findings enables surgical purges if a bump produces bad rows.
- **Container pull bandwidth** — first-time pull of a 1GB+ base image is slow. Trivy daemon's per-machine layer cache amortizes warm pulls within a worker's lifetime. Acceptable at v1; image-digest cache deferred to v1.5.
- **Checkov Python dependency** — pin minor version; install in venv if conflicts surface in CI.
- **Image-size delta from bundling** — measured at M1. If > 500MB, fork-point: split container scanning into a separate worker app.

### Open Questions (post-round-2-patch)
- **Helm rendering with custom values.yaml** — Checkov scans Helm with default values. v1 accepts the limitation; v1.5 candidate for custom values support if false-negatives surface. (Round-2 candidate: cut Helm from v1 entirely → 3 frameworks.)
- **Is `scanner_summary` query fast enough for the project overview tile?** — likely yes (indexed by `(organization_id, status, depscore DESC NULLS LAST)`). Re-evaluate if dogfood shows lag; opportunity-scout-f3 suggested a SQL view as the materialized form if needed.
- **Open scope-trim candidates** (round-2 P1s — not blocking, Henry's call):
  - Cut M0 benchmark (saves ~0.5d; defaults from upstream docs + first dogfood run is the actual benchmark).
  - Cut Helm framework (saves fixture + Chart.yaml glob + InfraIcon).
  - Cut `SCANNERS_ROLLOUT_ALLOWLIST` (kill switches already cover rollback for 1-user v1).

### Resolved (round 2)
- Trivy CLI auth flag → `DOCKER_AUTH_CONFIG` env (not `--username/--password`); decided in Subprocess pattern section.
- `infra_types` write coordination → worker UPDATE after RPC returns success (architect-f5); failure window documented.
- Fingerprint format collision risk → `scanner` column added to partial UNIQUE (skeptic-f2).
- `runScannerSubprocess` signature → includes `logger` + `verboseLogStep` matching `runDepScan` (architect-r2-f4).
- Down-migration self-sufficiency → prior RPC body captured verbatim at M1; single-transaction rollback with verification (Patch F).
- Bad-data recovery decision-preservation → two-stage backup → purge → restore procedure documented.
- Redis kill-switch unreachable → 1s timeout + try/catch + fallback to env flag + warn log.

### Decisions deferred to user
- **Confirm Patch 1 scope cuts** — Henry already approved the REWORK direction; this plan is the result. If anything in the v1.5 deferral list should actually stay in v1, flag now.

## Dependencies

- **Soft-switch atomic commit pattern + `finalize_extraction` RPC** — extended in this plan for new-table carry-forward.
- **`extraction_step_errors`** + `with-timeout.ts` — already shipped; reused.
- **GitHub App** + existing token resolution — reused for ghcr.io public + private base-image pulls. **No** per-project encrypted credential store at v1.
- **Existing depscore module** (`backend/extraction-worker/src/depscore.ts`) — extended for IaC scoring (CIS severity × asset_tier multiplier). Container CVEs use existing rubric unchanged.
- **`framework-icon.tsx`** + `VulnerabilityExpandableTable.tsx` + `SecurityFilterBar.tsx` — extended.
- **PGLite local-mode** + schema dump — refresh per CLAUDE.md.
- **Apply migrations via Supabase MCP** (memory `feedback_apply_migrations_via_mcp.md`).
- **Conventional Commits + no Co-Authored-By trailers** (memory `feedback_commit_format.md`, `feedback_no_coauthor_trailer.md`).

## Success Criteria

(All map to a named test in the table above.)

- All v1 in-scope IaC frameworks (Terraform, Kubernetes, Helm, Dockerfile) scan correctly against fixture repos.
- Container images pull and scan from public Docker Hub and ghcr.io (via GitHub App). Private non-GitHub registries deferred to v1.5 — out of v1 scope.
- **Multi-stage Dockerfiles** (Patch E): final-stage image is the one scanned, not the first FROM.
- **Dockerfile FROM namespace check** (Patch C): `FROM ghcr.io/<other-org>/...` is rejected with a warn step_error, no pull attempt, no findings rows. Non-Hub-public registries skip with `private_registry_unsupported_at_v1`.
- **organization_id integrity** (Patch D): trigger-overwritten regardless of caller-supplied value.
- **vulnerability_id scrub** (Patch B): storage layer never includes the GENERATED column in upsert payload.
- **Patch A — duplicate-on-NULL-start_line** prevented by `start_line_key` GENERATED column in plain UNIQUE.
- Findings appear in the unified security table with correct depscore, severity, type-filter chips, ignore + risk-accept actions.
- User-decision preservation: ignore an IaC finding, re-extract with line drift, status persists. Risk-accept a container CVE, base-image bumps, decision persists. Findings without fingerprint do NOT carry status (intentional).
- Scanner timeout: artificially-slow fixture causes timeout, pipeline completes, `extraction_step_errors` row recorded as `warn`.
- Empty state renders correctly on a project with no detected IaC and no Dockerfile.
- All four entry points (project card, project overview, security page, settings tab) reflect detected `infra_types` coherently.
- Tenant isolation: cross-project / cross-org access attempts return 403/empty for ALL 7 endpoints (incl. scanner-summary).
- Kill switches function correctly; Redis-unreachable falls back to env flag with warn log; rollout allowlist scopes correctly.
- **Patch F**: rollback runs end-to-end via single `psql -f` invocation, no manual paste; verification step confirms infra_types column absent + post-rollback extraction completes.
- Schema dump refreshed; CI schema-check passes.

## Future v2 Expansions (5-line pointer)

The full menu lives in `.cursor/plans/research-iac-containers.md`. Next obvious moves after v1 lands:

1. **Container Reachability** (the Endor counter-play, leverages Phase 2 tree-sitter — frontier feature)
2. **Aegis IaC Auto-Fix Agent** (extends Fix Agent with `terraform validate` / `kubeval` retry loop)
3. **Encrypted multi-registry credential store + configured images** (v1.5 — adds ECR/GCR/ACR/Quay/Harbor)
4. **Image-digest cache + reaper** (v1.5 — once dogfood shows real repeat-pull cost)
5. **PR blocking via flow builder** (waits for in-flight flow builder to ship its PR-check evaluator)
6. **Custom IaC policy via existing JS policy engine** (cheap; massive leverage on existing Monaco editor + AI assistant)
7. **Aegis chat tools for IaC** (`list_iac_findings`, `explain_iac_finding`, etc. — rides on Aegis v3 rails)
8. **GitHub Actions workflow scanner** (Scorecards/StepSecurity-class checks)
9. **Compliance framework mapping** (rich SOC 2 / ISO 27001 dashboard)

## Recommended Next Step

Run `/review-plan --no-debate` against this patched plan to confirm the verdict moves from REWORK → REVISE/READY before `/implement`. If it lands READY (or REVISE with only quick patches), proceed to `/implement` — start with M0 in a new worktree off main per memory `feedback_worktree_setup.md` (always copy `backend/.env` + `frontend/.env`; run `npm install`).
