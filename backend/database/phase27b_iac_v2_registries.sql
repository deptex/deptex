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
  CONSTRAINT orc_id_org_uq UNIQUE (id, organization_id)
);

CREATE INDEX IF NOT EXISTS idx_orc_org ON organization_registry_credentials(organization_id);

-- No org_id derivation trigger needed: organization_id is set directly by the
-- route layer (which authenticateUser already validated org membership against
-- the :id path segment). The composite UNIQUE + composite FK on
-- project_configured_images below prevent cross-org cred reuse downstream.

-- Helper trigger used by project_configured_images below. Mirrors
-- enforce_finding_org_id() (phase25). BEFORE INSERT OR UPDATE (no column list)
-- so org re-derives on every UPDATE.
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
  -- future internal RPC, etc.).
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
-- project moves DO NOT drop the cred (creds are org-shared).
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
-- INSERT-only and NEVER returned via API.
--
-- Composite PK includes scanner discriminator + Trivy DB-version-day so
-- multi-scanner Phase 2 (Grype/Syft) and CVE-DB freshness within the 7-day TTL
-- are addressed.
--
-- Worker writes only when ALL of: Trivy exit=0, no warnings, structurally-valid
-- parse, crane probe digest matches Trivy's RepoDigest. Cache write contract is
-- enforced by callers, not the table itself.
-- A nightly reaper drops rows older than 30 days (see below).
-- ============================================================
CREATE TABLE IF NOT EXISTS container_image_scan_cache (
  -- Bare 64-hex digest (no 'sha256:' prefix, no 'repo@' prefix), optional
  -- platform suffix for manifest-list resolution. normalizeDigest() helper
  -- produces this canonical form at every reader/writer.
  image_digest TEXT NOT NULL CHECK (image_digest ~ '^[a-f0-9]{64}(\+linux/(amd64|arm64))?$'),
  -- Discriminator so Grype/Syft (Phase 2+) don't collide on PK with Trivy.
  scanner TEXT NOT NULL CHECK (scanner IN ('trivy')),
  -- Trivy/Checkov binary version that produced this scan.
  scanner_version TEXT NOT NULL,
  -- Trivy CVE DB date (UTC YYYY-MM-DD). Within the 7-day TTL the CVE DB can
  -- update; including it in the PK forces a re-scan when the DB rolls over.
  trivy_db_version_day TEXT NOT NULL CHECK (trivy_db_version_day ~ '^\d{4}-\d{2}-\d{2}$'),
  -- Scan result body. STORAGE EXTENDED + 1MB cap; parser truncates to top-N
  -- findings sorted by severity desc if larger.
  scan_results JSONB NOT NULL CHECK (octet_length(scan_results::text) <= 1048576),
  -- sha256 of canonicalized scan_results JSON. Verified on every read; mismatch
  -- → log warning + treat as cache miss. Defends against silent DB corruption.
  scan_results_hash TEXT NOT NULL CHECK (scan_results_hash ~ '^[a-f0-9]{64}$'),
  -- Forensics-only attribution. NEVER read by user-facing code paths. Recovery
  -- of pull-string for debugging happens via extraction_logs WHERE
  -- organization_id = ? joined by digest at debug time.
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
-- violates 23514.
-- ============================================================
ALTER TABLE project_container_findings DROP CONSTRAINT IF EXISTS project_container_findings_image_source_check;
ALTER TABLE project_container_findings ADD CONSTRAINT project_container_findings_image_source_check
  CHECK (image_source IN ('dockerfile_base', 'configured_image'));

COMMIT;
