-- Migration: add provider and integration_id to project_repositories

-- 1. Add provider column (defaults to 'github' for existing rows)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'project_repositories'
      AND column_name = 'provider'
  ) THEN
    ALTER TABLE project_repositories
      ADD COLUMN provider TEXT NOT NULL DEFAULT 'github';
  END IF;
END $$;

-- 2. Add integration_id column referencing organization_integrations
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'project_repositories'
      AND column_name = 'integration_id'
  ) THEN
    ALTER TABLE project_repositories
      ADD COLUMN integration_id UUID REFERENCES organization_integrations(id) ON DELETE SET NULL;
  END IF;
END $$;

-- 3. Index for lookups by integration
CREATE INDEX IF NOT EXISTS idx_project_repositories_integration_id
  ON project_repositories(integration_id);

-- 4. Backfill integration_id for existing GitHub rows where possible
UPDATE project_repositories pr
SET integration_id = oi.id
FROM organization_integrations oi
JOIN projects p ON p.organization_id = oi.organization_id
WHERE pr.project_id = p.id
  AND oi.provider = 'github'
  AND pr.integration_id IS NULL
  AND pr.provider = 'github';
