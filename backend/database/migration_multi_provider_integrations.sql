-- Migration: support multiple connections per provider per organization
-- Drops the old UNIQUE(organization_id, provider) and adds display_name

-- 1. Add display_name column
ALTER TABLE organization_integrations
  ADD COLUMN IF NOT EXISTS display_name TEXT;

-- 2. Drop the old unique constraint that only allows one connection per provider
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'organization_integrations_organization_id_provider_key'
  ) THEN
    ALTER TABLE organization_integrations
      DROP CONSTRAINT organization_integrations_organization_id_provider_key;
  END IF;
END $$;

-- 3. Add a new unique constraint: same installation can't be added twice for same org+provider
CREATE UNIQUE INDEX IF NOT EXISTS idx_org_integrations_org_provider_installation
  ON organization_integrations(organization_id, provider, installation_id)
  WHERE installation_id IS NOT NULL;

-- 4. Backfill display_name from metadata for existing rows
UPDATE organization_integrations
SET display_name = COALESCE(
  metadata->>'account_login',
  metadata->>'name',
  metadata->>'username',
  provider
)
WHERE display_name IS NULL;
