-- Add UNIQUE constraint to github_installation_id on organizations table
-- Enforces strict "One-to-One" rule: A GitHub Installation ID can only belong to ONE Deptex Organization

-- First, check if there are any duplicates and handle them (keep the most recent)
-- This is a safety check before adding the constraint
DO $$
DECLARE
  duplicate_record RECORD;
BEGIN
  -- Find and nullify older duplicates (keep the most recently updated one)
  FOR duplicate_record IN
    SELECT github_installation_id, id, updated_at,
           ROW_NUMBER() OVER (PARTITION BY github_installation_id ORDER BY updated_at DESC) as rn
    FROM organizations
    WHERE github_installation_id IS NOT NULL
  LOOP
    IF duplicate_record.rn > 1 THEN
      UPDATE organizations 
      SET github_installation_id = NULL, updated_at = NOW()
      WHERE id = duplicate_record.id;
      RAISE NOTICE 'Cleared duplicate github_installation_id from organization %', duplicate_record.id;
    END IF;
  END LOOP;
END $$;

-- Drop the old index if it exists (we'll create a unique one)
DROP INDEX IF EXISTS idx_organizations_github_installation_id;

-- Add the unique constraint
-- Using a partial unique index to allow multiple NULLs (organizations without GitHub)
CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_github_installation_id_unique
  ON organizations(github_installation_id)
  WHERE github_installation_id IS NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN organizations.github_installation_id IS 
  'GitHub App installation ID for this organization. UNIQUE - can only belong to one organization.';
