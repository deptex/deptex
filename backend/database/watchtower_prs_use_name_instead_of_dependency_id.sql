-- Migrate watchtower_prs from dependency_id to name (package name).
-- Run this only if you already have watchtower_prs with dependency_id.
-- New installs use watchtower_prs_schema.sql which has name from the start.

ALTER TABLE watchtower_prs ADD COLUMN IF NOT EXISTS name TEXT;

UPDATE watchtower_prs wp
SET name = pd.name
FROM project_dependencies pd
WHERE wp.dependency_id = pd.id AND wp.name IS NULL;

-- Remove rows that could not be backfilled (orphaned dependency_id)
DELETE FROM watchtower_prs WHERE name IS NULL;

-- De-duplicate: keep one row per (project_id, name, type, target_version), delete the rest
DELETE FROM watchtower_prs a
USING watchtower_prs b
WHERE a.id > b.id
  AND a.project_id = b.project_id
  AND a.name = b.name
  AND a.type = b.type
  AND a.target_version = b.target_version;

-- Drop old unique constraint and column (only if dependency_id exists)
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'watchtower_prs' AND column_name = 'dependency_id'
  ) THEN
    ALTER TABLE watchtower_prs DROP CONSTRAINT IF EXISTS watchtower_prs_project_id_dependency_id_type_target_version_key;
    ALTER TABLE watchtower_prs DROP COLUMN dependency_id;
  END IF;
END $$;

ALTER TABLE watchtower_prs ALTER COLUMN name SET NOT NULL;

ALTER TABLE watchtower_prs ADD CONSTRAINT watchtower_prs_project_id_name_type_target_version_key
  UNIQUE (project_id, name, type, target_version);

DROP INDEX IF EXISTS idx_watchtower_prs_project_dependency_type;
CREATE INDEX IF NOT EXISTS idx_watchtower_prs_project_name_type
  ON watchtower_prs(project_id, name, type);

COMMENT ON TABLE watchtower_prs IS 'PRs created by Watchtower bump/decrease; one row per (project, package name, type, target_version).';
