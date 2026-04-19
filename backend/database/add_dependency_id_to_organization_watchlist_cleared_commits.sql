-- Add dependency_id to organization_watchlist_cleared_commits for consistency with organization_watchlist.
-- Backfill from dependencies by name. Keep name for backward compatibility until code uses dependency_id.

ALTER TABLE organization_watchlist_cleared_commits
ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

UPDATE organization_watchlist_cleared_commits owc
SET dependency_id = d.id
FROM (
  SELECT DISTINCT ON (name) id, name
  FROM dependencies
  ORDER BY name, updated_at DESC NULLS LAST
) d
WHERE d.name = owc.name AND owc.dependency_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_organization_watchlist_cleared_commits_dependency_id
  ON organization_watchlist_cleared_commits(organization_id, dependency_id)
  WHERE dependency_id IS NOT NULL;

COMMENT ON COLUMN organization_watchlist_cleared_commits.dependency_id IS 'References dependencies(id). Optional; name still used for lookups until code migrates.';
