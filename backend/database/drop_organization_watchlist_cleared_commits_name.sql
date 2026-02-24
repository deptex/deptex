-- Switch organization_watchlist_cleared_commits from name to dependency_id. No backfill.

ALTER TABLE organization_watchlist_cleared_commits
  ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

-- Drop old unique/index that use name before dropping the column
ALTER TABLE organization_watchlist_cleared_commits
  DROP CONSTRAINT IF EXISTS organization_watchlist_cleared_commits_organization_id_name_commit_sha_key;

DROP INDEX IF EXISTS idx_organization_watchlist_cleared_commits_org_name;

ALTER TABLE organization_watchlist_cleared_commits DROP COLUMN IF EXISTS name;

DELETE FROM organization_watchlist_cleared_commits WHERE dependency_id IS NULL;

ALTER TABLE organization_watchlist_cleared_commits
  ALTER COLUMN dependency_id SET NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS organization_watchlist_cleared_commits_org_dependency_id_commit_sha_key
  ON organization_watchlist_cleared_commits(organization_id, dependency_id, commit_sha);

CREATE INDEX IF NOT EXISTS idx_organization_watchlist_cleared_commits_org_dependency_id
  ON organization_watchlist_cleared_commits(organization_id, dependency_id);
