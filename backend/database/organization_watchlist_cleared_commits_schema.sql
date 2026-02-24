-- Per-organization per-package individually cleared (acknowledged) commits.
-- Used to hide specific commits from the Watchtower list without clearing all history.

CREATE TABLE IF NOT EXISTS organization_watchlist_cleared_commits (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  commit_sha TEXT NOT NULL,
  cleared_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(organization_id, name, commit_sha)
);

CREATE INDEX IF NOT EXISTS idx_organization_watchlist_cleared_commits_org_name
  ON organization_watchlist_cleared_commits(organization_id, name);

COMMENT ON TABLE organization_watchlist_cleared_commits IS
  'Commits individually acknowledged/cleared per org+package; excluded from Watchtower commit list.';
