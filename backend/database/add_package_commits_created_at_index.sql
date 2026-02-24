-- Index for "since last clear" query: filter by watched_package_id and created_at
CREATE INDEX IF NOT EXISTS idx_package_commits_watched_package_created_at
  ON package_commits(watched_package_id, created_at DESC);

COMMENT ON INDEX idx_package_commits_watched_package_created_at IS
  'Supports org Watchtower commit list filtered by created_at (commits added since last clear).';
