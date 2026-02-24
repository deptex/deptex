-- Remove watchtower columns from project_dependencies (run after code uses organization_watchlist)

DROP INDEX IF EXISTS idx_project_dependencies_is_watching;

ALTER TABLE project_dependencies
  DROP COLUMN IF EXISTS is_watching,
  DROP COLUMN IF EXISTS watchtower_cleared_at;
