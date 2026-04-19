-- Data migration: copy is_watching + watchtower_cleared_at from project_dependencies
-- into organization_watchlist (one row per org per package name).
-- Run after organization_watchlist_schema.sql and before dropping columns.

INSERT INTO organization_watchlist (organization_id, name, watchtower_cleared_at, created_at)
SELECT DISTINCT ON (p.organization_id, pd.name)
  p.organization_id,
  pd.name,
  pd.watchtower_cleared_at,
  COALESCE(pd.watchtower_cleared_at, pd.created_at, NOW())
FROM project_dependencies pd
JOIN projects p ON p.id = pd.project_id
WHERE pd.is_watching = true
ORDER BY p.organization_id, pd.name, pd.watchtower_cleared_at DESC NULLS LAST
ON CONFLICT (organization_id, name) DO UPDATE SET
  watchtower_cleared_at = COALESCE(EXCLUDED.watchtower_cleared_at, organization_watchlist.watchtower_cleared_at);
