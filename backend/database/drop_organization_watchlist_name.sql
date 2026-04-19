-- Remove name from organization_watchlist; display name comes from JOIN dependencies.
-- Run after add_dependency_id_to_organization_watchlist.sql (dependency_id already backfilled).

DROP INDEX IF EXISTS idx_organization_watchlist_name;
DROP INDEX IF EXISTS idx_organization_watchlist_org_name;

ALTER TABLE organization_watchlist
  DROP COLUMN IF EXISTS name;
