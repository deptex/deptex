-- Per-org "latest allowed version" for Watchtower status (outdated = behind this; decrease = above this).

ALTER TABLE organization_watchlist
ADD COLUMN IF NOT EXISTS latest_allowed_version TEXT;

COMMENT ON COLUMN organization_watchlist.latest_allowed_version IS 'Latest version this organization allows for this package. Outdated = project version < this; decrease = project version > this. Set when org adds package to watchlist (to current project version).';
