-- Per-org quarantine flags for Watchtower status card.
-- quarantine_next_release: user chose to quarantine the next release (toggle via UI).
-- is_current_version_quarantined: current installed version is in quarantine (default false).

ALTER TABLE organization_watchlist
ADD COLUMN IF NOT EXISTS quarantine_next_release BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE organization_watchlist
ADD COLUMN IF NOT EXISTS is_current_version_quarantined BOOLEAN NOT NULL DEFAULT false;

COMMENT ON COLUMN organization_watchlist.quarantine_next_release IS 'When true, next release is in quarantine (1 week) for this org. Toggled by Quarantine next version button.';
COMMENT ON COLUMN organization_watchlist.is_current_version_quarantined IS 'When true, the current installed version is quarantined; user should decrease version.';
