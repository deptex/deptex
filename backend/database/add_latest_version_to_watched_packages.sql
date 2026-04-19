-- Restore latest release version and date on watched_packages (may have been dropped by refactor_watchtower_schema).
-- Used when creating a watched package (npm API) and for "new version in quarantine for X days" in the UI.

ALTER TABLE watched_packages
ADD COLUMN IF NOT EXISTS latest_version TEXT;

ALTER TABLE watched_packages
ADD COLUMN IF NOT EXISTS latest_release_date TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN watched_packages.latest_version IS 'Latest version from npm registry (dist-tags.latest). Set on create and updated by poller.';
COMMENT ON COLUMN watched_packages.latest_release_date IS 'Release date of latest_version from npm (time[version]). Used for quarantine X days display.';
