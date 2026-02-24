-- When quarantine_next_release is true, optionally store when the quarantine period ends
-- (e.g. 7 days after the new version was released). Used for "new version in quarantine until X" display.

ALTER TABLE organization_watchlist
ADD COLUMN IF NOT EXISTS quarantine_until TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN organization_watchlist.quarantine_until IS 'When the current next-release quarantine period ends (e.g. latest_release_date + 7 days). Null if quarantine_next_release is false or not yet set.';
