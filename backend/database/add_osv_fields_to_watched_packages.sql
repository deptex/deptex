-- Add OSV vulnerability checking fields to watched_packages table
-- Used by the watchtower-poller to track npm versions and OSV checks

-- Add last_npm_version to track the latest version from npm registry
ALTER TABLE watched_packages 
ADD COLUMN IF NOT EXISTS last_npm_version TEXT;

-- Add last_osv_check_at to track when we last checked OSV for vulnerabilities
ALTER TABLE watched_packages 
ADD COLUMN IF NOT EXISTS last_osv_check_at TIMESTAMP WITH TIME ZONE;

-- Comment explaining the fields
COMMENT ON COLUMN watched_packages.last_npm_version IS 'The latest version from npm registry at last poll. Used to detect new releases.';
COMMENT ON COLUMN watched_packages.last_osv_check_at IS 'When we last checked OSV for vulnerabilities for this package.';
