-- Remove version column from watched_packages table
-- Watchtower tracks packages by name only, not by specific version

-- Drop the old unique constraint on (name, version)
ALTER TABLE watched_packages DROP CONSTRAINT IF EXISTS watched_packages_name_version_key;

-- Drop the version column
ALTER TABLE watched_packages DROP COLUMN IF EXISTS version;

-- Add unique constraint on name only (if not already exists)
ALTER TABLE watched_packages ADD CONSTRAINT watched_packages_name_key UNIQUE (name);

-- Drop the old name_version index if it exists
DROP INDEX IF EXISTS idx_watched_packages_name_version;

-- Rename release_date to latest_release_date if it exists
ALTER TABLE watched_packages RENAME COLUMN release_date TO latest_release_date;

-- Add latest_version column if it doesn't exist
ALTER TABLE watched_packages ADD COLUMN IF NOT EXISTS latest_version TEXT;
