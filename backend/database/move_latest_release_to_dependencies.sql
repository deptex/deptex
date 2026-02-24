-- Move latest release version and date from watched_packages to dependencies.
-- Dependencies has (name, version) UNIQUE; we denormalize so all rows with the same name get the same latest_version/latest_release_date.

-- 1. Add columns to dependencies
ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS latest_version TEXT;

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS latest_release_date TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN dependencies.latest_version IS 'Latest version from npm registry (dist-tags.latest). Set when enabling watch and can be updated by poller.';
COMMENT ON COLUMN dependencies.latest_release_date IS 'Release date of latest_version from npm (time[version]). Used for quarantine X days display.';

-- 2. Backfill from watched_packages: for each wp row with dependency_id, propagate latest_* to all dependencies rows with that name
UPDATE dependencies d
SET
  latest_version = sub.latest_version,
  latest_release_date = sub.latest_release_date
FROM (
  SELECT dep.name, wp.latest_version, wp.latest_release_date
  FROM watched_packages wp
  JOIN dependencies dep ON dep.id = wp.dependency_id
  WHERE wp.latest_version IS NOT NULL OR wp.latest_release_date IS NOT NULL
) sub
WHERE d.name = sub.name;

-- 3. Drop columns from watched_packages
ALTER TABLE watched_packages DROP COLUMN IF EXISTS latest_version;
ALTER TABLE watched_packages DROP COLUMN IF EXISTS latest_release_date;
