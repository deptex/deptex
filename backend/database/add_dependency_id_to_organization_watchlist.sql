-- Migrate organization_watchlist from name to dependency_id.
-- Backfill dependency_id from dependencies by matching name (one row per package name).
-- Keeps name for display; unique is (organization_id, dependency_id).

-- 1. Add column (nullable first for backfill)
ALTER TABLE organization_watchlist
ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

-- 2. Backfill from dependencies by name (pick one dependency per name if multiple exist)
UPDATE organization_watchlist ow
SET dependency_id = d.id
FROM (
  SELECT DISTINCT ON (name) id, name
  FROM dependencies
  ORDER BY name, updated_at DESC NULLS LAST
) d
WHERE d.name = ow.name AND ow.dependency_id IS NULL;

-- 3. Drop old unique constraint on (organization_id, name) so we can add (organization_id, dependency_id)
ALTER TABLE organization_watchlist
DROP CONSTRAINT IF EXISTS organization_watchlist_organization_id_name_key;

-- 4. Add unique on (organization_id, dependency_id); skip rows that didn't backfill (orphaned name)
DELETE FROM organization_watchlist WHERE dependency_id IS NULL;

ALTER TABLE organization_watchlist
ALTER COLUMN dependency_id SET NOT NULL;

ALTER TABLE organization_watchlist
ADD CONSTRAINT organization_watchlist_organization_id_dependency_id_key UNIQUE (organization_id, dependency_id);

-- 5. Index for lookups by dependency_id
CREATE INDEX IF NOT EXISTS idx_organization_watchlist_organization_id_dependency_id
  ON organization_watchlist(organization_id, dependency_id);

CREATE INDEX IF NOT EXISTS idx_organization_watchlist_dependency_id
  ON organization_watchlist(dependency_id);

COMMENT ON COLUMN organization_watchlist.dependency_id IS 'References dependencies(id). Replaces name as the canonical link to the package.';
