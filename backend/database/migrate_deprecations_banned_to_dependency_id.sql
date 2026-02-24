-- Switch team_deprecations, team_banned_versions, organization_deprecations, banned_versions
-- from dependency_name to dependency_id. No backfill: existing rows are removed.

-- ========== team_deprecations ==========
ALTER TABLE team_deprecations
  ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

ALTER TABLE team_deprecations DROP COLUMN IF EXISTS dependency_name;

DELETE FROM team_deprecations WHERE dependency_id IS NULL;

ALTER TABLE team_deprecations
  ALTER COLUMN dependency_id SET NOT NULL;

ALTER TABLE team_deprecations
  DROP CONSTRAINT IF EXISTS team_deprecations_team_id_dependency_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS team_deprecations_team_id_dependency_id_key
  ON team_deprecations(team_id, dependency_id);

DROP INDEX IF EXISTS idx_team_deprecations_team_name;

CREATE INDEX IF NOT EXISTS idx_team_deprecations_team_dependency_id
  ON team_deprecations(team_id, dependency_id);

-- ========== team_banned_versions ==========
ALTER TABLE team_banned_versions
  ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

ALTER TABLE team_banned_versions DROP COLUMN IF EXISTS dependency_name;

DELETE FROM team_banned_versions WHERE dependency_id IS NULL;

ALTER TABLE team_banned_versions
  ALTER COLUMN dependency_id SET NOT NULL;

ALTER TABLE team_banned_versions
  DROP CONSTRAINT IF EXISTS team_banned_versions_team_id_dependency_name_banned_version_key;

CREATE UNIQUE INDEX IF NOT EXISTS team_banned_versions_team_id_dependency_id_banned_version_key
  ON team_banned_versions(team_id, dependency_id, banned_version);

DROP INDEX IF EXISTS idx_team_banned_versions_team_dep;

CREATE INDEX IF NOT EXISTS idx_team_banned_versions_team_dependency_id
  ON team_banned_versions(team_id, dependency_id);

-- ========== organization_deprecations ==========
ALTER TABLE organization_deprecations
  ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

ALTER TABLE organization_deprecations DROP COLUMN IF EXISTS dependency_name;

DELETE FROM organization_deprecations WHERE dependency_id IS NULL;

ALTER TABLE organization_deprecations
  ALTER COLUMN dependency_id SET NOT NULL;

ALTER TABLE organization_deprecations
  DROP CONSTRAINT IF EXISTS organization_deprecations_organization_id_dependency_name_key;

CREATE UNIQUE INDEX IF NOT EXISTS organization_deprecations_organization_id_dependency_id_key
  ON organization_deprecations(organization_id, dependency_id);

DROP INDEX IF EXISTS idx_organization_deprecations_org_name;

CREATE INDEX IF NOT EXISTS idx_organization_deprecations_org_dependency_id
  ON organization_deprecations(organization_id, dependency_id);

-- ========== banned_versions ==========
ALTER TABLE banned_versions
  ADD COLUMN IF NOT EXISTS dependency_id UUID REFERENCES dependencies(id) ON DELETE CASCADE;

ALTER TABLE banned_versions DROP COLUMN IF EXISTS dependency_name;

DELETE FROM banned_versions WHERE dependency_id IS NULL;

ALTER TABLE banned_versions
  ALTER COLUMN dependency_id SET NOT NULL;

ALTER TABLE banned_versions
  DROP CONSTRAINT IF EXISTS banned_versions_organization_id_dependency_name_banned_version_key;

CREATE UNIQUE INDEX IF NOT EXISTS banned_versions_organization_id_dependency_id_banned_version_key
  ON banned_versions(organization_id, dependency_id, banned_version);

DROP INDEX IF EXISTS idx_banned_versions_org_dep;

CREATE INDEX IF NOT EXISTS idx_banned_versions_org_dependency_id
  ON banned_versions(organization_id, dependency_id);
