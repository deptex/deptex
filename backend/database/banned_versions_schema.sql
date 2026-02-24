-- Organization-level banned versions for supply chain management.
-- When a version is banned, PRs are created across all org projects currently on that version
-- to bump them to the specified target version.

CREATE TABLE IF NOT EXISTS banned_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  banned_version TEXT NOT NULL,
  bump_to_version TEXT NOT NULL,
  banned_by UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(organization_id, dependency_id, banned_version)
);

CREATE INDEX IF NOT EXISTS idx_banned_versions_org_dependency_id
  ON banned_versions(organization_id, dependency_id);

COMMENT ON TABLE banned_versions IS 'Per-organization banned dependency versions. Banning a version triggers PRs to bump all affected projects to the target version.';
COMMENT ON COLUMN banned_versions.banned_version IS 'The specific version that is banned.';
COMMENT ON COLUMN banned_versions.bump_to_version IS 'The version that projects should be bumped to.';
COMMENT ON COLUMN banned_versions.banned_by IS 'The user who banned this version.';
