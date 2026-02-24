-- Organization-level dependency deprecation rules
-- Allows orgs to mark a dependency as deprecated with a recommended alternative

CREATE TABLE IF NOT EXISTS organization_deprecations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  recommended_alternative TEXT NOT NULL,
  deprecated_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(organization_id, dependency_id)
);

CREATE INDEX IF NOT EXISTS idx_organization_deprecations_org_dependency_id
  ON organization_deprecations(organization_id, dependency_id);

COMMENT ON TABLE organization_deprecations IS 'Per-organization list of deprecated dependencies with recommended alternatives.';
