-- Team-level dependency deprecation rules.
-- Allows teams to mark a dependency as deprecated with a recommended alternative.
-- Org-level deprecations (organization_deprecations) take precedence; team deprecations apply only to that team's projects.

CREATE TABLE IF NOT EXISTS team_deprecations (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  recommended_alternative TEXT NOT NULL,
  deprecated_by UUID REFERENCES auth.users(id),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(team_id, dependency_id)
);

CREATE INDEX IF NOT EXISTS idx_team_deprecations_team_dependency_id
  ON team_deprecations(team_id, dependency_id);

COMMENT ON TABLE team_deprecations IS 'Per-team deprecated dependencies with recommended alternatives. Org manage can undeprecate these; team manage_projects can deprecate/undeprecate for their team.';
