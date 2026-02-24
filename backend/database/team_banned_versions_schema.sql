-- Team-level banned dependency versions.
-- When a version is banned at team level, PRs are created for projects in that team
-- that are on the banned version, to bump them to the target version.
-- Org-level bans (banned_versions) take precedence; team bans apply only to that team's projects.

CREATE TABLE IF NOT EXISTS team_banned_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  banned_version TEXT NOT NULL,
  bump_to_version TEXT NOT NULL,
  banned_by UUID NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(team_id, dependency_id, banned_version)
);

CREATE INDEX IF NOT EXISTS idx_team_banned_versions_team_dependency_id
  ON team_banned_versions(team_id, dependency_id);

COMMENT ON TABLE team_banned_versions IS 'Per-team banned dependency versions. Org manage can unban these; team manage_projects can ban/unban for their team.';
