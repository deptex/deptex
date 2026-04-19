-- DEPRECATED: Replaced by dependency_prs (see dependency_prs_schema.sql).
-- Track bump/decrease PRs per project + package name + target version.
-- Prevents duplicate PRs; used to show "View PR" and to close superseded open PRs.
-- Uses (project_id, name) so we track by package name, not project_dependencies.id (which is version-specific).

CREATE TABLE IF NOT EXISTS watchtower_prs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('bump', 'decrease')),
  target_version TEXT NOT NULL,
  pr_url TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  branch_name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, name, type, target_version)
);

CREATE INDEX IF NOT EXISTS idx_watchtower_prs_project_name_type
  ON watchtower_prs(project_id, name, type);

COMMENT ON TABLE watchtower_prs IS 'PRs created by Watchtower bump/decrease; one row per (project, package name, type, target_version).';
