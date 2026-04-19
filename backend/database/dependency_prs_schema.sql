-- Track bump/decrease/remove PRs per project + dependency (by id) + target version.
-- Replaces watchtower_prs; keyed by dependency_id so name is always resolved from dependencies.name.
-- Prevents duplicate PRs; used to show "View PR" and to close superseded open PRs.

CREATE TABLE IF NOT EXISTS dependency_prs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('bump', 'decrease', 'remove')),
  target_version TEXT NOT NULL,
  pr_url TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  branch_name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, dependency_id, type, target_version)
);

CREATE INDEX IF NOT EXISTS idx_dependency_prs_project_dependency_type
  ON dependency_prs(project_id, dependency_id, type);

COMMENT ON TABLE dependency_prs IS 'PRs created by Watchtower bump/decrease/remove; one row per (project, dependency_id, type, target_version). Name comes from dependencies.name.';
