-- Project repositories (connected repo per project)
CREATE TABLE IF NOT EXISTS project_repositories (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  installation_id TEXT NOT NULL,
  repo_id BIGINT NOT NULL,
  repo_full_name TEXT NOT NULL,
  default_branch TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id)
);

ALTER TABLE project_repositories ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_project_repositories_project_id
  ON project_repositories(project_id);

CREATE INDEX IF NOT EXISTS idx_project_repositories_repo_id
  ON project_repositories(repo_id);

