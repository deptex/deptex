-- Project dependencies extracted from manifests/lockfiles
CREATE TABLE IF NOT EXISTS project_dependencies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  license TEXT,
  is_direct BOOLEAN NOT NULL DEFAULT false,
  source TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, name, version, is_direct, source)
);

ALTER TABLE project_dependencies ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_project_dependencies_project_id
  ON project_dependencies(project_id);

CREATE INDEX IF NOT EXISTS idx_project_dependencies_name
  ON project_dependencies(name);

