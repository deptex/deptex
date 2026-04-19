-- Dependency relationships table - stores parent-child dependency relationships per project
-- This enables tracking which dependencies depend on which other dependencies

CREATE TABLE IF NOT EXISTS dependency_relationships (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  parent_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE CASCADE,
  child_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, parent_dependency_id, child_dependency_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_dep_rel_project ON dependency_relationships(project_id);
CREATE INDEX IF NOT EXISTS idx_dep_rel_parent ON dependency_relationships(parent_dependency_id);
CREATE INDEX IF NOT EXISTS idx_dep_rel_child ON dependency_relationships(child_dependency_id);

-- Enable RLS
ALTER TABLE dependency_relationships ENABLE ROW LEVEL SECURITY;

-- RLS policies - users can view relationships for projects they have access to
CREATE POLICY "Users can view dependency relationships for accessible projects"
  ON dependency_relationships
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE p.id = dependency_relationships.project_id
      AND om.user_id = auth.uid()
    )
  );
