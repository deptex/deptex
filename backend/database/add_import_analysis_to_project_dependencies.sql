-- Add import analysis columns and tables for AST parsing results
-- This tracks which functions are imported from each package and how many files import each package

-- Add files_importing_count column to project_dependencies
ALTER TABLE project_dependencies
ADD COLUMN IF NOT EXISTS files_importing_count INTEGER DEFAULT 0;

-- Create table to store imported functions per project dependency
CREATE TABLE IF NOT EXISTS project_dependency_functions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE CASCADE,
  function_name TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_dependency_id, function_name)
);

-- Enable RLS on new table
ALTER TABLE project_dependency_functions ENABLE ROW LEVEL SECURITY;

-- RLS policy: users can view functions for dependencies in projects they have access to
CREATE POLICY "Users can view dependency functions for accessible projects"
  ON project_dependency_functions
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM project_dependencies pd
      JOIN projects p ON p.id = pd.project_id
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE pd.id = project_dependency_functions.project_dependency_id
      AND om.user_id = auth.uid()
    )
  );

-- Indexes for efficient queries
CREATE INDEX IF NOT EXISTS idx_project_dependency_functions_project_dependency_id
  ON project_dependency_functions(project_dependency_id);

CREATE INDEX IF NOT EXISTS idx_project_dependency_functions_function_name
  ON project_dependency_functions(function_name);
