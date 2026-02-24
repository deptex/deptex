-- AI Usage Analysis: add columns to project_dependencies for storing AI-generated usage summaries,
-- and create a table for storing which files import each dependency (populated by parser-worker).

-- Add AI usage analysis columns to project_dependencies
ALTER TABLE project_dependencies
ADD COLUMN IF NOT EXISTS ai_usage_summary TEXT,
ADD COLUMN IF NOT EXISTS ai_usage_analyzed_at TIMESTAMPTZ;

-- Create table to store file paths that import each dependency
-- Populated by the parser-worker during AST analysis
CREATE TABLE IF NOT EXISTS project_dependency_files (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_dependency_id UUID REFERENCES project_dependencies(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_dependency_id, file_path)
);

-- Enable RLS on new table
ALTER TABLE project_dependency_files ENABLE ROW LEVEL SECURITY;

-- RLS policy: org members can view file paths for dependencies in their projects
CREATE POLICY "Users can view dependency files for accessible projects"
  ON project_dependency_files
  FOR SELECT
  USING (
    EXISTS (
      SELECT 1 FROM project_dependencies pd
      JOIN projects p ON p.id = pd.project_id
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE pd.id = project_dependency_files.project_dependency_id
      AND om.user_id = auth.uid()
    )
  );

-- Index for efficient lookups by project_dependency_id
CREATE INDEX IF NOT EXISTS idx_project_dependency_files_project_dependency_id
  ON project_dependency_files(project_dependency_id);
