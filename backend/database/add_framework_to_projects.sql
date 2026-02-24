-- Add framework column to projects table
ALTER TABLE projects ADD COLUMN IF NOT EXISTS framework TEXT;

-- Create index for framework queries
CREATE INDEX IF NOT EXISTS idx_projects_framework ON projects(framework);
