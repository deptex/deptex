-- Add is_watching column to project_dependencies for Watchtower feature
-- When true, enables forensic analysis on this package for the project
ALTER TABLE project_dependencies
ADD COLUMN IF NOT EXISTS is_watching BOOLEAN DEFAULT false;

-- Index for quick lookup of watched packages
CREATE INDEX IF NOT EXISTS idx_project_dependencies_is_watching
  ON project_dependencies(is_watching)
  WHERE is_watching = true;
