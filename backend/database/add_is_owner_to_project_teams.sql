-- Migration: Add is_owner column to project_teams table
-- This distinguishes between owner teams (who manage the project) and contributing teams (who have access but cannot manage)

-- Add is_owner column to project_teams
ALTER TABLE project_teams ADD COLUMN IF NOT EXISTS is_owner BOOLEAN DEFAULT FALSE;

-- Create index for faster queries filtering by is_owner
CREATE INDEX IF NOT EXISTS idx_project_teams_is_owner ON project_teams(project_id, is_owner);

-- Update existing records: set the first team for each project as the owner
-- This ensures backward compatibility with existing data
WITH first_teams AS (
  SELECT DISTINCT ON (project_id) id
  FROM project_teams
  ORDER BY project_id, created_at ASC
)
UPDATE project_teams
SET is_owner = TRUE
WHERE id IN (SELECT id FROM first_teams);

-- Add a constraint to ensure only one owner team per project
-- Note: This is a partial unique index that only applies when is_owner = true
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_teams_single_owner 
ON project_teams(project_id) 
WHERE is_owner = TRUE;
