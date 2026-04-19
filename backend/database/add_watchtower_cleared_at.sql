-- Add watchtower_cleared_at column to project_dependencies
-- Tracks when commits were last cleared for this dependency's watchtower view
-- Commits older than this timestamp will be hidden from the watchtower display

ALTER TABLE project_dependencies
ADD COLUMN IF NOT EXISTS watchtower_cleared_at TIMESTAMP WITH TIME ZONE;

COMMENT ON COLUMN project_dependencies.watchtower_cleared_at IS 
  'Timestamp when commits were last cleared. Commits before this time are hidden in watchtower.';
