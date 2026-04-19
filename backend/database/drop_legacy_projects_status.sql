-- Drop legacy projects.status column (Phase 4 replaced it with projects.status_id FK)
-- This column was originally a free-form text like 'compliant' and is now deprecated.

ALTER TABLE projects
  DROP COLUMN IF EXISTS status;

