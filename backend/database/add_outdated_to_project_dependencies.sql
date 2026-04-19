-- Phase 3A.3: Track outdated dependencies
ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS is_outdated BOOLEAN DEFAULT false;

ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS versions_behind INTEGER DEFAULT 0;
