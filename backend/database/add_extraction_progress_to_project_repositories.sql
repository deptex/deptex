-- Add extraction step and error tracking for async extraction worker.
-- extraction_step: queued | cloning | sbom | deps_synced | scanning | uploading | completed
-- status values: initializing (job queued), extracting (worker running), analyzing, finalizing, ready, error

ALTER TABLE project_repositories
  ADD COLUMN IF NOT EXISTS extraction_step TEXT,
  ADD COLUMN IF NOT EXISTS extraction_error TEXT;

COMMENT ON COLUMN project_repositories.extraction_step IS 'Current extraction step: queued, cloning, sbom, deps_synced, scanning, uploading, completed';
COMMENT ON COLUMN project_repositories.extraction_error IS 'Error message from extraction worker when status is error';
