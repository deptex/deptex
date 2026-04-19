-- Backfill last_extracted_at for existing projects that have completed extractions.
-- The column was added in phase8_migrations.sql but was never written to until the
-- workers.ts fix that sets it on extraction completion.
UPDATE project_repositories pr
SET last_extracted_at = ej.completed_at
FROM (
  SELECT DISTINCT ON (project_id) project_id, completed_at
  FROM extraction_jobs
  WHERE status = 'completed' AND completed_at IS NOT NULL
  ORDER BY project_id, completed_at DESC
) ej
WHERE pr.project_id = ej.project_id
  AND pr.last_extracted_at IS NULL;
