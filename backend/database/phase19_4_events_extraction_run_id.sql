-- Phase 19.4: project_vulnerability_events extraction_run_id + partial unique constraint
--
-- Prevents duplicate events on extraction retry. On a partial retry of finalize_extraction
-- (e.g. network blip between the event INSERT and the visibility-flip UPDATE), the next
-- attempt will re-run the trigger_calc / classify-unmatched CTEs and try to re-emit the
-- same (detected / reopened / rereview_triggered) events for the same extraction_run_id.
--
-- The partial unique index (extraction_run_id IS NOT NULL) lets extraction-driven events
-- dedup cleanly via ON CONFLICT DO NOTHING, while user-action events (suppressed,
-- accepted, unsuppressed — extraction_run_id IS NULL) are unaffected and can repeat
-- freely across suppress → unsuppress → suppress cycles.

ALTER TABLE project_vulnerability_events
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_pve_unique_per_run
  ON project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id)
  WHERE extraction_run_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pve_extraction_run_id
  ON project_vulnerability_events (extraction_run_id)
  WHERE extraction_run_id IS NOT NULL;
