-- Phase 50: capture the handler's source snippet so a DAST finding can show the
-- receiving code (like reachability flows show entry/source/sink code), not just
-- a file:line. The snippet is captured at extraction time onto the entry point
-- (the DAST worker has no repo on disk) and copied onto the finding at
-- cross-link time.
ALTER TABLE project_entry_points ADD COLUMN IF NOT EXISTS code_snippet TEXT;
ALTER TABLE project_dast_findings ADD COLUMN IF NOT EXISTS handler_code_snippet TEXT;
