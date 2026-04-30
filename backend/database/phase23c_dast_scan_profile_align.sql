-- Align scan_jobs.scan_profile vocabulary with the runner + route + UI.
--
-- Phase 23 (phase23_dast_consolidation.sql) defined the constraint as
-- ('baseline', 'full', 'api'), but the runner (depscanner/src/dast/runner.ts:
-- DastScanProfile = 'auto' | 'quick' | 'full' | 'api'), the route
-- (backend/src/routes/dast.ts), and project_dast_config's own scan_profile
-- check constraint all use ('auto', 'quick', 'full', 'api'). The mismatch
-- meant any DAST scan triggered with the default 'auto' or 'quick' profile
-- would fail at INSERT time inside queue_scan_job with
-- "violates check constraint scan_jobs_scan_profile_check".
--
-- Discovered via end-to-end test against PGLite + the live RPC, 2026-04-30.
-- Translation between user-facing profile and internal ZAP script name
-- ('quick' -> baseline.py, 'auto' + routes -> api-scan.py) happens at runtime
-- inside runner.ts:selectScript() — the DB stores the user-facing label.

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_scan_profile_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_scan_profile_check
  CHECK (
    scan_profile IS NULL
    OR scan_profile IN ('auto', 'quick', 'full', 'api')
  );
