-- Phase 23: DAST consolidation — rename extraction_jobs → scan_jobs + type discriminator.
--
-- Rationale: DAST (and future malicious-pkg, IaC, container scans) share the same job-claim
-- semantics as extraction (claim, heartbeat, recover, fail, machine-bound). Rather than
-- spawning a sibling table per scanner type, we widen extraction_jobs into a discriminated
-- union keyed on `type`. Worker dispatch reads `type` and runs the matching pipeline.
-- Aider/fix-worker stays in its own table because its runtime shape (Python + git PRs) is
-- different.
--
-- This migration is destructive in the sense that it RENAMES a table. After applying:
--   - Backend code that writes/reads `extraction_jobs` MUST be redeployed at the same time.
--   - Worker code that calls `claim_extraction_job` MUST be redeployed at the same time.
-- Existing data is preserved (rename keeps rows + FKs + RLS).
--
-- v1 type values: ('extraction', 'dast'). Phase 2+ will extend the CHECK constraint with
-- ('malicious_pkg', 'iac', 'container') as one-line edits.
--
-- See `.cursor/plans/dast.plan.md` v3 for the full DAST architecture.

-- =============================================================================
-- 1. Rename the table.
--    Postgres auto-renames RLS policies, primary key, and inbound FKs.
--    Indexes keep their original names (cosmetic) — we rename for clarity.
-- =============================================================================
ALTER TABLE extraction_jobs RENAME TO scan_jobs;

ALTER INDEX IF EXISTS idx_extraction_jobs_status_created RENAME TO idx_scan_jobs_status_created;
ALTER INDEX IF EXISTS idx_extraction_jobs_project        RENAME TO idx_scan_jobs_project;
ALTER INDEX IF EXISTS idx_extraction_jobs_org            RENAME TO idx_scan_jobs_org;

-- =============================================================================
-- 2. Add the type discriminator. Existing rows are extraction (default + backfill).
--    CHECK enforces the closed set; future scanner types extend the list.
-- =============================================================================
ALTER TABLE scan_jobs ADD COLUMN IF NOT EXISTS type TEXT NOT NULL DEFAULT 'extraction';

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_type_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_type_check
  CHECK (type IN ('extraction', 'dast'));

-- Composite index: type-aware claim queries hit (status, type, created_at).
CREATE INDEX IF NOT EXISTS idx_scan_jobs_type_status_created
  ON scan_jobs(type, status, created_at);

COMMENT ON COLUMN scan_jobs.type IS
  'Phase 23: scanner type discriminator. v1: extraction|dast. Future: malicious_pkg|iac|container.';

-- =============================================================================
-- 3. DAST sparse columns. Extraction rows leave these NULL.
-- =============================================================================
ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS target_url       TEXT,
  ADD COLUMN IF NOT EXISTS scan_profile     TEXT,
  ADD COLUMN IF NOT EXISTS timeout_minutes  INTEGER,
  ADD COLUMN IF NOT EXISTS trigger_source   TEXT,
  ADD COLUMN IF NOT EXISTS triggered_by     UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS error_category   TEXT,
  ADD COLUMN IF NOT EXISTS findings_count   INTEGER,
  ADD COLUMN IF NOT EXISTS duration_seconds INTEGER;

-- DAST scan profile: ZAP scan modes (baseline/full/api). Forward-compat with future engines.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_scan_profile_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_scan_profile_check
  CHECK (
    scan_profile IS NULL
    OR scan_profile IN ('baseline', 'full', 'api')
  );

-- DAST trigger source: how the scan was initiated. Extraction leaves NULL.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_trigger_source_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_source_check
  CHECK (
    trigger_source IS NULL
    OR trigger_source IN ('manual', 'webhook', 'scheduled', 'aegis')
  );

-- DAST error category: failure taxonomy. Extraction uses the existing `error` text field.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_error_category_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_error_category_check
  CHECK (
    error_category IS NULL
    OR error_category IN ('timeout', 'unreachable_target', 'ssrf_blocked', 'auth_failed', 'engine_crash', 'unknown')
  );

-- Sparse columns must be NULL for non-DAST rows (defense-in-depth: payloads belong to their type).
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_dast_columns_match_type;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_dast_columns_match_type
  CHECK (
    (type = 'dast') OR (
      target_url IS NULL
      AND scan_profile IS NULL
      AND timeout_minutes IS NULL
      AND trigger_source IS NULL
      AND triggered_by IS NULL
      AND error_category IS NULL
      AND findings_count IS NULL
      AND duration_seconds IS NULL
    )
  );

COMMENT ON COLUMN scan_jobs.target_url IS
  'Phase 23/DAST: HTTP(S) target URL for the scan. Extraction leaves NULL. SSRF-validated at queue time + worker pre-flight.';
COMMENT ON COLUMN scan_jobs.scan_profile IS
  'Phase 23/DAST: ZAP scan mode (baseline|full|api). Extraction leaves NULL.';
COMMENT ON COLUMN scan_jobs.timeout_minutes IS
  'Phase 23/DAST: hard timeout for the scan. Extraction leaves NULL (extraction uses its own per-step timeouts).';
COMMENT ON COLUMN scan_jobs.trigger_source IS
  'Phase 23/DAST: how the scan was initiated (manual|webhook|scheduled|aegis). Extraction leaves NULL.';
COMMENT ON COLUMN scan_jobs.triggered_by IS
  'Phase 23/DAST: user who initiated the scan, when applicable. Extraction leaves NULL.';
COMMENT ON COLUMN scan_jobs.error_category IS
  'Phase 23/DAST: structured failure taxonomy. Extraction uses existing `error` text field.';
COMMENT ON COLUMN scan_jobs.findings_count IS
  'Phase 23/DAST: count of findings emitted by this run. Extraction leaves NULL (extraction emits multiple finding kinds across separate tables).';
COMMENT ON COLUMN scan_jobs.duration_seconds IS
  'Phase 23/DAST: total scan duration. Extraction leaves NULL (extraction uses extraction_logs / extraction_runs timing).';

COMMENT ON TABLE scan_jobs IS
  'Phase 23: unified scan job queue. Replaces extraction_jobs. type discriminates scanner kind. Workers claim via claim_scan_job(machine_id, supported_types[]) and dispatch to per-type pipelines.';

-- =============================================================================
-- 4. Drop old extraction-named RPCs and rebuild as scan_jobs equivalents.
-- =============================================================================
DROP FUNCTION IF EXISTS claim_extraction_job(TEXT);
DROP FUNCTION IF EXISTS recover_stuck_extraction_jobs();
DROP FUNCTION IF EXISTS fail_exhausted_extraction_jobs();

-- claim_scan_job: atomic claim filtered by supported_types. Worker passes its capability list;
-- a depscanner machine that supports both extraction + DAST passes ARRAY['extraction','dast'].
-- The FOR UPDATE SKIP LOCKED prevents double-claim across concurrent pollers.
CREATE OR REPLACE FUNCTION claim_scan_job(
  p_machine_id      TEXT,
  p_supported_types TEXT[]
)
RETURNS SETOF scan_jobs AS $$
  UPDATE scan_jobs
  SET status      = 'processing',
      started_at  = NOW(),
      heartbeat_at = NOW(),
      machine_id  = p_machine_id,
      attempts    = attempts + 1
  WHERE id = (
    SELECT id FROM scan_jobs
    WHERE status = 'queued'
      AND type = ANY(p_supported_types)
    ORDER BY created_at
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *;
$$ LANGUAGE sql;

COMMENT ON FUNCTION claim_scan_job IS
  'Phase 23: atomic job claim. p_supported_types is the worker''s capability list — a machine ignores types it does not support, so a single Fly app can host different machine sizes per type via Fly Machines API.';

-- queue_scan_job: type-aware insert. Centralizes payload shape + sparse-column wiring.
-- Extraction callers pass NULLs for DAST columns; DAST callers pass NULL for extraction-only fields.
CREATE OR REPLACE FUNCTION queue_scan_job(
  p_project_id      UUID,
  p_organization_id UUID,
  p_type            TEXT,
  p_payload         JSONB,
  p_target_url       TEXT    DEFAULT NULL,
  p_scan_profile     TEXT    DEFAULT NULL,
  p_timeout_minutes  INTEGER DEFAULT NULL,
  p_trigger_source   TEXT    DEFAULT NULL,
  p_triggered_by     UUID    DEFAULT NULL
)
RETURNS scan_jobs AS $$
  INSERT INTO scan_jobs (
    project_id, organization_id, type, payload,
    target_url, scan_profile, timeout_minutes, trigger_source, triggered_by
  )
  VALUES (
    p_project_id, p_organization_id, p_type, COALESCE(p_payload, '{}'::jsonb),
    p_target_url, p_scan_profile, p_timeout_minutes, p_trigger_source, p_triggered_by
  )
  RETURNING *;
$$ LANGUAGE sql;

COMMENT ON FUNCTION queue_scan_job IS
  'Phase 23: type-aware scan-job insert. v1 callers: extraction-jobs.ts (type=extraction, sparse cols NULL), DAST routes in PR 2 (type=dast, target_url + scan_profile + timeout_minutes set).';

-- recover_stuck_scan_jobs: requeue jobs whose worker stopped sending heartbeats.
-- PR 1 only handles extraction (5min threshold). PR 2 will extend to DAST with a different
-- threshold via type-aware CASE logic.
CREATE OR REPLACE FUNCTION recover_stuck_scan_jobs()
RETURNS SETOF scan_jobs AS $$
  UPDATE scan_jobs
  SET status      = 'queued',
      machine_id  = NULL,
      started_at  = NULL,
      heartbeat_at = NULL,
      run_id      = gen_random_uuid()
  WHERE status = 'processing'
    AND type = 'extraction'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts < max_attempts
  RETURNING *;
$$ LANGUAGE sql;

COMMENT ON FUNCTION recover_stuck_scan_jobs IS
  'Phase 23: requeue jobs with stale heartbeats and remaining attempts. PR 1 only recovers extraction-type jobs (5min threshold). DAST type-aware threshold added in PR 2.';

-- fail_exhausted_scan_jobs: terminate jobs that have hit max_attempts.
CREATE OR REPLACE FUNCTION fail_exhausted_scan_jobs()
RETURNS SETOF scan_jobs AS $$
  UPDATE scan_jobs
  SET status        = 'failed',
      error         = type || ' job failed after ' || attempts || ' attempts (machine crash or timeout)',
      completed_at  = NOW()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts >= max_attempts
  RETURNING *;
$$ LANGUAGE sql;

COMMENT ON FUNCTION fail_exhausted_scan_jobs IS
  'Phase 23: terminate jobs that exhausted retries. Type-agnostic in PR 1; PR 2 may diverge thresholds per type.';

-- =============================================================================
-- 5. Update reap_orphaned_extractions to read scan_jobs.
--    The reaper still operates on extraction-type runs only — orphan reaping for DAST
--    will be a separate function in PR 2 (DAST writes findings to its own tables that the
--    extraction reaper does not know about).
-- =============================================================================
CREATE OR REPLACE FUNCTION reap_orphaned_extractions(p_older_than_hours INT DEFAULT 24)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_orphan RECORD;
  v_cutoff TIMESTAMPTZ := NOW() - (p_older_than_hours || ' hours')::INTERVAL;
  v_runs_reaped INTEGER := 0;
  v_pdv_deleted INTEGER := 0;
  v_pd_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
  v_events_deleted INTEGER := 0;
  v_entry_points_deleted INTEGER := 0;
  v_temp INTEGER;
  v_orphan_runs JSONB := '[]'::JSONB;
BEGIN
  FOR v_orphan IN
    SELECT DISTINCT sj.project_id, sj.id::TEXT AS run_id
    FROM scan_jobs sj
    JOIN projects p ON p.id = sj.project_id
    WHERE sj.type = 'extraction'
      AND sj.status IN ('failed', 'cancelled')
      AND sj.created_at < v_cutoff
      AND sj.id::TEXT IS DISTINCT FROM COALESCE(p.active_extraction_run_id, '')
      AND sj.id::TEXT IS DISTINCT FROM COALESCE(p.previous_extraction_run_id, '')
      AND NOT EXISTS (
        SELECT 1 FROM scan_jobs sj2
        WHERE sj2.project_id = sj.project_id
          AND sj2.type = 'extraction'
          AND sj2.status IN ('queued', 'processing')
      )
  LOOP
    DELETE FROM project_dependency_files
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_files_deleted := v_files_deleted + v_temp;

    DELETE FROM project_dependency_functions
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_fns_deleted := v_fns_deleted + v_temp;

    DELETE FROM project_dependency_vulnerabilities
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_pdv_deleted := v_pdv_deleted + v_temp;

    DELETE FROM project_semgrep_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_semgrep_deleted := v_semgrep_deleted + v_temp;

    DELETE FROM project_secret_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_secret_deleted := v_secret_deleted + v_temp;

    DELETE FROM project_reachable_flows
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_flows_deleted := v_flows_deleted + v_temp;

    DELETE FROM project_usage_slices
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_slices_deleted := v_slices_deleted + v_temp;

    DELETE FROM project_vulnerability_events
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_events_deleted := v_events_deleted + v_temp;

    DELETE FROM project_entry_points
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_entry_points_deleted := v_entry_points_deleted + v_temp;

    DELETE FROM project_dependencies
    WHERE project_id = v_orphan.project_id
      AND last_seen_extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_pd_deleted := v_pd_deleted + v_temp;

    v_orphan_runs := v_orphan_runs || jsonb_build_object(
      'project_id', v_orphan.project_id,
      'run_id', v_orphan.run_id
    );
    v_runs_reaped := v_runs_reaped + 1;
  END LOOP;

  RETURN jsonb_build_object(
    'cutoff_hours', p_older_than_hours,
    'runs_reaped', v_runs_reaped,
    'pdv_deleted', v_pdv_deleted,
    'pd_deleted', v_pd_deleted,
    'semgrep_deleted', v_semgrep_deleted,
    'secret_deleted', v_secret_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'files_deleted', v_files_deleted,
    'fns_deleted', v_fns_deleted,
    'events_deleted', v_events_deleted,
    'entry_points_deleted', v_entry_points_deleted,
    'orphan_runs', v_orphan_runs
  );
END;
$$;

COMMENT ON FUNCTION reap_orphaned_extractions IS
  'Phase 23: reads scan_jobs filtered by type=extraction. Body otherwise unchanged from phase22 — hard-deletes rows from extraction_run_ids that never made it to active/previous (failed/cancelled jobs > cutoff). DAST orphan reaping is a separate function added in PR 2.';

-- =============================================================================
-- 6. Note on commit_extraction (phase19/22): no edits needed.
--    The function takes p_job_id UUID as a parameter and never queries the jobs table
--    in its body — it only writes findings/deps. The extraction_jobs FK on
--    extraction_step_errors is auto-rewired by the rename in step 1 (Postgres updates
--    inbound FKs when a referenced table is renamed).
-- =============================================================================
