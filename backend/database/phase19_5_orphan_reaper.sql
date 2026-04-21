-- Phase 19.5: reap_orphaned_extractions RPC
--
-- `finalize_extraction` calls `reap_old_extractions` inline at the end of the
-- happy path, which cleans up rows from runs older than (active, previous).
-- But when an extraction crashes BEFORE finalize runs (machine killed, timeout,
-- max-attempts hit), its streamed rows stay behind tagged with a run_id that
-- never became active/previous. Those rows are invisible to read queries
-- (filtered by active_extraction_run_id) but accumulate indefinitely.
--
-- This RPC reaps those orphans. Called from the existing extraction-jobs
-- recovery cron (backend/src/routes/recovery.ts, QStash every 5min).
--
-- Safety rails:
--   1. Only targets run_ids from extraction_jobs with status failed/cancelled.
--   2. Only reaps jobs older than the configurable cutoff (default 24h).
--   3. Skips projects with any currently-queued or in-flight job, so an
--      in-progress extraction doesn't have its streamed rows yanked mid-run.
--   4. Never touches rows tagged with active_extraction_run_id or
--      previous_extraction_run_id for the project (double-guard beyond #1-#3).

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
  v_temp INTEGER;
  v_orphan_runs JSONB := '[]'::JSONB;
BEGIN
  FOR v_orphan IN
    SELECT DISTINCT ej.project_id, ej.id::TEXT AS run_id
    FROM extraction_jobs ej
    JOIN projects p ON p.id = ej.project_id
    WHERE ej.status IN ('failed', 'cancelled')
      AND ej.created_at < v_cutoff
      AND ej.id::TEXT IS DISTINCT FROM COALESCE(p.active_extraction_run_id, '')
      AND ej.id::TEXT IS DISTINCT FROM COALESCE(p.previous_extraction_run_id, '')
      AND NOT EXISTS (
        SELECT 1 FROM extraction_jobs ej2
        WHERE ej2.project_id = ej.project_id
          AND ej2.status IN ('queued', 'processing')
      )
  LOOP
    -- extraction_run_id is extraction_jobs.id (the PK, used by runPipeline as runId).
    -- Count files/fns BEFORE deleting PDs
    -- so we get accurate row-counts (PD delete CASCADEs pdf/pdfn).
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

    -- PD rows last seen by this orphan (no newer run referenced them).
    -- Outer loop already guarantees v_orphan.run_id is neither active nor
    -- previous, so this is safe.
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
    'orphan_runs', v_orphan_runs
  );
END;
$$;

COMMENT ON FUNCTION reap_orphaned_extractions IS
  'Phase 19.5: hard-deletes rows tagged with extraction_run_ids from failed/cancelled jobs older than p_older_than_hours. Called from the QStash extraction-jobs recovery cron (every 5min). Returns orphan_runs array so the caller can clean up Supabase Storage bucket files under project-imports/${project_id}/${run_id}/.';
