-- Phase 30: IaC + Container scanning carry-forward correctness fix.
--
-- Two interlocking bugs from phase25 broke any second extraction run with
-- non-NULL fingerprints:
--
--   1. The fingerprint indexes were declared UNIQUE without including
--      extraction_run_id. The first run's row pins (project_id, scanner,
--      iac_fingerprint) and the second run's identical-fingerprint row
--      violates the UNIQUE constraint at INSERT time. Same for
--      project_container_findings on (project_id, container_fingerprint).
--      Carry-forward only ever needed a lookup index, not a uniqueness
--      contract — UNIQUE was overreach.
--
--   2. reap_old_extractions never added project_iac_findings or
--      project_container_findings to its DELETE list, so even if the UNIQUE
--      were dropped, every successful run accumulates rows under the previous
--      run's id forever. Combined with #1 above, the very first re-run after
--      phase25 shipped would have failed.
--
-- Fix:
--   - Drop the UNIQUE indexes; recreate as plain (non-unique) indexes that
--     still serve carry-forward lookups.
--   - Extend reap_old_extractions to delete IaC + container rows for runs
--     that are neither the active nor previous-active. Mirrors the other
--     finding-table reaps in the same function.
--
-- Idempotent. Safe to apply on populated tables: dropping UNIQUE never
-- rejects existing data, and the recreate uses IF NOT EXISTS.

BEGIN;

-- ============================================================
-- 1. Drop UNIQUE on fingerprint indexes; recreate non-unique.
-- ============================================================
DROP INDEX IF EXISTS idx_piacf_fingerprint;
CREATE INDEX IF NOT EXISTS idx_piacf_fingerprint
  ON project_iac_findings (project_id, scanner, iac_fingerprint)
  WHERE iac_fingerprint IS NOT NULL;

DROP INDEX IF EXISTS idx_pcf_fingerprint;
CREATE INDEX IF NOT EXISTS idx_pcf_fingerprint
  ON project_container_findings (project_id, container_fingerprint)
  WHERE container_fingerprint IS NOT NULL;

-- ============================================================
-- 2. Extend reap_old_extractions to clean up IaC + container findings.
-- Mirrors the existing semgrep / secret / pdv DELETEs in the same function.
-- ============================================================
CREATE OR REPLACE FUNCTION reap_old_extractions(p_project_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_active TEXT;
  v_previous TEXT;
  v_pdv_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
  v_entry_points_deleted INTEGER := 0;
  v_iac_deleted INTEGER := 0;
  v_container_deleted INTEGER := 0;
BEGIN
  SELECT active_extraction_run_id, previous_extraction_run_id
    INTO v_active, v_previous
  FROM projects WHERE id = p_project_id;

  IF v_active IS NULL THEN
    RETURN jsonb_build_object('skipped', true, 'reason', 'no_active_run');
  END IF;

  DELETE FROM project_dependency_vulnerabilities
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_pdv_deleted = ROW_COUNT;

  DELETE FROM project_semgrep_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_semgrep_deleted = ROW_COUNT;

  DELETE FROM project_secret_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_secret_deleted = ROW_COUNT;

  DELETE FROM project_reachable_flows
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_flows_deleted = ROW_COUNT;

  DELETE FROM project_usage_slices
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_slices_deleted = ROW_COUNT;

  DELETE FROM project_dependency_files pdf
  USING project_dependencies pd
  WHERE pdf.project_dependency_id = pd.id
    AND pd.project_id = p_project_id
    AND pdf.extraction_run_id IS NOT NULL
    AND pdf.extraction_run_id <> v_active
    AND (v_previous IS NULL OR pdf.extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_files_deleted = ROW_COUNT;

  DELETE FROM project_dependency_functions pdfn
  USING project_dependencies pd
  WHERE pdfn.project_dependency_id = pd.id
    AND pd.project_id = p_project_id
    AND pdfn.extraction_run_id IS NOT NULL
    AND pdfn.extraction_run_id <> v_active
    AND (v_previous IS NULL OR pdfn.extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_fns_deleted = ROW_COUNT;

  DELETE FROM project_entry_points
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_entry_points_deleted = ROW_COUNT;

  -- Phase 30: IaC + container finding-table reaps. Mirrors the other
  -- finding-table DELETEs above. Without these, fingerprint duplicates
  -- accumulate and the partial index on (project_id, scanner, fingerprint)
  -- starts blocking inserts on the third+ run.
  DELETE FROM project_iac_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_iac_deleted = ROW_COUNT;

  DELETE FROM project_container_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_container_deleted = ROW_COUNT;

  RETURN jsonb_build_object(
    'project_id', p_project_id,
    'active', v_active,
    'previous', v_previous,
    'pdv_deleted', v_pdv_deleted,
    'semgrep_deleted', v_semgrep_deleted,
    'secret_deleted', v_secret_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'dep_files_deleted', v_files_deleted,
    'dep_functions_deleted', v_fns_deleted,
    'entry_points_deleted', v_entry_points_deleted,
    'iac_deleted', v_iac_deleted,
    'container_deleted', v_container_deleted
  );
END;
$$;

COMMENT ON FUNCTION reap_old_extractions IS
  'Phase 19.2 (+ Phase 22 + Phase 30): hard-delete finding rows belonging to extraction_run_ids that are neither the active nor the previous-active for the given project. Phase 30 added project_iac_findings + project_container_findings cleanup.';

-- ============================================================
-- 3. Extend reap_orphaned_extractions for the same two tables.
-- Without this, an extraction that crashes mid-run leaves IaC/container
-- rows tagged with a run_id that never becomes active — same accumulation
-- problem as #2 above, just on the failure path.
-- ============================================================
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
  v_iac_deleted INTEGER := 0;
  v_container_deleted INTEGER := 0;
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

    DELETE FROM project_iac_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_iac_deleted := v_iac_deleted + v_temp;

    DELETE FROM project_container_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_container_deleted := v_container_deleted + v_temp;

    -- PD rows last seen by this orphan (no newer run referenced them).
    DELETE FROM project_dependencies
    WHERE project_id = v_orphan.project_id
      AND last_seen_extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_pd_deleted := v_pd_deleted + v_temp;

    v_runs_reaped := v_runs_reaped + 1;
    v_orphan_runs := v_orphan_runs || jsonb_build_array(jsonb_build_object(
      'project_id', v_orphan.project_id,
      'run_id', v_orphan.run_id
    ));
  END LOOP;

  RETURN jsonb_build_object(
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
    'iac_deleted', v_iac_deleted,
    'container_deleted', v_container_deleted,
    'runs', v_orphan_runs
  );
END;
$$;

COMMENT ON FUNCTION reap_orphaned_extractions IS
  'Phase 19.5 (+ Phase 30): hard-delete finding rows for extraction_run_ids that crashed before finalize_extraction could promote them. Phase 30 added project_iac_findings + project_container_findings.';

COMMIT;
