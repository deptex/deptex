-- Phase 45: IaC + Container re-scan idempotency fix.
--
-- project_iac_findings / project_container_findings use a RUN-SCOPED row model:
-- one row per (finding, extraction_run_id), the worker upsert keys on the
-- run-scoped idx_*_unique index, and finalize_extraction carries triage state
-- (status / suppressed / risk_accepted) forward from the previous run by
-- fingerprint. This is identical to project_semgrep_findings /
-- project_secret_findings.
--
-- Two bugs made EVERY re-scan of an IaC/container project fail:
--
--   1. idx_piacf_fingerprint / idx_pcf_fingerprint were UNIQUE across runs
--      (the indexes carry no extraction_run_id). A cross-run UNIQUE on the
--      fingerprint means a given finding is legal in exactly ONE run forever.
--      Run #2 inserts a fresh row carrying the same fingerprint as run #1's
--      still-present row → unique violation → the scanner upsert throws → the
--      whole scan hard-fails (`IaC / container scanner(s) failed: ...
--      duplicate key value violates unique constraint idx_piacf_fingerprint`).
--      Within-run dedup is already provided by the run-scoped idx_*_unique
--      indexes, so the fingerprint indexes never needed to be unique. Recreate
--      them NON-unique — they still serve the finalize carry-forward join and
--      the phase25 bad-data-recovery UPDATE, neither of which needs uniqueness.
--
--   2. reap_old_extractions (called by finalize) and reap_orphaned_extractions
--      (the 24h stuck-job recovery cron) delete superseded-run rows for every
--      other findings table but NOT these two. So old-run rows both accumulated
--      unbounded AND stuck around to collide. Add the missing DELETEs so
--      iac/container reap exactly like semgrep/secret: retain the active +
--      previous run, drop everything older.
--
-- The read path already filters by active_extraction_run_id (see
-- backend/src/routes/scanner-findings.ts), so retaining active+previous never
-- double-counts. Deleting a container finding cascades to
-- project_composition_partners (ON DELETE CASCADE); project_iac_findings has no
-- inbound FK.

-- ── 1. Drop the cross-run UNIQUE; recreate the same indexes NON-unique ───────
DROP INDEX IF EXISTS public.idx_piacf_fingerprint;
CREATE INDEX idx_piacf_fingerprint
  ON public.project_iac_findings USING btree (project_id, scanner, iac_fingerprint)
  WHERE (iac_fingerprint IS NOT NULL);

DROP INDEX IF EXISTS public.idx_pcf_fingerprint;
CREATE INDEX idx_pcf_fingerprint
  ON public.project_container_findings USING btree (project_id, container_fingerprint)
  WHERE (container_fingerprint IS NOT NULL);

-- ── 2. reap_old_extractions — also reap iac/container (active + previous) ────
CREATE OR REPLACE FUNCTION public.reap_old_extractions(p_project_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_active TEXT;
  v_previous TEXT;
  v_pdv_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_iac_deleted INTEGER := 0;
  v_container_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
  v_entry_points_deleted INTEGER := 0;
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

  RETURN jsonb_build_object(
    'project_id', p_project_id,
    'active', v_active,
    'previous', v_previous,
    'pdv_deleted', v_pdv_deleted,
    'semgrep_deleted', v_semgrep_deleted,
    'secret_deleted', v_secret_deleted,
    'iac_deleted', v_iac_deleted,
    'container_deleted', v_container_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'dep_files_deleted', v_files_deleted,
    'dep_functions_deleted', v_fns_deleted,
    'entry_points_deleted', v_entry_points_deleted
  );
END;
$function$
;

-- ── 3. reap_orphaned_extractions — also reap iac/container for orphan runs ───
CREATE OR REPLACE FUNCTION public.reap_orphaned_extractions(p_older_than_hours integer DEFAULT 24)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_orphan RECORD;
  v_cutoff TIMESTAMPTZ := NOW() - (p_older_than_hours || ' hours')::INTERVAL;
  v_runs_reaped INTEGER := 0;
  v_pdv_deleted INTEGER := 0;
  v_pd_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_iac_deleted INTEGER := 0;
  v_container_deleted INTEGER := 0;
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

    DELETE FROM project_iac_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_iac_deleted := v_iac_deleted + v_temp;

    DELETE FROM project_container_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_container_deleted := v_container_deleted + v_temp;

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
    'iac_deleted', v_iac_deleted,
    'container_deleted', v_container_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'files_deleted', v_files_deleted,
    'fns_deleted', v_fns_deleted,
    'events_deleted', v_events_deleted,
    'entry_points_deleted', v_entry_points_deleted,
    'orphan_runs', v_orphan_runs
  );
END;
$function$
;
