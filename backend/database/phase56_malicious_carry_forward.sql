-- phase56: malicious-finding carry-forward + reap + is_malicious desync fix
--
-- PR-A left malicious manual-ignore as a status-only write with no carry-forward,
-- so an ignore reset on the next scan and `dependencies.is_malicious` stayed true
-- (the recompute only honoured the legacy suppressed/risk_accepted columns).
--
-- Malicious findings are NOT created by finalize_extraction — the worker inserts
-- them through `insert_malicious_findings_with_recompute`, which already recomputes
-- `is_malicious`. So carry-forward lives there (insert-time, order-independent,
-- keyed on the trigger-stamped finding_key) rather than in finalize. This also
-- gives malicious the same 2-run lifecycle as every other type by adding it to
-- `reap_old_extractions`.
--
-- Three functions are replaced in one transaction:
--   1. recompute_dependency_is_malicious — also treat a manual ignored/resolved
--      finding as "not active malicious" so a status ignore clears is_malicious.
--   2. insert_malicious_findings_with_recompute — carry a prior manual ignore onto
--      the freshly-inserted run before recomputing.
--   3. reap_old_extractions — delete malicious rows outside the active+previous
--      window and recompute the affected dependencies.

BEGIN;

-- 1. is_malicious now ignores manually-ignored / resolved findings ----------------
CREATE OR REPLACE FUNCTION public.recompute_dependency_is_malicious(p_dependency_ids uuid[])
 RETURNS void
 LANGUAGE plpgsql
AS $function$
BEGIN
  PERFORM 1 FROM public.dependencies WHERE id = ANY(p_dependency_ids) FOR UPDATE;

  UPDATE public.dependencies d
  SET is_malicious = (
    EXISTS (
      SELECT 1 FROM public.project_malicious_findings f
      WHERE f.dependency_id = d.id
        AND f.suppressed = false
        AND f.risk_accepted = false
        AND f.status NOT IN ('ignored', 'resolved')
    )
    OR EXISTS (
      SELECT 1 FROM public.known_malicious_packages k
      WHERE k.package_name = d.name
        AND k.ecosystem = public.canonicalize_malicious_ecosystem(d.ecosystem)
        AND k.withdrawn_at IS NULL
    )
  )
  WHERE d.id = ANY(p_dependency_ids);
END;
$function$
;

-- 2. carry a prior manual ignore onto the freshly-inserted run --------------------
CREATE OR REPLACE FUNCTION public.insert_malicious_findings_with_recompute(p_findings jsonb)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_inserted integer := 0;
  v_dep_ids uuid[];
  v_new_ids uuid[];
  v_project_ids uuid[];
BEGIN
  WITH inserted AS (
    INSERT INTO public.project_malicious_findings (
      project_id, organization_id, extraction_run_id, project_dependency_id,
      dependency_id, rule_id, scanner, severity, message, depscore,
      reachability_level, reachability_details, reachability_computed_at
    )
    SELECT
      (f->>'project_id')::uuid,
      (f->>'organization_id')::uuid,
      f->>'extraction_run_id',
      (f->>'project_dependency_id')::uuid,
      (f->>'dependency_id')::uuid,
      f->>'rule_id',
      f->>'scanner',
      f->>'severity',
      f->>'message',
      (f->>'depscore')::integer,
      f->>'reachability_level',
      f->'reachability_details',
      CASE
        WHEN f ? 'reachability_level' AND (f->>'reachability_level') IS NOT NULL THEN now()
        ELSE NULL
      END
    FROM jsonb_array_elements(p_findings) AS f
    ON CONFLICT (project_id, project_dependency_id, rule_id, scanner, extraction_run_id)
      DO NOTHING
    RETURNING id, dependency_id, project_id
  )
  SELECT array_agg(DISTINCT dependency_id),
         array_agg(id),
         array_agg(DISTINCT project_id),
         count(*)::integer
    INTO v_dep_ids, v_new_ids, v_project_ids, v_inserted
  FROM inserted;

  -- Carry a manual ignore from the most recent prior run of the same finding
  -- (matched on the trigger-stamped finding_key). Only 'ignored' carries —
  -- 'resolved' findings must not resurrect, and 'open' needs nothing.
  IF v_new_ids IS NOT NULL AND array_length(v_new_ids, 1) > 0 THEN
    UPDATE public.project_malicious_findings cur
    SET status        = prev.status,
        ignore_reason = prev.ignore_reason,
        ignore_note   = prev.ignore_note,
        ignored_by    = prev.ignored_by,
        ignored_at    = prev.ignored_at
    FROM (
      SELECT DISTINCT ON (p.project_id, p.finding_key)
             p.project_id, p.finding_key, p.status,
             p.ignore_reason, p.ignore_note, p.ignored_by, p.ignored_at
      FROM public.project_malicious_findings p
      WHERE p.project_id = ANY(v_project_ids)
        AND p.status = 'ignored'
        AND NOT (p.id = ANY(v_new_ids))
      ORDER BY p.project_id, p.finding_key, p.created_at DESC
    ) prev
    WHERE cur.id = ANY(v_new_ids)
      AND cur.project_id = prev.project_id
      AND cur.finding_key = prev.finding_key;
  END IF;

  IF v_dep_ids IS NOT NULL AND array_length(v_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_dep_ids);
  END IF;

  RETURN v_inserted;
END;
$function$
;

-- 3. reap malicious rows outside the active+previous window -----------------------
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
  v_malicious_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
  v_entry_points_deleted INTEGER := 0;
  v_mal_dep_ids uuid[];
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

  -- Malicious now follows the same 2-run window. Capture the affected
  -- dependencies so is_malicious can be recomputed after the delete.
  WITH del AS (
    DELETE FROM project_malicious_findings
    WHERE project_id = p_project_id
      AND extraction_run_id IS NOT NULL
      AND extraction_run_id <> v_active
      AND (v_previous IS NULL OR extraction_run_id <> v_previous)
    RETURNING dependency_id
  )
  SELECT array_agg(DISTINCT dependency_id), count(*)::integer
    INTO v_mal_dep_ids, v_malicious_deleted
  FROM del;

  IF v_mal_dep_ids IS NOT NULL AND array_length(v_mal_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_mal_dep_ids);
  END IF;

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
    'malicious_deleted', v_malicious_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'dep_files_deleted', v_files_deleted,
    'dep_functions_deleted', v_fns_deleted,
    'entry_points_deleted', v_entry_points_deleted
  );
END;
$function$
;

COMMIT;
