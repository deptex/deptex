-- =============================================================================
-- Malicious Packages v2: RPC updates
-- =============================================================================
-- 1. Replaces `insert_malicious_findings_with_recompute` to accept the new
--    `reachability_level` + `reachability_details` JSONB fields. Backwards-
--    compatible — callers that omit those fields still write rows with
--    NULL reachability columns.
--
-- 2. Adds `apply_malicious_allowlist(org_id, run_id)`. After findings land,
--    this auto-suppresses any matching the org allowlist with
--    `suppressed_reason='allowlist:<entry_id>'`, then recomputes the
--    `dependencies.is_malicious` denorm so the flag reflects allowlist
--    suppression. Uses `canonicalize_malicious_ecosystem(d.ecosystem)` (not
--    `lower(d.ecosystem)`) so legacy non-canonical values like 'gem',
--    'pip', 'go' match against the canonical allowlist column.
-- =============================================================================

CREATE OR REPLACE FUNCTION public.insert_malicious_findings_with_recompute(p_findings jsonb)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_inserted integer := 0;
  v_dep_ids uuid[];
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
      -- Stamp the computed_at only when the caller actually classified.
      -- A null `reachability_level` means soft-fail or resolver disabled —
      -- don't pretend we ran the resolver in that case.
      CASE
        WHEN f ? 'reachability_level' AND (f->>'reachability_level') IS NOT NULL THEN now()
        ELSE NULL
      END
    FROM jsonb_array_elements(p_findings) AS f
    ON CONFLICT (project_id, project_dependency_id, rule_id, scanner, extraction_run_id)
      DO NOTHING
    RETURNING dependency_id
  )
  SELECT array_agg(DISTINCT dependency_id), count(*)::integer
    INTO v_dep_ids, v_inserted FROM inserted;

  IF v_dep_ids IS NOT NULL AND array_length(v_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_dep_ids);
  END IF;

  RETURN v_inserted;
END;
$$;

-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.apply_malicious_allowlist(p_org_id uuid, p_extraction_run_id text)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
  v_suppressed integer := 0;
  v_dep_ids uuid[];
BEGIN
  -- Pick the deterministic-best allowlist entry per pmf.id via DISTINCT ON,
  -- then UPDATE ... FROM that CTE. The earlier scalar-subquery-in-SET shape
  -- raised "invalid reference to FROM-clause entry for table 'pmf'" because
  -- the subquery introduced its own JOIN scope and the outer pmf
  -- correlation didn't survive the join boundary. Same picking semantics
  -- (version-pinned beats wildcard, then most-recent), different SQL shape.
  WITH pmf_candidates AS (
    SELECT DISTINCT ON (pmf.id)
      pmf.id AS pmf_id,
      oma.id AS allowlist_id,
      pmf.dependency_id
    FROM public.project_malicious_findings pmf
    INNER JOIN public.project_dependencies pd ON pd.id = pmf.project_dependency_id
    INNER JOIN public.dependencies d ON d.id = pd.dependency_id
    INNER JOIN public.organization_malicious_allowlist oma
      ON oma.organization_id = p_org_id
      AND oma.revoked_at IS NULL
      AND oma.package_name = d.name
      AND oma.ecosystem = public.canonicalize_malicious_ecosystem(d.ecosystem)
      AND (oma.version IS NULL OR oma.version = pd.version)
    WHERE pmf.organization_id = p_org_id
      AND pmf.extraction_run_id = p_extraction_run_id
      AND pmf.suppressed = false
    ORDER BY pmf.id, (oma.version IS NULL) ASC, oma.added_at DESC
  ),
  applied AS (
    UPDATE public.project_malicious_findings pmf
    SET suppressed = true,
        suppressed_at = now(),
        suppressed_reason = 'allowlist:' || c.allowlist_id::text
    FROM pmf_candidates c
    WHERE pmf.id = c.pmf_id
    RETURNING pmf.id, pmf.dependency_id
  )
  SELECT count(*)::integer, array_agg(DISTINCT dependency_id)
  INTO v_suppressed, v_dep_ids
  FROM applied;

  -- Re-recompute is_malicious so the denorm reflects allowlist suppression.
  -- Note: recompute keeps is_malicious=true for deps still matched by
  -- known_malicious_packages (the second EXISTS clause inside
  -- recompute_dependency_is_malicious). Feed-flagged packages stay flagged
  -- regardless of per-project allowlist.
  IF v_dep_ids IS NOT NULL AND array_length(v_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_dep_ids);
  END IF;

  RETURN COALESCE(v_suppressed, 0);
END;
$$;
