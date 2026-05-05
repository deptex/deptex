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
  WITH allowlisted AS (
    UPDATE public.project_malicious_findings pmf
    SET
      suppressed = true,
      suppressed_at = now(),
      suppressed_reason = 'allowlist:' || (
        -- Pick the matching allowlist entry deterministically:
        -- prefer version-pinned entries over "all versions" wildcards,
        -- then most-recent. Stable identity for the audit cite.
        SELECT oma.id::text
        FROM public.organization_malicious_allowlist oma
        INNER JOIN public.project_dependencies pd2 ON pd2.id = pmf.project_dependency_id
        INNER JOIN public.dependencies d2 ON d2.id = pd2.dependency_id
        WHERE oma.organization_id = p_org_id
          AND oma.revoked_at IS NULL
          AND oma.package_name = d2.name
          AND oma.ecosystem = public.canonicalize_malicious_ecosystem(d2.ecosystem)
          AND (oma.version IS NULL OR oma.version = pd2.version)
        ORDER BY (oma.version IS NULL) ASC, oma.added_at DESC
        LIMIT 1
      )
    FROM public.organization_malicious_allowlist oma
    INNER JOIN public.project_dependencies pd ON pd.id = pmf.project_dependency_id
    INNER JOIN public.dependencies d ON d.id = pd.dependency_id
    WHERE pmf.organization_id = p_org_id
      AND pmf.extraction_run_id = p_extraction_run_id
      AND pmf.suppressed = false
      AND oma.organization_id = p_org_id
      AND oma.revoked_at IS NULL
      AND oma.package_name = d.name
      AND oma.ecosystem = public.canonicalize_malicious_ecosystem(d.ecosystem)
      AND (oma.version IS NULL OR oma.version = pd.version)
    RETURNING pmf.id, pmf.dependency_id
  ),
  suppressed_count AS (
    SELECT count(*)::integer AS n,
           array_agg(DISTINCT dependency_id) AS dep_ids
    FROM allowlisted
  )
  SELECT n, dep_ids INTO v_suppressed, v_dep_ids FROM suppressed_count;

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
