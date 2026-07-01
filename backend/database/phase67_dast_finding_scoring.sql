-- phase67: DAST finding scoring (N2 + SC2)
--
-- N2 — DAST findings have no depscore, so ZAP/Nuclei rows can't rank in the
--      unified findings order alongside SCA/SAST/secret/container/IaC findings.
--      Add a `depscore` column to project_dast_findings and backfill it.
--      The worker writes it going forward via calculateDastDepscore() =
--      severity-band base (critical 90 / high 70 / medium 50 / low 30 /
--      info 10 — the container/IaC severityToDepscore convention) folded with
--      projects.importance, at the implicit CONFIRMED reachability tier (1.0)
--      because a DAST hit is literal runtime proof.
--
-- SC2 — confirm_pdvs_from_dast_run flips a cross-linked PDV to 'confirmed' but
--       kept its pre-DAST contextual_depscore, so a vuln DAST just proved
--       reachable still ranked with its old, lower, unconfirmed score. Fill in
--       contextual_depscore at the confirmed tier when it was NULL (the EPD-
--       never-ran case), consistent with the worker's writers
--       (contextual = base_depscore_no_reachability × epd_factor, with the
--       confirmed-tier reachability weight = 1.0 implicit). Rows that already
--       carry an EPD/composition-derived contextual are left untouched —
--       contextual is reachability-weight-independent, so promotion to
--       confirmed does not change it.

-- ---------------------------------------------------------------------------
-- N2: depscore column + backfill
-- ---------------------------------------------------------------------------
ALTER TABLE public.project_dast_findings
  ADD COLUMN IF NOT EXISTS depscore integer;

UPDATE public.project_dast_findings f
   SET depscore = LEAST(100, ROUND(
         (CASE lower(f.severity)
            WHEN 'critical' THEN 90
            WHEN 'high'     THEN 70
            WHEN 'medium'   THEN 50
            WHEN 'low'      THEN 30
            WHEN 'info'     THEN 10
            ELSE 30 END)
         * GREATEST(0.5, LEAST(2.0, COALESCE(p.importance, 1.0)))
       ))::integer
  FROM public.projects p
 WHERE p.id = f.project_id
   AND f.depscore IS NULL;

-- ---------------------------------------------------------------------------
-- SC2: recompute contextual_depscore on DAST confirmation
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.confirm_pdvs_from_dast_run(p_project_id uuid, p_dast_run_id text)
 RETURNS TABLE(pdv_id uuid, osv_id text, prior_reachability_level text, new_reachability_level text)
 LANGUAGE plpgsql
 SET search_path TO 'public'
 SET statement_timeout TO '5s'
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.project_dast_findings
     WHERE dast_run_id = p_dast_run_id
       AND project_id = p_project_id
       AND engine = 'nuclei'
  ) THEN
    RAISE EXCEPTION 'dast_run_id % has no Nuclei findings in project %',
      p_dast_run_id, p_project_id USING ERRCODE = 'P0001';
  END IF;

  RETURN QUERY
  WITH matches AS (
    SELECT DISTINCT ON (pdv.id)
      pdv.id  AS pdv_id,
      pdv.osv_id,
      pdv.reachability_level AS prior_level,
      f.id    AS dast_finding_id
    FROM public.project_dast_findings f
    CROSS JOIN LATERAL (
      SELECT array_agg(upper(c)) AS cves
        FROM jsonb_array_elements_text(f.cross_link_metadata->'nuclei'->'cve_ids') c
    ) cve_set
    JOIN public.project_dependency_vulnerabilities pdv
      ON pdv.project_id = f.project_id
     AND pdv.project_dependency_id = f.linked_sca_project_dependency_id
     AND (
       upper(pdv.osv_id) = ANY(cve_set.cves)
       OR EXISTS (
         SELECT 1 FROM unnest(COALESCE(pdv.aliases, ARRAY[]::text[])) a
          WHERE upper(a) = ANY(cve_set.cves)
       )
     )
    WHERE f.project_id = p_project_id
      AND f.dast_run_id = p_dast_run_id
      AND f.engine = 'nuclei'
      AND f.linked_sca_project_dependency_id IS NOT NULL
      AND cve_set.cves IS NOT NULL
      AND public._pdv_reachability_rank(pdv.reachability_level) < public._pdv_reachability_rank('confirmed')
    ORDER BY pdv.id, public._pdv_severity_rank(f.severity) DESC, f.created_at ASC
  ),
  updated AS (
    UPDATE public.project_dependency_vulnerabilities pdv
       SET reachability_level             = 'confirmed',
           runtime_confirmed_at           = now(),
           runtime_confirmed_dast_finding_id = m.dast_finding_id,
           runtime_confirmed_prior_level  = m.prior_level,
           -- SC2: a DAST hit proves runtime reachability (confirmed tier,
           -- weight 1.0). When EPD never ran (module/function/unreachable PDVs
           -- carry NULL contextual_depscore), the canonical ranking score
           -- COALESCE(contextual_depscore, depscore) fell back to the stale,
           -- reachability-discounted depscore. Fill in the confirmed-tier
           -- contextual = base_depscore_no_reachability × COALESCE(epd_factor, 1.0)
           -- so the row ranks at its full proven severity. Existing (EPD- or
           -- composition-derived) contextual values are reachability-weight-
           -- independent and are left untouched.
           contextual_depscore = CASE
             WHEN pdv.contextual_depscore IS NULL THEN
               ROUND(
                 COALESCE(pdv.base_depscore_no_reachability, pdv.depscore, 0)
                   * COALESCE(pdv.epd_factor, 1.0),
                 4)
             ELSE pdv.contextual_depscore
           END
      FROM matches m
     WHERE pdv.id = m.pdv_id
    RETURNING pdv.id, pdv.osv_id, m.prior_level AS prior_level,
              pdv.reachability_level AS new_level
  )
  SELECT updated.id, updated.osv_id, updated.prior_level, updated.new_level FROM updated;
END;
$function$
;

REVOKE EXECUTE ON FUNCTION public.confirm_pdvs_from_dast_run(uuid, text) FROM PUBLIC;
GRANT  EXECUTE ON FUNCTION public.confirm_pdvs_from_dast_run(uuid, text) TO service_role;
