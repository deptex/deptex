-- Phase 24.3: Scope get_project_vulnerabilities_from_pdv to the project's ACTIVE
-- extraction run (+ non-suppressed rows) and surface runtime_confirmed_at.
--
-- BUG: the RPC returned PDV rows from EVERY historical extraction run for the
-- project (WHERE pdv.project_id = p_project_id only). After a re-scan that demotes
-- a CVE (e.g. module -> unreachable), the stale prior-run row stayed in the result
-- set. The per-project endpoint sorts by contextual_depscore DESC and the frontend
-- dedup keeps the highest-scored row per (dependency, osv) — so the stale, higher-
-- scored row won and was rendered: the finding showed the OLD depscore + OLD
-- reachability, so the Findings table showed "New" (auto-triage couldn't see the
-- unreachable level) on a vuln whose detail panel correctly showed NOT REACHABLE.
--
-- FIX: scope to projects.active_extraction_run_id and suppressed = false — exactly
-- what the org-wide GET /:id/vulnerabilities endpoint already does. Also project
-- runtime_confirmed_at so the frontend auto-triage logic keeps runtime-confirmed
-- vulns out of the auto-ignored bucket.
--
-- DROP first because CREATE OR REPLACE cannot change a RETURNS TABLE shape.

DROP FUNCTION IF EXISTS public.get_project_vulnerabilities_from_pdv(uuid);

CREATE FUNCTION public.get_project_vulnerabilities_from_pdv(p_project_id uuid)
RETURNS TABLE(
  id uuid,
  dependency_id uuid,
  osv_id text,
  severity text,
  summary text,
  details text,
  aliases text[],
  fixed_versions text[],
  published_at timestamp with time zone,
  modified_at timestamp with time zone,
  created_at timestamp with time zone,
  dependency_name text,
  dependency_version text,
  is_reachable boolean,
  reachability_level text,
  reachability_details jsonb,
  epss_score numeric,
  cvss_score numeric,
  cisa_kev boolean,
  depscore integer,
  contextual_depscore numeric,
  entry_point_classification text,
  epd_status text,
  sla_status text,
  sla_deadline_at timestamp with time zone,
  runtime_confirmed_at timestamp with time zone
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    pdv.id,
    pd.dependency_id,
    pdv.osv_id,
    pdv.severity,
    pdv.summary,
    NULL::TEXT AS details,
    pdv.aliases,
    pdv.fixed_versions,
    pdv.published_at,
    NULL::TIMESTAMPTZ AS modified_at,
    pdv.created_at,
    pd.name AS dependency_name,
    pd.version AS dependency_version,
    pdv.is_reachable,
    pdv.reachability_level,
    pdv.reachability_details,
    pdv.epss_score,
    pdv.cvss_score,
    pdv.cisa_kev,
    pdv.depscore,
    pdv.contextual_depscore,
    pdv.entry_point_classification,
    pdv.epd_status,
    pdv.sla_status,
    pdv.sla_deadline_at,
    pdv.runtime_confirmed_at
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  INNER JOIN projects p
    ON p.id = pdv.project_id
  WHERE pdv.project_id = p_project_id
    AND pdv.extraction_run_id = p.active_extraction_run_id
    AND pdv.suppressed = false;
$$;

COMMENT ON FUNCTION public.get_project_vulnerabilities_from_pdv(uuid) IS
  'Phase 24.3: scopes to projects.active_extraction_run_id + suppressed=false (was returning stale rows from every run) and surfaces runtime_confirmed_at for frontend auto-triage.';
