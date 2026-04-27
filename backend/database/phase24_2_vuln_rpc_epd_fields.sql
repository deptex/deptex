-- Phase 24.2: Surface entry_point_classification + epd_status on the vuln RPC
--
-- Extends get_project_vulnerabilities_from_pdv (last bumped by phase23_2) with
-- the two EPD disclosure fields the frontend badge reads. Both already live
-- on project_dependency_vulnerabilities (phase18 schema); this RPC just
-- wasn't projecting them. Without this change the frontend receives `null`
-- for both and the EntryPointBadge never renders on reachable vulns.
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
  sla_deadline_at timestamp with time zone
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
    pdv.sla_deadline_at
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;

COMMENT ON FUNCTION public.get_project_vulnerabilities_from_pdv(uuid) IS
  'Phase 24.2: adds entry_point_classification and epd_status to the return shape so the frontend can render the EPD entry-point badge (Public / Authenticated / Background) next to each reachable vulnerability.';
