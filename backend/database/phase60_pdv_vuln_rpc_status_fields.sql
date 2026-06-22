-- The project-panel vulnerability list (get_project_vulnerabilities_from_pdv)
-- omitted the unified-status columns, so reachable dependency vulns reached the
-- UI with no finding_key / status. The status cell had no handle to act on, so
-- the ⋯ actions menu (Ignore / file a ticket / Fix with Aegis) never rendered on
-- a dependency CVE row — only on data-flow rows, which come from a different
-- endpoint that already carries a key.
--
-- Surface finding_key + the status columns, and stop filtering out suppressed
-- rows here: the frontend Open / Ignored / All facet now owns that visibility
-- (matching the org-wide vuln list), so an ignored vuln moves to the Ignored tab
-- instead of vanishing from the project panel.
--
-- RETURNS TABLE gains columns, which CREATE OR REPLACE can't do — drop first.
DROP FUNCTION IF EXISTS public.get_project_vulnerabilities_from_pdv(uuid);

CREATE FUNCTION public.get_project_vulnerabilities_from_pdv(p_project_id uuid)
 RETURNS TABLE(
   id uuid, dependency_id uuid, osv_id text, severity text, summary text,
   details text, aliases text[], fixed_versions text[],
   published_at timestamptz, modified_at timestamptz, created_at timestamptz,
   dependency_name text, dependency_version text, is_reachable boolean,
   reachability_level text, reachability_details jsonb, epss_score numeric,
   cvss_score numeric, cisa_kev boolean, depscore integer,
   contextual_depscore numeric, entry_point_classification text, epd_status text,
   sla_status text, sla_deadline_at timestamptz, runtime_confirmed_at timestamptz,
   finding_key text, status text, auto_ignored boolean, auto_ignore_reason text,
   ignore_reason text, ignore_note text, suppressed boolean, risk_accepted boolean
 )
 LANGUAGE sql
 STABLE
AS $function$
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
    pdv.runtime_confirmed_at,
    pdv.finding_key,
    pdv.status,
    pdv.auto_ignored,
    pdv.auto_ignore_reason,
    pdv.ignore_reason,
    pdv.ignore_note,
    pdv.suppressed,
    pdv.risk_accepted
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  INNER JOIN projects p
    ON p.id = pdv.project_id
  WHERE pdv.project_id = p_project_id
    AND pdv.extraction_run_id = p.active_extraction_run_id;
$function$;
