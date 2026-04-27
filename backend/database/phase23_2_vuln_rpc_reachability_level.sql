-- Phase 23.2: Surface reachability_level / reachability_details / contextual_depscore
-- in the project vulnerabilities endpoint
-- ==========================================================================
-- Context
-- --------------------------------------------------------------------------
-- `get_project_vulnerabilities_from_pdv` is the canonical server-side RPC
-- behind `/api/organizations/:id/projects/:projectId/vulnerabilities` —
-- the main page the UI reads. Before this migration the RPC returned only
-- the boolean `is_reachable`, hiding three columns that DO live on
-- `project_dependency_vulnerabilities`:
--   - reachability_level   (text — phase23 added 'confirmed')
--   - reachability_details (jsonb — rule_ids, flow_count, entry_points, ...)
--   - contextual_depscore  (numeric — phase18 EPD scoring)
--
-- The frontend `ReachabilityFilterLevel` and `VulnerabilityNode` etc.
-- already expect `reachability_level` (they handle 'confirmed' with a red
-- shield), and the route at backend/src/routes/projects.ts:7064 already
-- maps `contextual_depscore` from the RPC result. Without this migration
-- both land as `null` in the response. `contextual_depscore` in particular
-- is what the frontend sorts `rank()` by, so its absence has been
-- silently collapsing the sort order to the plain `depscore` field.
-- ==========================================================================

-- DROP first because changing the RETURN TABLE shape is not a valid
-- `CREATE OR REPLACE` edit in Postgres.
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
    pdv.sla_status,
    pdv.sla_deadline_at
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;

COMMENT ON FUNCTION public.get_project_vulnerabilities_from_pdv(uuid) IS
  'Phase 23.2: extends return shape with reachability_level, reachability_details, and contextual_depscore so the vulnerabilities UI can distinguish confirmed-level findings and sort by the EPD-adjusted score.';
