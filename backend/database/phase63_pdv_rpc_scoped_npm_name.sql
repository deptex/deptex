-- phase63: fix scoped-npm package names displaying with their scope dropped.
--
-- cdxgen emits a scoped npm package as name='core' + group='@babel', and
-- sbom.ts persists those into project_dependencies.name + .namespace as SEPARATE
-- columns. get_project_vulnerabilities_from_pdv returned the bare `pd.name`, so
-- every `@scope/name` package (`@babel/core`, `@radix-ui/*`, `@remix-run/*`, …)
-- rendered with its scope dropped (e.g. "core" for "@babel/core") — confusing,
-- and it breaks registry / CVE cross-references that key on the canonical name.
--
-- Fix: reassemble the canonical display name ecosystem-awarely. npm scopes start
-- with `@` and join with `/`; Maven's `group:name` is a deliberately separate
-- coordinate (no `/`), so we only rejoin when the namespace looks like an npm
-- scope (`@…`). Everything else keeps the bare name unchanged.
--
-- Read-side only — project_dependencies.name stays the bare cdxgen name so dedup
-- keys + OSV/SBOM purl matching are untouched.

CREATE OR REPLACE FUNCTION public.get_project_vulnerabilities_from_pdv(p_project_id uuid)
 RETURNS TABLE(id uuid, dependency_id uuid, osv_id text, severity text, summary text, details text, aliases text[], fixed_versions text[], published_at timestamp with time zone, modified_at timestamp with time zone, created_at timestamp with time zone, dependency_name text, dependency_version text, is_reachable boolean, reachability_level text, reachability_details jsonb, epss_score numeric, cvss_score numeric, cisa_kev boolean, depscore integer, contextual_depscore numeric, entry_point_classification text, epd_status text, sla_status text, sla_deadline_at timestamp with time zone, runtime_confirmed_at timestamp with time zone, finding_key text, status text, auto_ignored boolean, auto_ignore_reason text, ignore_reason text, ignore_note text, suppressed boolean, risk_accepted boolean)
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
    -- Rejoin an npm scope (`@babel` + `core` -> `@babel/core`); leave Maven
    -- group:name and unscoped packages as the bare name.
    CASE
      WHEN pd.namespace IS NOT NULL
       AND pd.namespace <> ''
       AND left(pd.namespace, 1) = '@'
        THEN pd.namespace || '/' || pd.name
      ELSE pd.name
    END AS dependency_name,
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
