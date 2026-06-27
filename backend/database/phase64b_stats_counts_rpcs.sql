-- phase64b: SQL-aggregate RPCs for the live project /stats and team /stats endpoints.
--
-- Why: both handlers fetched ALL project_dependency_vulnerabilities / project_dependencies
-- rows and counted them in JS. PostgREST caps a client fetch at 1000 rows, so for any
-- project/team with >1000 vulns (or deps) the critical/high/SLA/deps tallies silently
-- truncated to wrong (low) numbers. Counting server-side with FILTER aggregates removes the
-- cap entirely. These RPCs mirror the EXACT tally semantics of the JS they replace
-- (read projects.ts ~L11435 and teams.ts ~L1964 for the originals) — no new predicates.

-- ---------------------------------------------------------------------------
-- project_stats_counts — replaces the vulnRows + depsRows JS counting in
-- GET /:id/projects/:projectId/stats. vuln_total is unconditional over the
-- suppressed=false set; SLA is also over suppressed=false (project /stats only).
-- policy_result is compared as jsonb (=== true / === false) to match the strict
-- boolean check `policy_result?.allowed === true/false` exactly.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.project_stats_counts(
  p_project_id uuid,
  p_active_run_id text
)
RETURNS TABLE (
  vuln_total bigint, vuln_critical bigint, vuln_high bigint, vuln_medium bigint, vuln_low bigint,
  reachable_count bigint,
  sla_on_track bigint, sla_warning bigint, sla_breached bigint, sla_exempt bigint,
  sla_met bigint, sla_resolved_late bigint,
  deps_total bigint, deps_direct bigint, deps_transitive bigint, deps_outdated bigint,
  deps_compliant bigint, deps_failing bigint, deps_vulnerable bigint
)
LANGUAGE sql STABLE AS $$
  SELECT
    v.vuln_total, v.vuln_critical, v.vuln_high, v.vuln_medium, v.vuln_low, v.reachable_count,
    v.sla_on_track, v.sla_warning, v.sla_breached, v.sla_exempt, v.sla_met, v.sla_resolved_late,
    d.deps_total, d.deps_direct, d.deps_transitive, d.deps_outdated,
    d.deps_compliant, d.deps_failing, v.deps_vulnerable
  FROM (
    SELECT
      count(*) FILTER (WHERE NOT suppressed) AS vuln_total,
      count(*) FILTER (WHERE NOT suppressed AND severity = 'critical') AS vuln_critical,
      count(*) FILTER (WHERE NOT suppressed AND severity = 'high') AS vuln_high,
      count(*) FILTER (WHERE NOT suppressed AND severity = 'medium') AS vuln_medium,
      count(*) FILTER (WHERE NOT suppressed AND severity = 'low') AS vuln_low,
      count(*) FILTER (WHERE NOT suppressed AND is_reachable) AS reachable_count,
      count(*) FILTER (WHERE NOT suppressed AND sla_status = 'on_track') AS sla_on_track,
      count(*) FILTER (WHERE NOT suppressed AND sla_status = 'warning') AS sla_warning,
      count(*) FILTER (WHERE NOT suppressed AND sla_status = 'breached') AS sla_breached,
      count(*) FILTER (WHERE NOT suppressed AND sla_status = 'exempt') AS sla_exempt,
      count(*) FILTER (WHERE NOT suppressed AND sla_status = 'met') AS sla_met,
      count(*) FILTER (WHERE NOT suppressed AND sla_status = 'resolved_late') AS sla_resolved_late,
      count(DISTINCT project_dependency_id) FILTER (WHERE NOT suppressed) AS deps_vulnerable
    FROM project_dependency_vulnerabilities
    WHERE project_id = p_project_id AND extraction_run_id = p_active_run_id
  ) v
  CROSS JOIN (
    SELECT
      count(*) AS deps_total,
      count(*) FILTER (WHERE is_direct) AS deps_direct,
      count(*) FILTER (WHERE NOT is_direct) AS deps_transitive,
      count(*) FILTER (WHERE is_outdated) AS deps_outdated,
      count(*) FILTER (WHERE policy_result->'allowed' = 'true'::jsonb) AS deps_compliant,
      count(*) FILTER (WHERE policy_result->'allowed' = 'false'::jsonb) AS deps_failing
    FROM project_dependencies
    WHERE project_id = p_project_id AND removed_at IS NULL
  ) d;
$$;

-- ---------------------------------------------------------------------------
-- team_stats_counts — replaces the vulnsResult + pdvSla JS counting in
-- GET /:id/teams/:teamId/stats. vuln_* are over suppressed=false (the vulns fetch
-- filters suppressed=false); SLA is over ALL rows (the pdvSla fetch does NOT filter
-- suppressed) — this asymmetry is intentional and mirrors teams.ts exactly.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.team_stats_counts(
  p_project_ids uuid[],
  p_active_run_ids text[]
)
RETURNS TABLE (
  vuln_total bigint, vuln_critical bigint, vuln_high bigint, vuln_medium bigint, vuln_low bigint,
  sla_on_track bigint, sla_warning bigint, sla_breached bigint, sla_exempt bigint,
  sla_met bigint, sla_resolved_late bigint
)
LANGUAGE sql STABLE AS $$
  SELECT
    count(*) FILTER (WHERE NOT suppressed) AS vuln_total,
    count(*) FILTER (WHERE NOT suppressed AND severity = 'critical') AS vuln_critical,
    count(*) FILTER (WHERE NOT suppressed AND severity = 'high') AS vuln_high,
    count(*) FILTER (WHERE NOT suppressed AND severity = 'medium') AS vuln_medium,
    count(*) FILTER (WHERE NOT suppressed AND severity = 'low') AS vuln_low,
    count(*) FILTER (WHERE sla_status = 'on_track') AS sla_on_track,
    count(*) FILTER (WHERE sla_status = 'warning') AS sla_warning,
    count(*) FILTER (WHERE sla_status = 'breached') AS sla_breached,
    count(*) FILTER (WHERE sla_status = 'exempt') AS sla_exempt,
    count(*) FILTER (WHERE sla_status = 'met') AS sla_met,
    count(*) FILTER (WHERE sla_status = 'resolved_late') AS sla_resolved_late
  FROM project_dependency_vulnerabilities
  WHERE project_id = ANY(p_project_ids)
    AND extraction_run_id = ANY(p_active_run_ids);
$$;

-- ---------------------------------------------------------------------------
-- team_top_vulns — replaces the in-JS top-5 derivation (byDepscore sort + osv dedup +
-- affected-project count) in the same team /stats handler, which read the same unbounded
-- vulns array and was therefore subject to the same truncation. Returns one row per top
-- osv_id: the worst (highest-depscore) critical/high occurrence's depscore + severity +
-- project, plus the affected_project_count computed over ALL severities (suppressed=false).
-- The osv summary/severity enrichment (dependency_vulnerabilities) and project-name lookup
-- stay in TS — both are bounded (<=5 osv_ids / the already-fetched projects list).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.team_top_vulns(
  p_project_ids uuid[],
  p_active_run_ids text[]
)
RETURNS TABLE (
  osv_id text,
  depscore numeric,
  severity text,
  worst_project_id uuid,
  affected_project_count bigint
)
LANGUAGE sql STABLE AS $$
  WITH team_vulns AS (
    SELECT project_id, osv_id, severity, depscore
    FROM project_dependency_vulnerabilities
    WHERE project_id = ANY(p_project_ids)
      AND extraction_run_id = ANY(p_active_run_ids)
      AND suppressed = false
      AND osv_id IS NOT NULL
  ),
  affected AS (
    SELECT osv_id AS oid, count(DISTINCT project_id) AS affected_project_count
    FROM team_vulns
    GROUP BY osv_id
  ),
  ranked AS (
    SELECT tv.osv_id, tv.severity, tv.depscore, tv.project_id,
           row_number() OVER (PARTITION BY tv.osv_id ORDER BY tv.depscore DESC NULLS LAST) AS rn
    FROM team_vulns tv
    WHERE tv.severity IN ('critical', 'high')
  )
  SELECT r.osv_id, r.depscore, r.severity, r.project_id AS worst_project_id, a.affected_project_count
  FROM ranked r
  JOIN affected a ON a.oid = r.osv_id
  WHERE r.rn = 1
  ORDER BY r.depscore DESC NULLS LAST
  LIMIT 5;
$$;
