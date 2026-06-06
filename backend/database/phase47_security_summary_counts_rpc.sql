-- phase47: security-summary per-project aggregation RPC
--
-- The org and team /security-summary endpoints previously counted findings by SELECTing every
-- row into Node and counting in JS. PostgREST caps a select at 1000 rows, so past ~1000 findings
-- of a type the band / semgrep / secret / ignored counts were silently truncated and the
-- has_container / has_dast flags became order-dependent. This function does the aggregation in
-- SQL (no row transfer, no cap), keyed by a caller-supplied set of project ids + active run ids.
--
-- Band thresholds mirror backend/src/lib/depscore-bands.ts: COALESCE(contextual_depscore,
-- depscore, 0) -> >=90 critical / >=70 high / >=40 medium / <40 low.

CREATE OR REPLACE FUNCTION security_summary_counts(
  p_project_ids uuid[],
  p_active_run_ids text[]  -- extraction_run_id columns are text, not uuid
)
RETURNS TABLE (
  project_id uuid,
  vuln_count bigint,
  critical_count bigint,
  reachable_count bigint,
  worst_depscore numeric,
  band_critical bigint,
  band_high bigint,
  band_medium bigint,
  band_low bigint,
  ignored_count bigint,
  semgrep_count bigint,
  secret_count bigint,
  verified_secret_count bigint,
  has_container boolean,
  has_dast boolean,
  last_scan_at timestamptz
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    p.id AS project_id,
    COALESCE(v.vuln_count, 0) AS vuln_count,
    COALESCE(v.critical_count, 0) AS critical_count,
    COALESCE(v.reachable_count, 0) AS reachable_count,
    COALESCE(v.worst_depscore, 0) AS worst_depscore,
    COALESCE(v.band_critical, 0) AS band_critical,
    COALESCE(v.band_high, 0) AS band_high,
    COALESCE(v.band_medium, 0) AS band_medium,
    COALESCE(v.band_low, 0) AS band_low,
    COALESCE(ig.ignored_count, 0) AS ignored_count,
    COALESCE(sg.semgrep_count, 0) AS semgrep_count,
    COALESCE(sec.secret_count, 0) AS secret_count,
    COALESCE(sec.verified_secret_count, 0) AS verified_secret_count,
    COALESCE(c.has_container, false) AS has_container,
    COALESCE(d.has_dast, false) AS has_dast,
    sj.last_scan_at AS last_scan_at
  FROM unnest(p_project_ids) AS p(id)
  LEFT JOIN LATERAL (
    SELECT
      count(*) AS vuln_count,
      count(*) FILTER (WHERE pdv.severity = 'critical') AS critical_count,
      count(*) FILTER (WHERE pdv.is_reachable) AS reachable_count,
      max(pdv.depscore) AS worst_depscore,
      count(*) FILTER (WHERE COALESCE(pdv.contextual_depscore, pdv.depscore, 0) >= 90) AS band_critical,
      count(*) FILTER (WHERE COALESCE(pdv.contextual_depscore, pdv.depscore, 0) >= 70
                         AND COALESCE(pdv.contextual_depscore, pdv.depscore, 0) < 90) AS band_high,
      count(*) FILTER (WHERE COALESCE(pdv.contextual_depscore, pdv.depscore, 0) >= 40
                         AND COALESCE(pdv.contextual_depscore, pdv.depscore, 0) < 70) AS band_medium,
      count(*) FILTER (WHERE COALESCE(pdv.contextual_depscore, pdv.depscore, 0) < 40) AS band_low
    FROM project_dependency_vulnerabilities pdv
    WHERE pdv.project_id = p.id
      AND pdv.extraction_run_id = ANY(p_active_run_ids)
      AND pdv.suppressed = false
  ) v ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS ignored_count
    FROM project_dependency_vulnerabilities pdv
    WHERE pdv.project_id = p.id
      AND pdv.extraction_run_id = ANY(p_active_run_ids)
      AND pdv.suppressed = true
  ) ig ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS semgrep_count
    FROM project_semgrep_findings sf
    WHERE sf.project_id = p.id AND sf.extraction_run_id = ANY(p_active_run_ids)
  ) sg ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS secret_count,
           count(*) FILTER (WHERE psf.is_verified) AS verified_secret_count
    FROM project_secret_findings psf
    WHERE psf.project_id = p.id AND psf.extraction_run_id = ANY(p_active_run_ids)
  ) sec ON true
  LEFT JOIN LATERAL (
    SELECT EXISTS (
      SELECT 1 FROM project_container_findings pcf
      WHERE pcf.project_id = p.id AND pcf.extraction_run_id = ANY(p_active_run_ids)
    ) AS has_container
  ) c ON true
  LEFT JOIN LATERAL (
    SELECT (
      EXISTS (SELECT 1 FROM project_dast_targets pdt WHERE pdt.project_id = p.id)
      OR EXISTS (SELECT 1 FROM project_dast_findings pdf WHERE pdf.project_id = p.id)
    ) AS has_dast
  ) d ON true
  LEFT JOIN LATERAL (
    SELECT max(sj2.completed_at) AS last_scan_at
    FROM scan_jobs sj2
    WHERE sj2.project_id = p.id AND sj2.status = 'completed'
  ) sj ON true;
$$;
