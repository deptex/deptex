-- phase48: security_summary_counts — align "issues" vs "ignored" with the frontend auto-triage
--
-- The org + team /security-summary sidebars render the band_* counts as the issue pills and
-- ignored_count as the Ignored column. The findings table (VulnerabilityExpandableTable.autoTriageRow)
-- AUTO-IGNORES findings by reachability — but phase47 counted "ignored" as only suppressed=true and
-- left auto-ignored findings IN the band counts. Result: the pills showed more "issues" than the
-- Open findings view, and Ignored read 0 even when everything was auto-ignored.
--
-- This replaces the function so the SQL mirrors autoTriageRow exactly:
--   A vuln is AUTO-IGNORED when
--     runtime_confirmed_at IS NULL                                  (DAST-confirmed is never set aside)
--     AND lower(reachability_level) NOT IN ('confirmed','data_flow') (strong signals stay visible)
--     AND (lower(reachability_level) IN ('unreachable','module') OR is_reachable = false)
--   (function-level / no-verdict findings stay OPEN.)
--
--   band_critical/high/medium/low + worst_depscore  -> OPEN only (suppressed=false AND NOT auto-ignored)
--   ignored_count                                    -> suppressed = true OR auto-ignored
--   vuln_count / critical_count / reachable_count    -> unchanged (all non-suppressed; other consumers rely on these)
--
-- Band thresholds still mirror backend/src/lib/depscore-bands.ts.

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
    -- Compute is_open once per row (mirrors autoTriageRow), then aggregate. Band counts +
    -- worst_depscore use only OPEN rows; vuln/critical/reachable stay as all non-suppressed.
    SELECT
      count(*) AS vuln_count,
      count(*) FILTER (WHERE r.severity = 'critical') AS critical_count,
      count(*) FILTER (WHERE r.is_reachable) AS reachable_count,
      max(r.depscore) FILTER (WHERE r.is_open) AS worst_depscore,
      count(*) FILTER (WHERE r.is_open AND r.eff_score >= 90) AS band_critical,
      count(*) FILTER (WHERE r.is_open AND r.eff_score >= 70 AND r.eff_score < 90) AS band_high,
      count(*) FILTER (WHERE r.is_open AND r.eff_score >= 40 AND r.eff_score < 70) AS band_medium,
      count(*) FILTER (WHERE r.is_open AND r.eff_score < 40) AS band_low
    FROM (
      SELECT
        pdv.severity,
        pdv.is_reachable,
        pdv.depscore,
        COALESCE(pdv.contextual_depscore, pdv.depscore, 0) AS eff_score,
        NOT (
          pdv.runtime_confirmed_at IS NULL
          AND lower(COALESCE(pdv.reachability_level, '')) NOT IN ('confirmed', 'data_flow')
          AND (lower(COALESCE(pdv.reachability_level, '')) IN ('unreachable', 'module') OR pdv.is_reachable = false)
        ) AS is_open
      FROM project_dependency_vulnerabilities pdv
      WHERE pdv.project_id = p.id
        AND pdv.extraction_run_id = ANY(p_active_run_ids)
        AND pdv.suppressed = false
    ) r
  ) v ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS ignored_count
    FROM project_dependency_vulnerabilities pdv
    WHERE pdv.project_id = p.id
      AND pdv.extraction_run_id = ANY(p_active_run_ids)
      AND (
        pdv.suppressed = true
        OR (
          pdv.runtime_confirmed_at IS NULL
          AND lower(COALESCE(pdv.reachability_level, '')) NOT IN ('confirmed', 'data_flow')
          AND (lower(COALESCE(pdv.reachability_level, '')) IN ('unreachable', 'module') OR pdv.is_reachable = false)
        )
      )
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
