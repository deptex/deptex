-- phase51: security_summary_counts — count ALL finding types in the band pills, not just SCA
--
-- The org + team /security-summary projects tables render band_critical/high/medium/low as the
-- per-project severity pills. phase47/48 only counted project_dependency_vulnerabilities (SCA) in
-- those bands, so a project whose SCA vulns are mostly auto-ignored (unreachable) showed e.g.
-- "1 low + 1 medium" even when it had critical IaC, exploited DAST, exposed secrets, etc. The pills
-- badly undercounted vs. the findings table, which loads all 7 finding types.
--
-- This replaces the function so the band counts fold in EVERY finding type, each by its own
-- open/auto-ignore rule (mirroring VulnerabilityExpandableTable.autoTriageRow) and banded by
-- normalised severity:
--   SCA (PDV)  -> open (reachable, not suppressed), depscore band  (unchanged from phase48)
--   IaC        -> security-critical rules only (privileged/host-ns/hostPath set, or HIGH/CRITICAL
--                 Dockerfile findings); the hardening tail is set aside
--   Container  -> KEV only (base-image CVEs are remediated by upgrading the image, not counted)
--   DAST       -> exploited or high/critical, deduped by (handler, line, vuln type)
--   Secret     -> always shown (verified -> critical, else high)
--   Semgrep    -> all open (ERROR->high, WARNING->medium, INFO->low)
--   Malicious  -> not suppressed / risk-accepted
-- Everything else (vuln_count, ignored_count, semgrep/secret counts, has_*) is unchanged.

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
    -- Bands now sum every finding type's open count.
    COALESCE(v.band_critical, 0) + COALESCE(iac.crit, 0) + COALESCE(cont.crit, 0)
      + COALESCE(dast.crit, 0) + COALESCE(sec.crit, 0) + COALESCE(sg.crit, 0) + COALESCE(mal.crit, 0) AS band_critical,
    COALESCE(v.band_high, 0) + COALESCE(iac.high, 0) + COALESCE(cont.high, 0)
      + COALESCE(dast.high, 0) + COALESCE(sec.high, 0) + COALESCE(sg.high, 0) + COALESCE(mal.high, 0) AS band_high,
    COALESCE(v.band_medium, 0) + COALESCE(iac.med, 0) + COALESCE(cont.med, 0)
      + COALESCE(dast.med, 0) + COALESCE(sec.med, 0) + COALESCE(sg.med, 0) + COALESCE(mal.med, 0) AS band_medium,
    COALESCE(v.band_low, 0) + COALESCE(iac.low, 0) + COALESCE(cont.low, 0)
      + COALESCE(dast.low, 0) + COALESCE(sec.low, 0) + COALESCE(sg.low, 0) + COALESCE(mal.low, 0) AS band_low,
    COALESCE(ig.ignored_count, 0) AS ignored_count,
    COALESCE(sgc.semgrep_count, 0) AS semgrep_count,
    COALESCE(secc.secret_count, 0) AS secret_count,
    COALESCE(secc.verified_secret_count, 0) AS verified_secret_count,
    COALESCE(c.has_container, false) AS has_container,
    COALESCE(d.has_dast, false) AS has_dast,
    sj.last_scan_at AS last_scan_at
  FROM unnest(p_project_ids) AS p(id)
  -- SCA (PDV): open rows banded by depscore (unchanged from phase48).
  LEFT JOIN LATERAL (
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
  -- SCA ignored (suppressed OR auto-ignored). Unchanged.
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
  -- IaC: security-critical misconfigs only (the hardening tail is auto-ignored).
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE b = 'critical') AS crit,
      count(*) FILTER (WHERE b = 'high') AS high,
      count(*) FILTER (WHERE b = 'medium') AS med,
      count(*) FILTER (WHERE b = 'low') AS low
    FROM (
      SELECT CASE lower(COALESCE(f.severity, ''))
               WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high'
               WHEN 'medium' THEN 'medium' WHEN 'moderate' THEN 'medium'
               WHEN 'low' THEN 'low' ELSE 'low' END AS b
      FROM project_iac_findings f
      WHERE f.project_id = p.id
        AND f.extraction_run_id = ANY(p_active_run_ids)
        AND COALESCE(f.suppressed, false) = false
        AND COALESCE(f.risk_accepted, false) = false
        AND (
          upper(f.rule_id) IN (
            'CKV_K8S_16','CKV_K8S_17','CKV_K8S_18','CKV_K8S_19','CKV_K8S_20','CKV_K8S_23',
            'KSV-0023','KSV023','AVD-KSV-0023','KSV-0121'
          )
          OR (f.framework = 'dockerfile' AND lower(COALESCE(f.severity, '')) IN ('high', 'critical'))
        )
    ) q
  ) iac ON true
  -- Container: KEV base-image CVEs only.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE b = 'critical') AS crit,
      count(*) FILTER (WHERE b = 'high') AS high,
      count(*) FILTER (WHERE b = 'medium') AS med,
      count(*) FILTER (WHERE b = 'low') AS low
    FROM (
      SELECT CASE lower(COALESCE(pcf.severity, ''))
               WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high'
               WHEN 'medium' THEN 'medium' WHEN 'low' THEN 'low' ELSE 'low' END AS b
      FROM project_container_findings pcf
      WHERE pcf.project_id = p.id
        AND pcf.extraction_run_id = ANY(p_active_run_ids)
        AND pcf.is_kev = true
        AND COALESCE(pcf.suppressed, false) = false
    ) q
  ) cont ON true
  -- DAST: exploited or high/critical, deduped by (handler, line, vuln type) on the latest run.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE b = 'critical') AS crit,
      count(*) FILTER (WHERE b = 'high') AS high,
      count(*) FILTER (WHERE b = 'medium') AS med,
      count(*) FILTER (WHERE b = 'low') AS low
    FROM (
      SELECT CASE
               WHEN bool_or(lower(COALESCE(df.severity, '')) = 'critical') THEN 'critical'
               WHEN bool_or(lower(COALESCE(df.severity, '')) = 'high') THEN 'high'
               WHEN bool_or(lower(COALESCE(df.severity, '')) = 'medium') THEN 'medium'
               ELSE 'low' END AS b
      FROM project_dast_findings df
      WHERE df.project_id = p.id
        AND COALESCE(df.status, 'open') = 'open'
        AND df.dast_run_id = (
          SELECT df2.dast_run_id FROM project_dast_findings df2
          WHERE df2.project_id = p.id ORDER BY df2.created_at DESC LIMIT 1
        )
        AND (
          (df.payload_redacted IS NOT NULL AND btrim(df.payload_redacted) <> '')
          OR lower(COALESCE(df.severity, '')) IN ('high', 'critical')
        )
      GROUP BY df.handler_file_path, df.handler_line, df.vulnerability_type
    ) q
  ) dast ON true
  -- Secrets: always shown (verified -> critical, else high).
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE psf.is_verified) AS crit,
      count(*) FILTER (WHERE NOT psf.is_verified) AS high,
      0 AS med, 0 AS low
    FROM project_secret_findings psf
    WHERE psf.project_id = p.id AND psf.extraction_run_id = ANY(p_active_run_ids)
  ) sec ON true
  -- Semgrep: all findings, by severity (ERROR->high, WARNING->medium, INFO->low).
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE b = 'critical') AS crit,
      count(*) FILTER (WHERE b = 'high') AS high,
      count(*) FILTER (WHERE b = 'medium') AS med,
      count(*) FILTER (WHERE b = 'low') AS low
    FROM (
      SELECT CASE lower(COALESCE(sf.severity, ''))
               WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high' WHEN 'error' THEN 'high'
               WHEN 'medium' THEN 'medium' WHEN 'warning' THEN 'medium'
               ELSE 'low' END AS b
      FROM project_semgrep_findings sf
      WHERE sf.project_id = p.id AND sf.extraction_run_id = ANY(p_active_run_ids)
    ) q
  ) sg ON true
  -- Malicious packages: not suppressed / risk-accepted.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE b = 'critical') AS crit,
      count(*) FILTER (WHERE b = 'high') AS high,
      count(*) FILTER (WHERE b = 'medium') AS med,
      count(*) FILTER (WHERE b = 'low') AS low
    FROM (
      SELECT CASE lower(COALESCE(pmf.severity, ''))
               WHEN 'critical' THEN 'critical' WHEN 'high' THEN 'high'
               WHEN 'medium' THEN 'medium' WHEN 'low' THEN 'low' ELSE 'high' END AS b
      FROM project_malicious_findings pmf
      WHERE pmf.project_id = p.id
        AND pmf.extraction_run_id = ANY(p_active_run_ids)
        AND COALESCE(pmf.suppressed, false) = false
        AND COALESCE(pmf.risk_accepted, false) = false
    ) q
  ) mal ON true
  -- Unchanged supplementary counts + flags.
  LEFT JOIN LATERAL (
    SELECT count(*) AS semgrep_count
    FROM project_semgrep_findings sf
    WHERE sf.project_id = p.id AND sf.extraction_run_id = ANY(p_active_run_ids)
  ) sgc ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS secret_count,
           count(*) FILTER (WHERE psf.is_verified) AS verified_secret_count
    FROM project_secret_findings psf
    WHERE psf.project_id = p.id AND psf.extraction_run_id = ANY(p_active_run_ids)
  ) secc ON true
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
