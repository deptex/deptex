-- phase54: count first-party data-flow findings in the band pills
--
-- The unified findings table now surfaces a `taint_flow` row type — first-party
-- taint-engine flows (project_reachable_flows where reachability_source =
-- 'taint_engine' AND osv_id IS NULL): a source→sink path in the user's OWN code,
-- with no dependency CVE. phase52's security_summary_counts banded the other
-- seven types but had no contribution for these, so the preview pills under-
-- counted vs the table.
--
-- This adds a `cf` LATERAL that bands those flows by the vuln_class → depscore
-- map mirrored from backend/src/lib/code-flow-findings.ts (the single source of
-- truth the GET .../code-flow-findings endpoint uses). Confirmed reachable
-- paths, so every flow is "open"; user-suppressed flows (by flow_signature_hash)
-- are excluded the same way the endpoint excludes them.
--
-- NOTE: the band scores below are mirrored from BAND_SCORE + VULN_CLASS_META in
-- code-flow-findings.ts (critical classes → 92, high → 78, everything else → 55).
-- If that map changes, update this CASE too — the permanent fix (store the
-- computed depscore once so both read it) is the findings-status foundation,
-- same caveat as the DAST mirror in phase52.

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
    COALESCE(v.band_critical, 0) + COALESCE(iac.crit, 0) + COALESCE(cont.crit, 0)
      + COALESCE(dast.crit, 0) + COALESCE(sec.crit, 0) + COALESCE(sg.crit, 0) + COALESCE(mal.crit, 0)
      + COALESCE(cf.crit, 0) AS band_critical,
    COALESCE(v.band_high, 0) + COALESCE(iac.high, 0) + COALESCE(cont.high, 0)
      + COALESCE(dast.high, 0) + COALESCE(sec.high, 0) + COALESCE(sg.high, 0) + COALESCE(mal.high, 0)
      + COALESCE(cf.high, 0) AS band_high,
    COALESCE(v.band_medium, 0) + COALESCE(iac.med, 0) + COALESCE(cont.med, 0)
      + COALESCE(dast.med, 0) + COALESCE(sec.med, 0) + COALESCE(sg.med, 0) + COALESCE(mal.med, 0)
      + COALESCE(cf.med, 0) AS band_medium,
    COALESCE(v.band_low, 0) + COALESCE(iac.low, 0) + COALESCE(cont.low, 0)
      + COALESCE(dast.low, 0) + COALESCE(sec.low, 0) + COALESCE(sg.low, 0) + COALESCE(mal.low, 0)
      + COALESCE(cf.low, 0) AS band_low,
    COALESCE(ig.ignored_count, 0) AS ignored_count,
    COALESCE(sgc.semgrep_count, 0) AS semgrep_count,
    COALESCE(secc.secret_count, 0) AS secret_count,
    COALESCE(secc.verified_secret_count, 0) AS verified_secret_count,
    COALESCE(c.has_container, false) AS has_container,
    COALESCE(d.has_dast, false) AS has_dast,
    sj.last_scan_at AS last_scan_at
  FROM unnest(p_project_ids) AS p(id)
  -- SCA (PDV): open rows banded by eff_score (contextual_depscore, else depscore).
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
  -- IaC: security-critical misconfigs only (the hardening tail is auto-ignored). Banded by
  -- severity (iacRuleInfo's per-rule score isn't ported); the open set is the critical rules.
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
  -- Container: KEV base-image CVEs individually (by depscore), PLUS one "out-of-date base
  -- image" row per image with non-KEV CVEs (banded by that image's worst depscore) — mirrors
  -- the frontend collapse to a single Open row.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE b = 'critical') AS crit,
      count(*) FILTER (WHERE b = 'high') AS high,
      count(*) FILTER (WHERE b = 'medium') AS med,
      count(*) FILTER (WHERE b = 'low') AS low
    FROM (
      SELECT CASE
               WHEN COALESCE(pcf.depscore, 0) >= 90 THEN 'critical'
               WHEN COALESCE(pcf.depscore, 0) >= 70 THEN 'high'
               WHEN COALESCE(pcf.depscore, 0) >= 40 THEN 'medium' ELSE 'low' END AS b
      FROM project_container_findings pcf
      WHERE pcf.project_id = p.id
        AND pcf.extraction_run_id = ANY(p_active_run_ids)
        AND pcf.is_kev = true
        AND COALESCE(pcf.suppressed, false) = false
      UNION ALL
      SELECT CASE
               WHEN m >= 90 THEN 'critical' WHEN m >= 70 THEN 'high'
               WHEN m >= 40 THEN 'medium' ELSE 'low' END AS b
      FROM (
        SELECT max(COALESCE(pcf.depscore, 0)) AS m
        FROM project_container_findings pcf
        WHERE pcf.project_id = p.id
          AND pcf.extraction_run_id = ANY(p_active_run_ids)
          AND pcf.is_kev = false
          AND COALESCE(pcf.suppressed, false) = false
        GROUP BY pcf.image_reference
      ) g
    ) q
  ) cont ON true
  -- DAST: open = attack payload OR high/critical severity (mirrors autoTriageRow). Deduped by
  -- (handler, vuln FAMILY) on the latest run — SSTI + reflected/DOM XSS on one handler are one
  -- hole, so they collapse to a single row (dastVulnFamily + dedupeDastRows, ported). The
  -- canonical row per family (highest severity, then most-specific label) is banded by
  -- dastDepscore() ported from backend/src/routes/dast.ts (severity base + confidence + impact
  -- class, floored into the critical band when confirmed-exploitable or KEV). The injected-param
  -- axis of the frontend key is omitted (URL/payload parsing isn't ported) — a rare under-merge.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE ds >= 90) AS crit,
      count(*) FILTER (WHERE ds >= 70 AND ds < 90) AS high,
      count(*) FILTER (WHERE ds >= 40 AND ds < 70) AS med,
      count(*) FILTER (WHERE ds < 40) AS low
    FROM (
      SELECT CASE WHEN g.kev THEN GREATEST(g.ds_raw, 96)
                  WHEN g.exploitable THEN GREATEST(g.ds_raw, 90)
                  ELSE g.ds_raw END AS ds
      FROM (
        SELECT DISTINCT ON (s.handler_file_path, s.fam) s.ds_raw, s.exploitable, s.kev
        FROM (
          SELECT
            df.handler_file_path,
            CASE
              WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.rule_id,'')||' '||COALESCE(df.message,'')) ~ '(sql ?injection|sqli)' THEN 'sqli'
              WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.rule_id,'')||' '||COALESCE(df.message,'')) ~ '(template ?injection|ssti|cross.?site.?script|\yxss\y)' THEN 'output-injection'
              WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.rule_id,'')||' '||COALESCE(df.message,'')) ~ '(path ?traversal|directory ?traversal|local file inclusion|\ylfi\y)' THEN 'path-traversal'
              WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.rule_id,'')||' '||COALESCE(df.message,'')) ~ '(command ?injection|os ?command)' THEN 'command-injection'
              ELSE 'rule:'||lower(COALESCE(df.rule_id, df.vulnerability_type, 'other'))
            END AS fam,
            LEAST(100, GREATEST(0,
              (CASE lower(COALESCE(df.severity, ''))
                 WHEN 'critical' THEN 90 WHEN 'high' THEN 72 WHEN 'medium' THEN 48
                 WHEN 'low' THEN 26 WHEN 'info' THEN 10 ELSE 48 END)
              + (CASE lower(COALESCE(df.confidence, ''))
                   WHEN 'confirmed' THEN 10 WHEN 'high' THEN 6 WHEN 'low' THEN -12 ELSE 0 END)
              + (CASE
                   WHEN lower(COALESCE(df.vulnerability_type, '')) ~ '(sql injection|command injection|code injection|template injection|ldap injection|xpath|path traversal|remote os command|remote code|server side request|ssrf|xxe|xml external|deserial)' THEN 10
                   WHEN lower(COALESCE(df.vulnerability_type, '')) ~ '(cross.?site.?scripting|xss|cross.?site.?request|csrf|open redirect)' THEN 4
                   WHEN lower(COALESCE(df.vulnerability_type, '')) ~ '(header|cache|cookie|csp|content security policy|clickjack|x-powered-by|information disclosure|source code disclosure|strict-transport|spectre|site isolation|storable|cacheable|permissions policy|sec-fetch|mime|x-content-type|charset|timestamp|comment)' THEN -8
                   ELSE 0 END)
            )) AS ds_raw,
            (df.linked_sca_osv_id IS NOT NULL) AS exploitable,
            COALESCE(df.kev, false) AS kev,
            ((CASE lower(COALESCE(df.severity,'')) WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) * 10
             + (CASE
                  WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.message,'')) ~ '(template ?injection|ssti|sql ?injection|sqli|command ?injection)' THEN 3
                  WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.message,'')) ~ '(persistent|stored)' THEN 2
                  WHEN lower(COALESCE(df.vulnerability_type,'')||' '||COALESCE(df.message,'')) ~ '(cross.?site.?script|\yxss\y)' THEN 1
                  ELSE 0 END)) AS canon
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
        ) s
        ORDER BY s.handler_file_path, s.fam, s.canon DESC
      ) g
    ) f
  ) dast ON true
  -- Secrets: all shown (open), banded by stored depscore (matches the table).
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) >= 90) AS crit,
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) >= 70 AND COALESCE(psf.depscore, 0) < 90) AS high,
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) >= 40 AND COALESCE(psf.depscore, 0) < 70) AS med,
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) < 40) AS low
    FROM project_secret_findings psf
    WHERE psf.project_id = p.id AND psf.extraction_run_id = ANY(p_active_run_ids)
  ) sec ON true
  -- Semgrep: all findings, banded by stored depscore (matches the table).
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) >= 90) AS crit,
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) >= 70 AND COALESCE(sf.depscore, 0) < 90) AS high,
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) >= 40 AND COALESCE(sf.depscore, 0) < 70) AS med,
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) < 40) AS low
    FROM project_semgrep_findings sf
    WHERE sf.project_id = p.id AND sf.extraction_run_id = ANY(p_active_run_ids)
  ) sg ON true
  -- Malicious packages: not suppressed / risk-accepted, banded by stored depscore
  -- (crit severity with no stored score -> 95, mirroring the table fallback).
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE ds >= 90) AS crit,
      count(*) FILTER (WHERE ds >= 70 AND ds < 90) AS high,
      count(*) FILTER (WHERE ds >= 40 AND ds < 70) AS med,
      count(*) FILTER (WHERE ds < 40) AS low
    FROM (
      SELECT COALESCE(pmf.depscore, CASE WHEN lower(COALESCE(pmf.severity, '')) = 'critical' THEN 95 ELSE 0 END) AS ds
      FROM project_malicious_findings pmf
      WHERE pmf.project_id = p.id
        AND pmf.extraction_run_id = ANY(p_active_run_ids)
        AND COALESCE(pmf.suppressed, false) = false
        AND COALESCE(pmf.risk_accepted, false) = false
    ) q
  ) mal ON true
  -- First-party data-flow findings: taint-engine source→sink paths in the user's own
  -- code (osv_id IS NULL). Banded by the vuln_class -> depscore map mirrored from
  -- backend/src/lib/code-flow-findings.ts. All are open (confirmed reachable); user-
  -- suppressed flows (by flow_signature_hash) are excluded like the endpoint does.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE ds >= 90) AS crit,
      count(*) FILTER (WHERE ds >= 70 AND ds < 90) AS high,
      count(*) FILTER (WHERE ds >= 40 AND ds < 70) AS med,
      count(*) FILTER (WHERE ds < 40) AS low
    FROM (
      SELECT CASE lower(COALESCE(prf.vuln_class, ''))
               WHEN 'sql_injection' THEN 92
               WHEN 'command_injection' THEN 92
               WHEN 'code_injection' THEN 92
               WHEN 'deserialization' THEN 92
               WHEN 'xss' THEN 78
               WHEN 'ssrf' THEN 78
               WHEN 'path_traversal' THEN 78
               WHEN 'file_upload' THEN 78
               WHEN 'prototype_pollution' THEN 78
               WHEN 'auth_bypass' THEN 78
               ELSE 55  -- open_redirect / redos / log_injection / weak_crypto / unknown
             END AS ds
      FROM project_reachable_flows prf
      WHERE prf.project_id = p.id
        AND prf.extraction_run_id = ANY(p_active_run_ids)
        AND prf.reachability_source = 'taint_engine'
        AND prf.osv_id IS NULL
        AND NOT EXISTS (
          SELECT 1 FROM project_reachable_flow_suppressions s
          WHERE s.project_id = p.id
            AND s.flow_signature_hash = prf.flow_signature_hash
        )
    ) q
  ) cf ON true
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
