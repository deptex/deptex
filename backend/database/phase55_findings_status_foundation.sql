-- phase55: findings-status foundation
--
-- Collapses the three-way auto-triage drift (frontend autoTriageRow, backend
-- finding-triage.ts, the phase54 count SQL) into ONE stored source: a per-row
-- `auto_ignored` verdict + a stable `finding_key` handle, computed in SQL and
-- BACKFILLED by this migration itself so every existing row is correct the
-- instant it applies (no rollout window). The frozen contract these helpers
-- mirror lives in backend/src/lib/findings/triage-golden-master.ts.
--
-- One transaction. Order matters: columns -> helper functions -> backfill ->
-- legacy->status -> the simplified security_summary_counts (LAST, so the
-- column is populated before the new RPC body becomes visible). CONCURRENTLY
-- indexes can't run in a txn — they live in phase55b.

BEGIN;

-- ---------------------------------------------------------------------------
-- 1. Columns. `status` is new only on malicious; the unified status/ignore/
--    auto-ignore columns are added everywhere (taint_flow stays out of the
--    unified model — it keeps its flow_signature_hash suppression).
-- ---------------------------------------------------------------------------
ALTER TABLE project_malicious_findings ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'open';

-- DAST has a status CHECK with its own vocabulary (open/suppressed/risk_accepted/
-- fixed). Admit the unified 'ignored'/'resolved' so the status endpoint can write
-- them, while keeping the legacy values valid (existing dast.ts writers + rows).
ALTER TABLE project_dast_findings DROP CONSTRAINT IF EXISTS project_dast_findings_status_check;
ALTER TABLE project_dast_findings ADD CONSTRAINT project_dast_findings_status_check
  CHECK (status = ANY (ARRAY['open','suppressed','risk_accepted','fixed','ignored','resolved']));

DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY[
    'project_dependency_vulnerabilities',
    'project_secret_findings',
    'project_semgrep_findings',
    'project_dast_findings',
    'project_iac_findings',
    'project_container_findings',
    'project_malicious_findings'
  ] LOOP
    EXECUTE format('ALTER TABLE %I
      ADD COLUMN IF NOT EXISTS finding_key text,
      ADD COLUMN IF NOT EXISTS ignore_reason text,
      ADD COLUMN IF NOT EXISTS ignore_note text,
      ADD COLUMN IF NOT EXISTS ignored_by uuid,
      ADD COLUMN IF NOT EXISTS ignored_at timestamptz,
      ADD COLUMN IF NOT EXISTS auto_ignored boolean NOT NULL DEFAULT false,
      ADD COLUMN IF NOT EXISTS auto_ignore_reason text,
      ADD COLUMN IF NOT EXISTS resolved_at timestamptz', t);
  END LOOP;
END $$;

-- Write-only audit log of manual status changes (no v1 reader — the MTTR/events
-- surface is PR-B). Created here so the status endpoint can INSERT into it.
CREATE TABLE IF NOT EXISTS project_finding_status_events (
  id uuid NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  finding_type text NOT NULL,
  finding_key text NOT NULL,
  finding_id uuid,
  from_status text,
  to_status text NOT NULL,
  reason text,
  note text,
  actor_user_id uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_finding_status_events_project
  ON project_finding_status_events (project_id, finding_type, finding_key);

-- ---------------------------------------------------------------------------
-- 2. Helper functions (the single source the worker + readers + backfill share).
-- ---------------------------------------------------------------------------

-- Stable, denormalized finding handle. NOT a carry-forward join key (the
-- existing per-type joins are untouched) — it's the identity used by the status
-- endpoint and future tracker/event references. Parts are lowercased, null->''
-- and joined with the unit separator; order is preserved deterministically.
CREATE OR REPLACE FUNCTION compute_finding_key(p_parts text[])
RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT encode(
    sha256(convert_to(
      (SELECT string_agg(lower(coalesce(x.val, '')), E'\x1F' ORDER BY x.ord)
       FROM unnest(p_parts) WITH ORDINALITY AS x(val, ord)),
      'UTF8'
    )),
    'hex'
  );
$$;

-- IaC criticality, frozen from iacRuleInfo() (infra-format.ts). Per-rule entries
-- win by exact (case-sensitive) match; unmapped rules fall back to severity.
-- A critical rule stays Open; the hardening tail is auto-ignored. NOTE: this is
-- faithful to the TS truth, NOT phase54's narrow IN-list — an unmapped
-- HIGH/CRITICAL rule is now correctly kept Open (the lossy-mirror fix).
CREATE OR REPLACE FUNCTION compute_iac_is_critical(p_rule_id text, p_severity text)
RETURNS boolean LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE
    WHEN p_rule_id IN (
      'CKV_K8S_16','CKV_K8S_20','CKV_K8S_23','CKV_K8S_19','CKV_K8S_17','CKV_K8S_18',
      'KSV-0023','KSV023','AVD-KSV-0023','KSV-0121'
    ) THEN true
    WHEN p_rule_id IN (
      'CKV_K8S_38','CKV_K8S_28','CKV_K8S_37','CKV2_K8S_6','CKV_K8S_31','CKV_K8S_22',
      'CKV_K8S_29','CKV_K8S_14','CKV_K8S_43','CKV_K8S_40','CKV_K8S_13','CKV_K8S_11',
      'CKV_K8S_10','CKV_K8S_12','CKV_K8S_8','CKV_K8S_9','CKV_K8S_21'
    ) THEN false
    ELSE upper(coalesce(p_severity, '')) IN ('HIGH', 'CRITICAL')
  END;
$$;

-- The stored per-row auto-ignore reason (NULL = not auto-ignored, so
-- auto_ignored = reason IS NOT NULL). Mirrors autoTriageRow branch-for-branch.
-- For SCA this is REACHABILITY ONLY — the runtime_confirmed_at override is a
-- read-time concern (a later DAST run can flip it without re-running finalize),
-- so readers apply `auto_ignored AND runtime_confirmed_at IS NULL`.
CREATE OR REPLACE FUNCTION compute_auto_ignore_reason(
  p_type text,
  p_reachability_level text,
  p_is_reachable boolean,
  p_is_kev boolean,
  p_rule_id text,
  p_severity text,
  p_payload_redacted text
) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE p_type
    WHEN 'container' THEN
      CASE WHEN p_is_kev IS TRUE THEN NULL ELSE 'base_image' END
    WHEN 'iac' THEN
      CASE WHEN compute_iac_is_critical(p_rule_id, p_severity) THEN NULL ELSE 'iac_hardening' END
    WHEN 'dast' THEN
      CASE
        WHEN (p_payload_redacted IS NOT NULL AND btrim(p_payload_redacted) <> '')
          OR lower(coalesce(p_severity, '')) IN ('high', 'critical') THEN NULL
        ELSE 'passive_hygiene'
      END
    WHEN 'vulnerability' THEN
      CASE
        WHEN lower(coalesce(p_reachability_level, '')) IN ('confirmed', 'data_flow') THEN NULL
        WHEN lower(coalesce(p_reachability_level, '')) = 'unreachable' OR p_is_reachable IS FALSE THEN 'not_reachable'
        WHEN lower(coalesce(p_reachability_level, '')) = 'module' THEN 'unconfirmed_reachable'
        ELSE NULL
      END
    ELSE NULL  -- secret / semgrep / malicious / taint_flow are never auto-ignored
  END;
$$;

-- ---------------------------------------------------------------------------
-- 3. Backfill finding_key + auto_ignored/auto_ignore_reason for ALL rows
--    (active + previous + any). Set-based; idempotent.
-- ---------------------------------------------------------------------------

-- SCA: dep_name via correlated subquery (LEFT-join semantics; null->'' in hash).
UPDATE project_dependency_vulnerabilities pdv SET
  finding_key = compute_finding_key(ARRAY[
    (SELECT pd.name FROM project_dependencies pd WHERE pd.id = pdv.project_dependency_id),
    pdv.osv_id
  ]),
  auto_ignore_reason = compute_auto_ignore_reason('vulnerability', pdv.reachability_level, pdv.is_reachable, NULL, NULL, NULL, NULL),
  auto_ignored = compute_auto_ignore_reason('vulnerability', pdv.reachability_level, pdv.is_reachable, NULL, NULL, NULL, NULL) IS NOT NULL;

-- Secret: never auto-ignored; just the handle.
UPDATE project_secret_findings SET
  finding_key = compute_finding_key(ARRAY[detector_type, file_path, redacted_value]);

-- Semgrep: never auto-ignored.
UPDATE project_semgrep_findings SET
  finding_key = compute_finding_key(ARRAY[
    coalesce(semgrep_fingerprint, concat_ws('|', rule_id, file_path, start_line::text))
  ]);

-- DAST: handler-mode vs endpoint-mode handle (matches commit_dast_target_run).
UPDATE project_dast_findings SET
  finding_key = compute_finding_key(ARRAY[
    rule_id,
    vulnerability_type,
    CASE WHEN handler_file_path IS NOT NULL
         THEN concat_ws('|', handler_file_path, handler_function_name)
         ELSE concat_ws('|', endpoint_url, http_method) END
  ]),
  auto_ignore_reason = compute_auto_ignore_reason('dast', NULL, NULL, NULL, NULL, severity, payload_redacted),
  auto_ignored = compute_auto_ignore_reason('dast', NULL, NULL, NULL, NULL, severity, payload_redacted) IS NOT NULL;

-- IaC: fingerprint handle (scanner+rule+file+line fallback).
UPDATE project_iac_findings SET
  finding_key = compute_finding_key(ARRAY[
    coalesce(iac_fingerprint, concat_ws('|', scanner, rule_id, file_path, start_line_key::text))
  ]),
  auto_ignore_reason = compute_auto_ignore_reason('iac', NULL, NULL, NULL, rule_id, severity, NULL),
  auto_ignored = compute_auto_ignore_reason('iac', NULL, NULL, NULL, rule_id, severity, NULL) IS NOT NULL;

-- Container: fingerprint handle (image+osv fallback). Per-row verdict only —
-- the base-image GROUPING stays a presentation concern in the count RPC.
UPDATE project_container_findings SET
  finding_key = compute_finding_key(ARRAY[
    coalesce(container_fingerprint, concat_ws('|', image_reference, coalesce(osv_id, cve_id, os_package_name)))
  ]),
  auto_ignore_reason = compute_auto_ignore_reason('container', NULL, NULL, is_kev, NULL, NULL, NULL),
  auto_ignored = compute_auto_ignore_reason('container', NULL, NULL, is_kev, NULL, NULL, NULL) IS NOT NULL;

-- Malicious: never auto-ignored; dep_name via correlated subquery.
UPDATE project_malicious_findings pmf SET
  finding_key = compute_finding_key(ARRAY[
    (SELECT pd.name FROM project_dependencies pd WHERE pd.id = pmf.project_dependency_id),
    pmf.rule_id,
    pmf.scanner
  ]);

-- ---------------------------------------------------------------------------
-- 4. Legacy disposition -> unified status. Idempotent. Carries the legacy
--    actor/reason into the new ignore_* columns where derivable.
-- ---------------------------------------------------------------------------
UPDATE project_dependency_vulnerabilities SET
  status = 'ignored',
  ignore_reason = CASE WHEN risk_accepted THEN 'accepted_risk' ELSE ignore_reason END,
  ignore_note = coalesce(ignore_note, risk_accepted_reason),
  ignored_by = coalesce(ignored_by, risk_accepted_by, suppressed_by),
  ignored_at = coalesce(ignored_at, risk_accepted_at, suppressed_at)
WHERE (coalesce(suppressed, false) OR coalesce(risk_accepted, false)) AND status <> 'ignored';

UPDATE project_iac_findings SET
  status = 'ignored',
  ignore_reason = CASE WHEN risk_accepted THEN 'accepted_risk' ELSE ignore_reason END,
  ignore_note = coalesce(ignore_note, risk_accepted_reason),
  ignored_by = coalesce(ignored_by, risk_accepted_by, suppressed_by),
  ignored_at = coalesce(ignored_at, risk_accepted_at, suppressed_at)
WHERE (coalesce(suppressed, false) OR coalesce(risk_accepted, false)) AND status <> 'ignored';

UPDATE project_container_findings SET
  status = 'ignored',
  ignore_reason = CASE WHEN risk_accepted THEN 'accepted_risk' ELSE ignore_reason END,
  ignore_note = coalesce(ignore_note, risk_accepted_reason),
  ignored_by = coalesce(ignored_by, risk_accepted_by, suppressed_by),
  ignored_at = coalesce(ignored_at, risk_accepted_at, suppressed_at)
WHERE (coalesce(suppressed, false) OR coalesce(risk_accepted, false)) AND status <> 'ignored';

-- DAST keeps its native status vocabulary (open/suppressed/risk_accepted/fixed):
-- any non-'open' value already means hidden, so the count RPC's `status='open'`
-- filter handles it and no legacy remap is needed. The status endpoint writes the
-- unified 'ignored'/'open' going forward (now admitted by the expanded CHECK). We
-- only carry the risk-accept actor/reason into the new ignore_* columns.
UPDATE project_dast_findings SET
  ignore_reason = CASE WHEN risk_accepted_at IS NOT NULL THEN 'accepted_risk' ELSE ignore_reason END,
  ignore_note = coalesce(ignore_note, risk_accepted_reason),
  ignored_by = coalesce(ignored_by, risk_accepted_by),
  ignored_at = coalesce(ignored_at, risk_accepted_at)
WHERE risk_accepted_at IS NOT NULL;

-- Malicious: suppressed/risk-accepted -> ignored, EXCLUDING the auto, run-scoped
-- allowlist suppressions (those are managed by the is_malicious recompute path,
-- not a sticky manual ignore). Manual malicious ignore carry-forward is PR-B.
UPDATE project_malicious_findings SET
  status = 'ignored',
  ignore_reason = CASE WHEN risk_accepted THEN 'accepted_risk' ELSE ignore_reason END,
  ignore_note = coalesce(ignore_note, risk_accepted_reason, suppressed_reason),
  ignored_by = coalesce(ignored_by, risk_accepted_by, suppressed_by),
  ignored_at = coalesce(ignored_at, risk_accepted_at, suppressed_at)
WHERE (coalesce(suppressed, false) OR coalesce(risk_accepted, false))
  AND coalesce(suppressed_reason, '') NOT LIKE 'allowlist:%'
  AND status <> 'ignored';

-- ---------------------------------------------------------------------------
-- 5. Simplified security_summary_counts (LAST statement). Reads the stored
--    auto_ignored + manual status instead of re-deriving triage. Per-type
--    run-scoping and the container/DAST grouping are preserved (the grouping is
--    a presentation concern, explicitly out of the v1 zero-drift guarantee).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION security_summary_counts(
  p_project_ids uuid[],
  p_active_run_ids text[]
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
  -- SCA (PDV): open = not manually ignored/resolved/suppressed AND not
  -- auto-ignored (with the PDV runtime override). Banded by eff_score.
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
        (
          COALESCE(pdv.suppressed, false) = false
          AND COALESCE(pdv.risk_accepted, false) = false
          AND NOT (pdv.auto_ignored AND pdv.runtime_confirmed_at IS NULL)
        ) AS is_open
      FROM project_dependency_vulnerabilities pdv
      WHERE pdv.project_id = p.id
        AND pdv.extraction_run_id = ANY(p_active_run_ids)
        AND pdv.status NOT IN ('ignored', 'resolved')
    ) r
  ) v ON true
  -- SCA ignored (manual status, legacy suppressed/risk-accepted, or auto-ignored).
  LEFT JOIN LATERAL (
    SELECT count(*) AS ignored_count
    FROM project_dependency_vulnerabilities pdv
    WHERE pdv.project_id = p.id
      AND pdv.extraction_run_id = ANY(p_active_run_ids)
      AND (
        pdv.status = 'ignored'
        OR COALESCE(pdv.suppressed, false) = true
        OR COALESCE(pdv.risk_accepted, false) = true
        OR (pdv.auto_ignored AND pdv.runtime_confirmed_at IS NULL)
      )
  ) ig ON true
  -- IaC: open = stored auto_ignored=false (faithful per-rule verdict, fixing the
  -- phase54 generic-severity drift) AND not manually ignored. Banded by severity.
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
        AND f.status NOT IN ('ignored', 'resolved')
        AND COALESCE(f.suppressed, false) = false
        AND COALESCE(f.risk_accepted, false) = false
        AND f.auto_ignored = false
    ) q
  ) iac ON true
  -- Container: KEV CVEs individually + one "out-of-date base image" row per image
  -- for the non-KEV tail (the per-row members are auto-ignored, but the collapsed
  -- group is one open row). GROUPING preserved — residual, out of the v1 guarantee.
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
        AND pcf.status NOT IN ('ignored', 'resolved')
        AND COALESCE(pcf.suppressed, false) = false
        AND COALESCE(pcf.risk_accepted, false) = false
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
          AND pcf.status NOT IN ('ignored', 'resolved')
          AND COALESCE(pcf.suppressed, false) = false
          AND COALESCE(pcf.risk_accepted, false) = false
        GROUP BY pcf.image_reference
      ) g
    ) q
  ) cont ON true
  -- DAST: open = stored auto_ignored=false (== the passive-vs-active verdict) AND
  -- status open. Family grouping + dastDepscore banding preserved (residual).
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
            AND df.status = 'open'
            AND df.auto_ignored = false
            AND df.dast_run_id = (
              SELECT df2.dast_run_id FROM project_dast_findings df2
              WHERE df2.project_id = p.id ORDER BY df2.created_at DESC LIMIT 1
            )
        ) s
        ORDER BY s.handler_file_path, s.fam, s.canon DESC
      ) g
    ) f
  ) dast ON true
  -- Secrets: open (not manually ignored), banded by stored depscore.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) >= 90) AS crit,
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) >= 70 AND COALESCE(psf.depscore, 0) < 90) AS high,
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) >= 40 AND COALESCE(psf.depscore, 0) < 70) AS med,
      count(*) FILTER (WHERE COALESCE(psf.depscore, 0) < 40) AS low
    FROM project_secret_findings psf
    WHERE psf.project_id = p.id AND psf.extraction_run_id = ANY(p_active_run_ids)
      AND psf.status NOT IN ('ignored', 'resolved')
  ) sec ON true
  -- Semgrep: open (not manually ignored), banded by stored depscore.
  LEFT JOIN LATERAL (
    SELECT
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) >= 90) AS crit,
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) >= 70 AND COALESCE(sf.depscore, 0) < 90) AS high,
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) >= 40 AND COALESCE(sf.depscore, 0) < 70) AS med,
      count(*) FILTER (WHERE COALESCE(sf.depscore, 0) < 40) AS low
    FROM project_semgrep_findings sf
    WHERE sf.project_id = p.id AND sf.extraction_run_id = ANY(p_active_run_ids)
      AND sf.status NOT IN ('ignored', 'resolved')
  ) sg ON true
  -- Malicious packages: not ignored/suppressed/risk-accepted, banded by stored depscore.
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
        AND pmf.status NOT IN ('ignored', 'resolved')
        AND COALESCE(pmf.suppressed, false) = false
        AND COALESCE(pmf.risk_accepted, false) = false
    ) q
  ) mal ON true
  -- First-party data-flow findings (taint_engine, osv_id IS NULL): unchanged.
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
               ELSE 55
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

COMMIT;
