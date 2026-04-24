-- Phase 23: Semgrep reachability rules engine
--
-- Phase 3 of the reachability roadmap adds hand-authored, per-CVE Semgrep
-- taint-tracking rules that upgrade matching vulns from heuristic
-- (module/function) to `confirmed` reachability — the highest-priority signal
-- in the depscore pipeline.
--
-- Schema-wise, this re-uses the existing `project_reachable_flows` table
-- (Phase 6b) by making it polymorphic over its source. Atom-derived flows
-- (the existing rows) keep `reachability_source='atom'`. Semgrep taint
-- matches insert with `reachability_source='semgrep_taint'`, a non-NULL
-- `osv_id` so we can attribute the flow to the specific CVE that fired,
-- and a non-NULL `rule_id` carrying the Semgrep rule that matched.
--
-- We deliberately do NOT widen the existing UNIQUE constraint:
--   - Within a single extraction_run_id, Semgrep emits each (rule, file, line)
--     finding at most once, so semgrep_taint rows do not duplicate-collide
--     against each other.
--   - In the rare case a semgrep_taint row shares (purl, entry_point_file,
--     entry_point_line, sink_method) with an atom row, the worker uses
--     `.upsert(..., { ignoreDuplicates: true })` so the atom row wins.
--     We lose the `confirmed` upgrade in that exact collision, but the atom
--     row already proves data flow, so the depscore impact is minor and
--     easily diagnosed via reachability_source telemetry.
--
-- The two new indexes target the read patterns:
--   - (extraction_run_id, reachability_source) — fetch only taint flows when
--     building the (dependency_id, osv_id) → flows map in updateReachabilityLevels
--   - (project_id, extraction_run_id, osv_id) WHERE osv_id IS NOT NULL —
--     attribute a taint flow to the specific PDV it should upgrade.

-- =============================================================================
-- 1. New columns on project_reachable_flows
-- =============================================================================

ALTER TABLE project_reachable_flows
  ADD COLUMN IF NOT EXISTS reachability_source TEXT NOT NULL DEFAULT 'atom';

ALTER TABLE project_reachable_flows
  ADD COLUMN IF NOT EXISTS osv_id TEXT NULL;

ALTER TABLE project_reachable_flows
  ADD COLUMN IF NOT EXISTS rule_id TEXT NULL;

ALTER TABLE project_reachable_flows
  DROP CONSTRAINT IF EXISTS project_reachable_flows_source_chk;

ALTER TABLE project_reachable_flows
  ADD CONSTRAINT project_reachable_flows_source_chk
  CHECK (reachability_source IN ('atom', 'semgrep_taint'));

COMMENT ON COLUMN project_reachable_flows.reachability_source IS
  'Phase 23: source of this flow row. ''atom'' for dep-scan/atom-derived flows (Phase 6b), ''semgrep_taint'' for hand-authored CVE-specific Semgrep taint rules (Phase 3).';

COMMENT ON COLUMN project_reachable_flows.osv_id IS
  'Phase 23: CVE/GHSA identifier the flow attributes to, populated for semgrep_taint rows so updateReachabilityLevels can match a flow to a specific PDV. NULL for atom rows (where the whole dep is implicated).';

COMMENT ON COLUMN project_reachable_flows.rule_id IS
  'Phase 23: Semgrep rule.id (e.g. ''deptex.lodash.template-injection'') for semgrep_taint rows. NULL for atom rows.';

-- =============================================================================
-- 2. Indexes for the new read patterns
-- =============================================================================

CREATE INDEX IF NOT EXISTS idx_prf_run_source
  ON project_reachable_flows(extraction_run_id, reachability_source);

CREATE INDEX IF NOT EXISTS idx_prf_project_run_osv
  ON project_reachable_flows(project_id, extraction_run_id, osv_id)
  WHERE osv_id IS NOT NULL;

-- =============================================================================
-- 3. commit_extraction — extend p_reachable_flows typedef to carry new columns.
--
-- finalize_extraction is the active commit path; commit_extraction is dead
-- code today (kept available for any future JSONB-payload caller per the
-- phase19_3 comment). Updating it here so it stays consistent if it ever
-- gets resurrected.
-- =============================================================================

CREATE OR REPLACE FUNCTION commit_extraction(
  p_job_id UUID,
  p_project_id UUID,
  p_extraction_run_id TEXT,
  p_dependencies JSONB,
  p_vulnerabilities JSONB,
  p_semgrep_findings JSONB,
  p_secret_findings JSONB,
  p_reachable_flows JSONB,
  p_usage_slices JSONB,
  p_dependency_files JSONB,
  p_dependency_functions JSONB
)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_prev_active TEXT;
  v_org_id UUID;
  v_asset_tier_id UUID;
  v_sla_paused BOOLEAN;
  v_rereview_settings JSONB;
  v_triggers JSONB;
  v_enabled BOOLEAN;
  v_deps_inserted INTEGER := 0;
  v_deps_updated INTEGER := 0;
  v_deps_removed INTEGER := 0;
  v_pdv_inserted INTEGER := 0;
  v_pdv_carried INTEGER := 0;
  v_pdv_new INTEGER := 0;
  v_pdv_reopened INTEGER := 0;
  v_pdv_critical_new INTEGER := 0;
  v_pdv_rereview_fired INTEGER := 0;
  v_semgrep_inserted INTEGER := 0;
  v_secret_inserted INTEGER := 0;
  v_sla_set INTEGER := 0;
  v_sla_row RECORD;
  v_sla_hours INTEGER;
  v_sla_warn_pct INTEGER;
  v_now TIMESTAMPTZ := NOW();
  v_reap_result JSONB;
BEGIN
  SELECT p.active_extraction_run_id, p.organization_id, p.asset_tier_id,
         (o.sla_paused_at IS NOT NULL)
    INTO v_prev_active, v_org_id, v_asset_tier_id, v_sla_paused
  FROM projects p
  JOIN organizations o ON o.id = p.organization_id
  WHERE p.id = p_project_id
  FOR UPDATE OF p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_extraction: project % not found', p_project_id;
  END IF;

  SELECT COALESCE(
    oat.rereview_settings,
    '{"enabled": true, "triggers": {"depscore_delta": 5, "severity_escalation": true, "reachability_upgrade": true, "kev_added": true, "epss_delta": 0.1}}'::jsonb
  )
  INTO v_rereview_settings
  FROM projects p
  LEFT JOIN organization_asset_tiers oat ON oat.id = p.asset_tier_id
  WHERE p.id = p_project_id;

  v_enabled := COALESCE((v_rereview_settings->>'enabled')::boolean, true);
  v_triggers := COALESCE(v_rereview_settings->'triggers', '{}'::jsonb);

  WITH input_deps AS (
    SELECT * FROM jsonb_to_recordset(p_dependencies) AS d(
      name TEXT, version TEXT, is_direct BOOLEAN, source TEXT,
      environment TEXT, license TEXT, dependency_id UUID,
      files_importing_count INTEGER, is_outdated BOOLEAN, versions_behind INTEGER,
      policy_result JSONB, dependency_version_id UUID,
      namespace TEXT
    )
  ),
  upserted AS (
    INSERT INTO project_dependencies (
      project_id, name, version, is_direct, source,
      environment, license, dependency_id,
      files_importing_count, is_outdated, versions_behind,
      policy_result, dependency_version_id, namespace,
      last_seen_extraction_run_id, removed_at, created_at
    )
    SELECT
      p_project_id, d.name, d.version, d.is_direct, d.source,
      d.environment, d.license, d.dependency_id,
      COALESCE(d.files_importing_count, 0),
      COALESCE(d.is_outdated, false),
      COALESCE(d.versions_behind, 0),
      d.policy_result, d.dependency_version_id, d.namespace,
      p_extraction_run_id, NULL, v_now
    FROM input_deps d
    ON CONFLICT (project_id, name, version, is_direct, source) DO UPDATE SET
      environment = EXCLUDED.environment,
      license = EXCLUDED.license,
      dependency_id = EXCLUDED.dependency_id,
      files_importing_count = EXCLUDED.files_importing_count,
      is_outdated = EXCLUDED.is_outdated,
      versions_behind = EXCLUDED.versions_behind,
      policy_result = EXCLUDED.policy_result,
      dependency_version_id = EXCLUDED.dependency_version_id,
      namespace = EXCLUDED.namespace,
      last_seen_extraction_run_id = p_extraction_run_id,
      removed_at = NULL
    RETURNING (xmax = 0) AS was_inserted
  )
  SELECT
    COUNT(*) FILTER (WHERE was_inserted),
    COUNT(*) FILTER (WHERE NOT was_inserted)
  INTO v_deps_inserted, v_deps_updated
  FROM upserted;

  UPDATE project_dependencies
  SET removed_at = v_now
  WHERE project_id = p_project_id
    AND removed_at IS NULL
    AND (last_seen_extraction_run_id IS DISTINCT FROM p_extraction_run_id);
  GET DIAGNOSTICS v_deps_removed = ROW_COUNT;

  WITH input_vulns AS (
    SELECT * FROM jsonb_to_recordset(p_vulnerabilities) AS v(
      dep_name TEXT, dep_version TEXT, dep_is_direct BOOLEAN, dep_source TEXT,
      osv_id TEXT, severity TEXT, summary TEXT,
      aliases TEXT[], fixed_versions TEXT[],
      is_reachable BOOLEAN, epss_score NUMERIC, cvss_score NUMERIC,
      cisa_kev BOOLEAN, depscore INTEGER, published_at TIMESTAMPTZ,
      reachability_level TEXT, reachability_details JSONB,
      base_depscore_no_reachability NUMERIC, epd_factor NUMERIC,
      contextual_depscore NUMERIC, reachability_status TEXT, epd_confidence_tier TEXT
    )
  )
  INSERT INTO project_dependency_vulnerabilities (
    project_id, project_dependency_id, osv_id, severity, summary,
    aliases, fixed_versions, is_reachable, epss_score, cvss_score,
    cisa_kev, depscore, published_at,
    reachability_level, reachability_details,
    base_depscore_no_reachability, epd_factor, contextual_depscore,
    reachability_status, epd_confidence_tier,
    extraction_run_id, detected_at, created_at, status
  )
  SELECT
    p_project_id, pd.id, v.osv_id, v.severity, v.summary,
    v.aliases, v.fixed_versions,
    COALESCE(v.is_reachable, true),
    v.epss_score, v.cvss_score,
    COALESCE(v.cisa_kev, false),
    v.depscore, v.published_at,
    v.reachability_level, v.reachability_details,
    v.base_depscore_no_reachability, v.epd_factor, v.contextual_depscore,
    v.reachability_status, v.epd_confidence_tier,
    p_extraction_run_id, v_now, v_now, 'open'
  FROM input_vulns v
  JOIN project_dependencies pd
    ON pd.project_id = p_project_id
   AND pd.name = v.dep_name
   AND pd.version = v.dep_version
   AND pd.is_direct = COALESCE(v.dep_is_direct, false)
   AND pd.source = v.dep_source
   AND pd.last_seen_extraction_run_id = p_extraction_run_id;
  GET DIAGNOSTICS v_pdv_inserted = ROW_COUNT;

  INSERT INTO project_semgrep_findings (
    project_id, extraction_run_id, rule_id, file_path, start_line, end_line,
    severity, message, cwe_ids, owasp_ids, category, metadata,
    semgrep_fingerprint, status, created_at
  )
  SELECT
    p_project_id, p_extraction_run_id, s.rule_id, s.file_path, s.start_line, s.end_line,
    s.severity, s.message, s.cwe_ids, s.owasp_ids, s.category, s.metadata,
    s.semgrep_fingerprint, 'open', v_now
  FROM jsonb_to_recordset(p_semgrep_findings) AS s(
    rule_id TEXT, file_path TEXT, start_line INTEGER, end_line INTEGER,
    severity TEXT, message TEXT, cwe_ids TEXT[], owasp_ids TEXT[],
    category TEXT, metadata JSONB, semgrep_fingerprint TEXT
  );
  GET DIAGNOSTICS v_semgrep_inserted = ROW_COUNT;

  INSERT INTO project_secret_findings (
    project_id, extraction_run_id, detector_type, file_path, start_line,
    is_verified, description, redacted_value, status, created_at
  )
  SELECT
    p_project_id, p_extraction_run_id, sf.detector_type, sf.file_path, sf.start_line,
    COALESCE(sf.is_verified, false), sf.description, sf.redacted_value, 'open', v_now
  FROM jsonb_to_recordset(p_secret_findings) AS sf(
    detector_type TEXT, file_path TEXT, start_line INTEGER,
    is_verified BOOLEAN, description TEXT, redacted_value TEXT
  );
  GET DIAGNOSTICS v_secret_inserted = ROW_COUNT;

  -- Phase 23: extend p_reachable_flows typedef with reachability_source/osv_id/rule_id
  INSERT INTO project_reachable_flows (
    project_id, extraction_run_id, purl, dependency_id, flow_nodes,
    entry_point_file, entry_point_method, entry_point_line, entry_point_tag,
    sink_file, sink_method, sink_line, sink_is_external, flow_length, llm_prompt,
    reachability_source, osv_id, rule_id, created_at
  )
  SELECT
    p_project_id, p_extraction_run_id, rf.purl, rf.dependency_id, rf.flow_nodes,
    rf.entry_point_file, rf.entry_point_method, rf.entry_point_line, rf.entry_point_tag,
    rf.sink_file, rf.sink_method, rf.sink_line,
    COALESCE(rf.sink_is_external, true), rf.flow_length, rf.llm_prompt,
    COALESCE(rf.reachability_source, 'atom'), rf.osv_id, rf.rule_id, v_now
  FROM jsonb_to_recordset(p_reachable_flows) AS rf(
    purl TEXT, dependency_id UUID, flow_nodes JSONB,
    entry_point_file TEXT, entry_point_method TEXT, entry_point_line INTEGER, entry_point_tag TEXT,
    sink_file TEXT, sink_method TEXT, sink_line INTEGER, sink_is_external BOOLEAN,
    flow_length INTEGER, llm_prompt TEXT,
    reachability_source TEXT, osv_id TEXT, rule_id TEXT
  );

  INSERT INTO project_usage_slices (
    project_id, extraction_run_id, file_path, line_number, containing_method,
    target_name, target_type, resolved_method, usage_label, ecosystem, created_at
  )
  SELECT
    p_project_id, p_extraction_run_id, u.file_path, u.line_number, u.containing_method,
    u.target_name, u.target_type, u.resolved_method, u.usage_label, u.ecosystem, v_now
  FROM jsonb_to_recordset(p_usage_slices) AS u(
    file_path TEXT, line_number INTEGER, containing_method TEXT,
    target_name TEXT, target_type TEXT, resolved_method TEXT,
    usage_label TEXT, ecosystem TEXT
  );

  INSERT INTO project_dependency_files (
    project_dependency_id, file_path, extraction_run_id, created_at
  )
  SELECT pd.id, df.file_path, p_extraction_run_id, v_now
  FROM jsonb_to_recordset(p_dependency_files) AS df(
    dep_name TEXT, dep_version TEXT, dep_is_direct BOOLEAN, dep_source TEXT, file_path TEXT
  )
  JOIN project_dependencies pd
    ON pd.project_id = p_project_id
   AND pd.name = df.dep_name
   AND pd.version = df.dep_version
   AND pd.is_direct = COALESCE(df.dep_is_direct, false)
   AND pd.source = df.dep_source
   AND pd.last_seen_extraction_run_id = p_extraction_run_id;

  INSERT INTO project_dependency_functions (
    project_dependency_id, function_name, extraction_run_id, created_at
  )
  SELECT pd.id, dfn.function_name, p_extraction_run_id, v_now
  FROM jsonb_to_recordset(p_dependency_functions) AS dfn(
    dep_name TEXT, dep_version TEXT, dep_is_direct BOOLEAN, dep_source TEXT, function_name TEXT
  )
  JOIN project_dependencies pd
    ON pd.project_id = p_project_id
   AND pd.name = dfn.dep_name
   AND pd.version = dfn.dep_version
   AND pd.is_direct = COALESCE(dfn.dep_is_direct, false)
   AND pd.source = dfn.dep_source
   AND pd.last_seen_extraction_run_id = p_extraction_run_id;

  IF v_prev_active IS NOT NULL THEN
    WITH carried AS (
      UPDATE project_dependency_vulnerabilities new_pdv
      SET
        status = old_data.status,
        suppressed = old_data.suppressed,
        suppressed_by = old_data.suppressed_by,
        suppressed_at = old_data.suppressed_at,
        risk_accepted = old_data.risk_accepted,
        risk_accepted_by = old_data.risk_accepted_by,
        risk_accepted_at = old_data.risk_accepted_at,
        risk_accepted_reason = old_data.risk_accepted_reason,
        detected_at = COALESCE(old_data.detected_at, new_pdv.detected_at),
        sla_status = old_data.sla_status,
        sla_deadline_at = old_data.sla_deadline_at,
        sla_warning_at = old_data.sla_warning_at,
        sla_breached_at = old_data.sla_breached_at,
        sla_met_at = old_data.sla_met_at,
        sla_exempt_reason = old_data.sla_exempt_reason,
        sla_warning_notified_at = old_data.sla_warning_notified_at,
        sla_breach_notified_at = old_data.sla_breach_notified_at,
        re_review_triggered_at = old_data.re_review_triggered_at,
        re_review_reasons = old_data.re_review_reasons
      FROM (
        SELECT DISTINCT ON (npd.id, opdv.osv_id)
          npd.id AS new_pd_id,
          opdv.osv_id,
          opdv.status, opdv.suppressed, opdv.suppressed_by, opdv.suppressed_at,
          opdv.risk_accepted, opdv.risk_accepted_by, opdv.risk_accepted_at, opdv.risk_accepted_reason,
          opdv.detected_at,
          opdv.sla_status, opdv.sla_deadline_at, opdv.sla_warning_at,
          opdv.sla_breached_at, opdv.sla_met_at, opdv.sla_exempt_reason,
          opdv.sla_warning_notified_at, opdv.sla_breach_notified_at,
          opdv.re_review_triggered_at, opdv.re_review_reasons
        FROM project_dependency_vulnerabilities opdv
        JOIN project_dependencies opd ON opd.id = opdv.project_dependency_id
        JOIN project_dependencies npd
          ON npd.project_id = opd.project_id
         AND npd.name = opd.name
         AND npd.last_seen_extraction_run_id = p_extraction_run_id
        WHERE opdv.project_id = p_project_id
          AND opdv.extraction_run_id = v_prev_active
        ORDER BY
          npd.id, opdv.osv_id,
          (npd.id = opd.id) DESC,
          (npd.version = opd.version) DESC,
          opdv.detected_at ASC NULLS LAST
      ) AS old_data
      WHERE new_pdv.project_id = p_project_id
        AND new_pdv.extraction_run_id = p_extraction_run_id
        AND new_pdv.project_dependency_id = old_data.new_pd_id
        AND new_pdv.osv_id = old_data.osv_id
      RETURNING new_pdv.id
    )
    SELECT COUNT(*) INTO v_pdv_carried FROM carried;

    IF v_enabled THEN
      WITH trigger_calc AS (
        SELECT DISTINCT ON (npdv.id)
          npdv.id AS pdv_id,
          npdv.osv_id,
          CASE
            WHEN (v_triggers ? 'depscore_delta')
              AND npdv.depscore IS NOT NULL
              AND old_pdv.depscore IS NOT NULL
              AND (npdv.depscore - old_pdv.depscore) >= (v_triggers->>'depscore_delta')::numeric
            THEN jsonb_build_object('trigger', 'depscore_delta', 'from', old_pdv.depscore, 'to', npdv.depscore, 'detected_at', v_now)
            ELSE NULL
          END AS r_depscore,
          CASE
            WHEN COALESCE((v_triggers->>'severity_escalation')::boolean, false)
              AND _pdv_severity_rank(npdv.severity) > _pdv_severity_rank(old_pdv.severity)
            THEN jsonb_build_object('trigger', 'severity_escalation', 'from', old_pdv.severity, 'to', npdv.severity, 'detected_at', v_now)
            ELSE NULL
          END AS r_severity,
          CASE
            WHEN COALESCE((v_triggers->>'reachability_upgrade')::boolean, false)
              AND _pdv_reachability_rank(npdv.reachability_level) > _pdv_reachability_rank(old_pdv.reachability_level)
            THEN jsonb_build_object('trigger', 'reachability_upgrade', 'from', old_pdv.reachability_level, 'to', npdv.reachability_level, 'detected_at', v_now)
            ELSE NULL
          END AS r_reachability,
          CASE
            WHEN COALESCE((v_triggers->>'kev_added')::boolean, false)
              AND npdv.cisa_kev = true
              AND COALESCE(old_pdv.cisa_kev, false) = false
            THEN jsonb_build_object('trigger', 'kev_added', 'from', false, 'to', true, 'detected_at', v_now)
            ELSE NULL
          END AS r_kev,
          CASE
            WHEN (v_triggers ? 'epss_delta')
              AND npdv.epss_score IS NOT NULL
              AND old_pdv.epss_score IS NOT NULL
              AND abs(npdv.epss_score - old_pdv.epss_score) >= (v_triggers->>'epss_delta')::numeric
            THEN jsonb_build_object('trigger', 'epss_delta', 'from', old_pdv.epss_score, 'to', npdv.epss_score, 'detected_at', v_now)
            ELSE NULL
          END AS r_epss,
          CASE
            WHEN COALESCE((v_triggers->>'became_direct')::boolean, false)
              AND npd.is_direct = true
              AND COALESCE(opd.is_direct, false) = false
            THEN jsonb_build_object('trigger', 'became_direct', 'from', false, 'to', true, 'detected_at', v_now)
            ELSE NULL
          END AS r_direct,
          CASE
            WHEN COALESCE((v_triggers->>'dev_to_prod')::boolean, false)
              AND lower(COALESCE(npd.environment, '')) = 'prod'
              AND lower(COALESCE(opd.environment, '')) = 'dev'
            THEN jsonb_build_object('trigger', 'dev_to_prod', 'from', opd.environment, 'to', npd.environment, 'detected_at', v_now)
            ELSE NULL
          END AS r_env
        FROM project_dependency_vulnerabilities npdv
        JOIN project_dependencies npd ON npd.id = npdv.project_dependency_id
        JOIN project_dependencies opd
          ON opd.project_id = npd.project_id
         AND opd.name = npd.name
        JOIN project_dependency_vulnerabilities old_pdv
          ON old_pdv.project_id = p_project_id
         AND old_pdv.project_dependency_id = opd.id
         AND old_pdv.osv_id = npdv.osv_id
         AND old_pdv.extraction_run_id = v_prev_active
        WHERE npdv.project_id = p_project_id
          AND npdv.extraction_run_id = p_extraction_run_id
        ORDER BY
          npdv.id,
          (opd.id = npd.id) DESC,
          (opd.version = npd.version) DESC,
          old_pdv.detected_at ASC NULLS LAST
      ),
      new_reasons AS (
        SELECT
          pdv_id,
          osv_id,
          jsonb_strip_nulls(jsonb_build_array(r_depscore, r_severity, r_reachability, r_kev, r_epss, r_direct, r_env)) AS reasons
        FROM trigger_calc
      ),
      fired AS (
        UPDATE project_dependency_vulnerabilities pdv
        SET
          re_review_triggered_at = v_now,
          re_review_reasons = COALESCE(pdv.re_review_reasons, '[]'::jsonb) || nr.reasons
        FROM new_reasons nr
        WHERE pdv.id = nr.pdv_id
          AND jsonb_array_length(nr.reasons) > 0
        RETURNING pdv.id, pdv.project_dependency_id AS pd_id, nr.osv_id, nr.reasons
      ),
      event_insert AS (
        INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
        SELECT p_project_id, osv_id, 'rereview_triggered', p_extraction_run_id, pd_id,
               jsonb_build_object('reasons', reasons),
               v_now
        FROM fired
        ON CONFLICT (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
          WHERE extraction_run_id IS NOT NULL
          DO NOTHING
      )
      SELECT COUNT(*) INTO v_pdv_rereview_fired FROM fired;
    END IF;

    WITH unmatched AS (
      SELECT npdv.id AS pdv_id, npdv.project_dependency_id AS pd_id, npd.name AS dep_name, npdv.osv_id
      FROM project_dependency_vulnerabilities npdv
      JOIN project_dependencies npd ON npd.id = npdv.project_dependency_id
      WHERE npdv.project_id = p_project_id
        AND npdv.extraction_run_id = p_extraction_run_id
        AND NOT EXISTS (
          SELECT 1
          FROM project_dependency_vulnerabilities opdv
          JOIN project_dependencies opd ON opd.id = opdv.project_dependency_id
          WHERE opdv.project_id = p_project_id
            AND opdv.extraction_run_id = v_prev_active
            AND opd.name = npd.name
            AND opdv.osv_id = npdv.osv_id
        )
    ),
    classified AS (
      SELECT
        u.pdv_id,
        u.pd_id,
        u.osv_id,
        u.dep_name,
        EXISTS (
          SELECT 1
          FROM project_dependency_vulnerabilities opdv
          JOIN project_dependencies opd ON opd.id = opdv.project_dependency_id
          WHERE opdv.project_id = p_project_id
            AND opdv.extraction_run_id IS DISTINCT FROM p_extraction_run_id
            AND opdv.extraction_run_id IS DISTINCT FROM v_prev_active
            AND opd.name = u.dep_name
            AND opdv.osv_id = u.osv_id
        ) AS is_reopened
      FROM unmatched u
    ),
    events_inserted AS (
      INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
      SELECT
        p_project_id,
        c.osv_id,
        CASE WHEN c.is_reopened THEN 'reopened' ELSE 'detected' END,
        p_extraction_run_id,
        c.pd_id,
        jsonb_build_object('dep_name', c.dep_name),
        v_now
      FROM classified c
      ON CONFLICT (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
        WHERE extraction_run_id IS NOT NULL
        DO NOTHING
      RETURNING id, event_type
    )
    SELECT
      COUNT(*) FILTER (WHERE event_type = 'reopened'),
      COUNT(*) FILTER (WHERE event_type = 'detected')
    INTO v_pdv_reopened, v_pdv_new
    FROM events_inserted;
  ELSE
    INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected', p_extraction_run_id, npdv.project_dependency_id,
           jsonb_build_object('dep_name', npd.name),
           v_now
    FROM project_dependency_vulnerabilities npdv
    JOIN project_dependencies npd ON npd.id = npdv.project_dependency_id
    WHERE npdv.project_id = p_project_id
      AND npdv.extraction_run_id = p_extraction_run_id
    ON CONFLICT (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
      WHERE extraction_run_id IS NOT NULL
      DO NOTHING;

    v_pdv_carried := 0;
    v_pdv_rereview_fired := 0;
    v_pdv_reopened := 0;
    v_pdv_new := v_pdv_inserted;
  END IF;

  SELECT COUNT(*) INTO v_pdv_critical_new
  FROM project_dependency_vulnerabilities npdv
  JOIN project_dependencies npd ON npd.id = npdv.project_dependency_id
  WHERE npdv.project_id = p_project_id
    AND npdv.extraction_run_id = p_extraction_run_id
    AND (lower(COALESCE(npdv.severity, '')) = 'critical' OR npdv.cisa_kev = true)
    AND (
      v_prev_active IS NULL
      OR NOT EXISTS (
        SELECT 1
        FROM project_dependency_vulnerabilities opdv
        JOIN project_dependencies opd ON opd.id = opdv.project_dependency_id
        WHERE opdv.project_id = p_project_id
          AND opdv.extraction_run_id = v_prev_active
          AND opd.name = npd.name
          AND opdv.osv_id = npdv.osv_id
      )
    );

  IF v_prev_active IS NOT NULL THEN
    UPDATE project_semgrep_findings new_sf
    SET status = old_sf.status
    FROM project_semgrep_findings old_sf
    WHERE new_sf.project_id = p_project_id
      AND new_sf.extraction_run_id = p_extraction_run_id
      AND new_sf.semgrep_fingerprint IS NOT NULL
      AND old_sf.project_id = p_project_id
      AND old_sf.extraction_run_id = v_prev_active
      AND old_sf.semgrep_fingerprint = new_sf.semgrep_fingerprint;

    UPDATE project_semgrep_findings new_sf
    SET status = old_sf.status
    FROM project_semgrep_findings old_sf
    WHERE new_sf.project_id = p_project_id
      AND new_sf.extraction_run_id = p_extraction_run_id
      AND new_sf.semgrep_fingerprint IS NULL
      AND old_sf.project_id = p_project_id
      AND old_sf.extraction_run_id = v_prev_active
      AND old_sf.rule_id = new_sf.rule_id
      AND old_sf.file_path = new_sf.file_path
      AND old_sf.start_line IS NOT DISTINCT FROM new_sf.start_line;

    UPDATE project_secret_findings new_secf
    SET status = old_secf.status
    FROM project_secret_findings old_secf
    WHERE new_secf.project_id = p_project_id
      AND new_secf.extraction_run_id = p_extraction_run_id
      AND old_secf.project_id = p_project_id
      AND old_secf.extraction_run_id = v_prev_active
      AND old_secf.detector_type = new_secf.detector_type
      AND old_secf.file_path = new_secf.file_path
      AND old_secf.redacted_value IS NOT DISTINCT FROM new_secf.redacted_value;
  END IF;

  IF NOT v_sla_paused THEN
    FOR v_sla_row IN
      SELECT pdv.id, pdv.severity, pdv.detected_at
      FROM project_dependency_vulnerabilities pdv
      WHERE pdv.project_id = p_project_id
        AND pdv.extraction_run_id = p_extraction_run_id
        AND pdv.sla_status IS NULL
        AND pdv.severity IN ('critical', 'high', 'medium', 'low')
    LOOP
      SELECT max_hours, warning_threshold_percent INTO v_sla_hours, v_sla_warn_pct
      FROM get_effective_sla_policy(v_org_id, v_sla_row.severity, v_asset_tier_id);

      IF v_sla_hours IS NOT NULL THEN
        UPDATE project_dependency_vulnerabilities
        SET
          sla_deadline_at = v_sla_row.detected_at + (v_sla_hours || ' hours')::INTERVAL,
          sla_warning_at = v_sla_row.detected_at + (v_sla_hours * COALESCE(v_sla_warn_pct, 75) / 100.0 || ' hours')::INTERVAL,
          sla_status = CASE
            WHEN v_now > v_sla_row.detected_at + (v_sla_hours || ' hours')::INTERVAL THEN 'breached'
            WHEN v_now >= v_sla_row.detected_at + (v_sla_hours * COALESCE(v_sla_warn_pct, 75) / 100.0 || ' hours')::INTERVAL THEN 'warning'
            ELSE 'on_track'
          END,
          sla_breached_at = CASE
            WHEN v_now > v_sla_row.detected_at + (v_sla_hours || ' hours')::INTERVAL
            THEN v_sla_row.detected_at + (v_sla_hours || ' hours')::INTERVAL
            ELSE NULL
          END
        WHERE id = v_sla_row.id;
        v_sla_set := v_sla_set + 1;
      END IF;
    END LOOP;
  END IF;

  UPDATE projects
  SET
    previous_extraction_run_id = active_extraction_run_id,
    active_extraction_run_id = p_extraction_run_id
  WHERE id = p_project_id;

  v_reap_result := reap_old_extractions(p_project_id);

  RETURN jsonb_build_object(
    'extraction_run_id', p_extraction_run_id,
    'previous_extraction_run_id', v_prev_active,
    'deps_inserted', v_deps_inserted,
    'deps_updated', v_deps_updated,
    'deps_removed', v_deps_removed,
    'vulns_inserted', v_pdv_inserted,
    'vulns_carried_forward', v_pdv_carried,
    'vulns_new', v_pdv_new,
    'vulns_reopened', v_pdv_reopened,
    'vulns_critical_new', v_pdv_critical_new,
    'vulns_re_review_fired', v_pdv_rereview_fired,
    'semgrep_inserted', v_semgrep_inserted,
    'secret_inserted', v_secret_inserted,
    'sla_computed', v_sla_set,
    'rereview_enabled', v_enabled,
    'reap', v_reap_result
  );
END;
$$;

COMMENT ON FUNCTION commit_extraction IS
  'Phase 19.2 (+ Phase 22, Phase 23): atomic commit of an extraction pipeline run. finalize_extraction is the active path; commit_extraction stays available for any future JSONB-payload caller. Phase 23 extended p_reachable_flows typedef with reachability_source/osv_id/rule_id columns.';
