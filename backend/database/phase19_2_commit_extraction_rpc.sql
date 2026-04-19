-- Phase 19.2: commit_extraction + reap_old_extractions RPCs
--
-- commit_extraction: single-transaction atomic commit of a pipeline run.
--   1. Upsert deps (UUIDs stable across extractions)
--   2. Soft-delete deps missing from this extraction
--   3. Insert findings in FK order, tagged with new extraction_run_id
--   4. Carry forward user/system state by stable identifiers
--        - PDV: state carried by (project_id, dep_name, osv_id) — survives version bumps
--        - Semgrep: state carried by semgrep_fingerprint, falls back to (rule_id, file_path, start_line)
--        - Secrets: state carried by (detector_type, file_path, redacted_value)
--   5. Detect re-review triggers on PDV, write re_review_triggered_at + reasons
--   6. Classify unmatched new PDVs as "new" (never seen) vs "reopened" (seen in older run)
--   7. Write 'detected' / 'reopened' / 'rereview_triggered' events to project_vulnerability_events
--   8. Compute SLA deadlines for newly-detected PDVs (tier-aware via get_effective_sla_policy)
--   9. Flip active_extraction_run_id → new, previous → old active
--  10. Reap rows from extractions older than (active, previous)
--  11. Return summary for notification emission
--
-- reap_old_extractions: hard-deletes findings rows for extraction runs older
-- than (active, previous) for a given project. Called from commit_extraction
-- directly + available for standalone cron use if needed.
--
-- See .cursor/plans/phase1-atomic-commit-design.md for full design rationale.

-- =============================================================================
-- Helpers: severity rank + reachability rank (used for delta detection)
-- =============================================================================
CREATE OR REPLACE FUNCTION _pdv_severity_rank(p_severity TEXT)
RETURNS INTEGER AS $$
  SELECT CASE lower(COALESCE(p_severity, ''))
    WHEN 'critical' THEN 4
    WHEN 'high' THEN 3
    WHEN 'medium' THEN 2
    WHEN 'low' THEN 1
    ELSE 0
  END;
$$ LANGUAGE sql IMMUTABLE;

CREATE OR REPLACE FUNCTION _pdv_reachability_rank(p_level TEXT)
RETURNS INTEGER AS $$
  SELECT CASE lower(COALESCE(p_level, ''))
    WHEN 'confirmed' THEN 4
    WHEN 'data_flow' THEN 3
    WHEN 'function' THEN 2
    WHEN 'module' THEN 1
    ELSE 0
  END;
$$ LANGUAGE sql IMMUTABLE;

-- =============================================================================
-- reap_old_extractions: hard-delete rows tagged with extraction_run_ids that
-- are neither the current active nor the previous. Declared first so that
-- commit_extraction can PERFORM it at the end.
-- =============================================================================
CREATE OR REPLACE FUNCTION reap_old_extractions(p_project_id UUID)
RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_active TEXT;
  v_previous TEXT;
  v_pdv_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
BEGIN
  SELECT active_extraction_run_id, previous_extraction_run_id
    INTO v_active, v_previous
  FROM projects WHERE id = p_project_id;

  IF v_active IS NULL THEN
    RETURN jsonb_build_object('skipped', true, 'reason', 'no_active_run');
  END IF;

  DELETE FROM project_dependency_vulnerabilities
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_pdv_deleted = ROW_COUNT;

  DELETE FROM project_semgrep_findings
  WHERE project_id = p_project_id
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_semgrep_deleted = ROW_COUNT;

  DELETE FROM project_secret_findings
  WHERE project_id = p_project_id
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_secret_deleted = ROW_COUNT;

  DELETE FROM project_reachable_flows
  WHERE project_id = p_project_id
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_flows_deleted = ROW_COUNT;

  DELETE FROM project_usage_slices
  WHERE project_id = p_project_id
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_slices_deleted = ROW_COUNT;

  DELETE FROM project_dependency_files pdf
  USING project_dependencies pd
  WHERE pdf.project_dependency_id = pd.id
    AND pd.project_id = p_project_id
    AND pdf.extraction_run_id IS NOT NULL
    AND pdf.extraction_run_id <> v_active
    AND (v_previous IS NULL OR pdf.extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_files_deleted = ROW_COUNT;

  DELETE FROM project_dependency_functions pdfn
  USING project_dependencies pd
  WHERE pdfn.project_dependency_id = pd.id
    AND pd.project_id = p_project_id
    AND pdfn.extraction_run_id IS NOT NULL
    AND pdfn.extraction_run_id <> v_active
    AND (v_previous IS NULL OR pdfn.extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_fns_deleted = ROW_COUNT;

  RETURN jsonb_build_object(
    'project_id', p_project_id,
    'active', v_active,
    'previous', v_previous,
    'pdv_deleted', v_pdv_deleted,
    'semgrep_deleted', v_semgrep_deleted,
    'secret_deleted', v_secret_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'dep_files_deleted', v_files_deleted,
    'dep_functions_deleted', v_fns_deleted
  );
END;
$$;

COMMENT ON FUNCTION reap_old_extractions IS
  'Phase 19.2: hard-delete finding rows belonging to extraction_run_ids that are neither the active nor the previous-active for the given project. Called by commit_extraction at the end of every run and available as a standalone callable.';

-- =============================================================================
-- commit_extraction: the big one
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
  -- ===========================================================================
  -- 1. Lock project + capture previous active run + org/tier context
  -- ===========================================================================
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

  -- ===========================================================================
  -- 2. Resolve re-review settings for this project's tier
  -- ===========================================================================
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

  -- ===========================================================================
  -- 3. Upsert deps
  -- ===========================================================================
  WITH input_deps AS (
    SELECT * FROM jsonb_to_recordset(p_dependencies) AS d(
      name TEXT, version TEXT, is_direct BOOLEAN, source TEXT,
      environment TEXT, license TEXT, dependency_id UUID,
      files_importing_count INTEGER, is_outdated BOOLEAN, versions_behind INTEGER,
      policy_result JSONB, dependency_version_id UUID
    )
  ),
  upserted AS (
    INSERT INTO project_dependencies (
      project_id, name, version, is_direct, source,
      environment, license, dependency_id,
      files_importing_count, is_outdated, versions_behind,
      policy_result, dependency_version_id,
      last_seen_extraction_run_id, removed_at, created_at
    )
    SELECT
      p_project_id, d.name, d.version, d.is_direct, d.source,
      d.environment, d.license, d.dependency_id,
      COALESCE(d.files_importing_count, 0),
      COALESCE(d.is_outdated, false),
      COALESCE(d.versions_behind, 0),
      d.policy_result, d.dependency_version_id,
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
      last_seen_extraction_run_id = p_extraction_run_id,
      removed_at = NULL
    RETURNING (xmax = 0) AS was_inserted
  )
  SELECT
    COUNT(*) FILTER (WHERE was_inserted),
    COUNT(*) FILTER (WHERE NOT was_inserted)
  INTO v_deps_inserted, v_deps_updated
  FROM upserted;

  -- ===========================================================================
  -- 4. Mark deps missing from this extraction as removed (soft-delete)
  -- ===========================================================================
  UPDATE project_dependencies
  SET removed_at = v_now
  WHERE project_id = p_project_id
    AND removed_at IS NULL
    AND (last_seen_extraction_run_id IS DISTINCT FROM p_extraction_run_id);
  GET DIAGNOSTICS v_deps_removed = ROW_COUNT;

  -- ===========================================================================
  -- 5. Insert findings in FK order
  -- ===========================================================================
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

  INSERT INTO project_reachable_flows (
    project_id, extraction_run_id, purl, dependency_id, flow_nodes,
    entry_point_file, entry_point_method, entry_point_line, entry_point_tag,
    sink_file, sink_method, sink_line, sink_is_external, flow_length, llm_prompt, created_at
  )
  SELECT
    p_project_id, p_extraction_run_id, rf.purl, rf.dependency_id, rf.flow_nodes,
    rf.entry_point_file, rf.entry_point_method, rf.entry_point_line, rf.entry_point_tag,
    rf.sink_file, rf.sink_method, rf.sink_line,
    COALESCE(rf.sink_is_external, true), rf.flow_length, rf.llm_prompt, v_now
  FROM jsonb_to_recordset(p_reachable_flows) AS rf(
    purl TEXT, dependency_id UUID, flow_nodes JSONB,
    entry_point_file TEXT, entry_point_method TEXT, entry_point_line INTEGER, entry_point_tag TEXT,
    sink_file TEXT, sink_method TEXT, sink_line INTEGER, sink_is_external BOOLEAN,
    flow_length INTEGER, llm_prompt TEXT
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

  -- ===========================================================================
  -- 6. Carry-forward PDV state by (project_id, dep_name, osv_id)
  -- ===========================================================================
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
        SELECT
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
      ) AS old_data
      WHERE new_pdv.project_id = p_project_id
        AND new_pdv.extraction_run_id = p_extraction_run_id
        AND new_pdv.project_dependency_id = old_data.new_pd_id
        AND new_pdv.osv_id = old_data.osv_id
      RETURNING new_pdv.id
    )
    SELECT COUNT(*) INTO v_pdv_carried FROM carried;

    -- =========================================================================
    -- 7. Trigger detection on carried-forward PDVs
    -- =========================================================================
    IF v_enabled THEN
      WITH trigger_calc AS (
        SELECT
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
         AND opd.last_seen_extraction_run_id IS DISTINCT FROM p_extraction_run_id
        JOIN project_dependency_vulnerabilities old_pdv
          ON old_pdv.project_id = p_project_id
         AND old_pdv.project_dependency_id = opd.id
         AND old_pdv.osv_id = npdv.osv_id
         AND old_pdv.extraction_run_id = v_prev_active
        WHERE npdv.project_id = p_project_id
          AND npdv.extraction_run_id = p_extraction_run_id
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
        RETURNING pdv.id, nr.osv_id, nr.reasons
      ),
      event_insert AS (
        INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, metadata, created_at)
        SELECT p_project_id, osv_id, 'rereview_triggered',
               jsonb_build_object('extraction_run_id', p_extraction_run_id, 'reasons', reasons),
               v_now
        FROM fired
      )
      SELECT COUNT(*) INTO v_pdv_rereview_fired FROM fired;
    END IF;

    -- =========================================================================
    -- 8. Classify unmatched new PDVs (new vs reopened) + write events
    -- =========================================================================
    WITH unmatched AS (
      SELECT npdv.id AS pdv_id, npd.name AS dep_name, npdv.osv_id
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
      INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, metadata, created_at)
      SELECT
        p_project_id,
        c.osv_id,
        CASE WHEN c.is_reopened THEN 'reopened' ELSE 'detected' END,
        jsonb_build_object('extraction_run_id', p_extraction_run_id, 'dep_name', c.dep_name),
        v_now
      FROM classified c
      RETURNING id, event_type
    )
    SELECT
      COUNT(*) FILTER (WHERE event_type = 'reopened'),
      COUNT(*) FILTER (WHERE event_type = 'detected')
    INTO v_pdv_reopened, v_pdv_new
    FROM events_inserted;
  ELSE
    -- First extraction: every inserted PDV is new, write 'detected' events
    INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected',
           jsonb_build_object('extraction_run_id', p_extraction_run_id, 'dep_name', npd.name),
           v_now
    FROM project_dependency_vulnerabilities npdv
    JOIN project_dependencies npd ON npd.id = npdv.project_dependency_id
    WHERE npdv.project_id = p_project_id
      AND npdv.extraction_run_id = p_extraction_run_id;

    v_pdv_carried := 0;
    v_pdv_rereview_fired := 0;
    v_pdv_reopened := 0;
    v_pdv_new := v_pdv_inserted;
  END IF;

  -- ===========================================================================
  -- 9. Count new critical / KEV findings (for notification roll-up)
  -- ===========================================================================
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

  -- ===========================================================================
  -- 10. Semgrep + secret status carry-forward
  -- ===========================================================================
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

  -- ===========================================================================
  -- 11. Compute SLA deadlines for newly-detected PDVs
  --     Only applies to rows where sla_status IS NULL after carry-forward
  --     (i.e., truly new findings or reopened with no carried state).
  --     Uses get_effective_sla_policy from phase15_sla_management.sql.
  -- ===========================================================================
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

  -- ===========================================================================
  -- 12. Pointer flip — atomic visibility switch
  -- ===========================================================================
  UPDATE projects
  SET
    previous_extraction_run_id = active_extraction_run_id,
    active_extraction_run_id = p_extraction_run_id
  WHERE id = p_project_id;

  -- ===========================================================================
  -- 13. Reap rows from extractions older than (new active, previous)
  -- ===========================================================================
  v_reap_result := reap_old_extractions(p_project_id);

  -- ===========================================================================
  -- 14. Return summary for notification emission + telemetry
  -- ===========================================================================
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
  'Phase 19.2: atomic commit of an extraction pipeline run. Upserts deps, soft-deletes missing, inserts findings under fresh extraction_run_id, carries forward user state, detects re-review triggers, writes lifecycle events, computes SLA for new findings, flips active_extraction_run_id pointer, reaps old rows. Returns summary JSONB for notification emission.';
