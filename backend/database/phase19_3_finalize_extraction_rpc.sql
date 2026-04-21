-- Phase 19.3: finalize_extraction RPC
--
-- The primary commit path used by pipeline.ts. Assumes rows for the new
-- extraction_run_id have ALREADY been inserted by the pipeline (streamed
-- writes, each tagged with the fresh run_id). This function does only the
-- finalization work that must happen atomically at the end of a run:
--   1. Mark deps missing from this extraction as removed (soft-delete)
--   2. Carry-forward PDV state (18 user/SLA/risk/re-review columns) by (project_id, dep_name, osv_id)
--   3. Detect re-review triggers on carried PDVs + append to re_review_reasons + write 'rereview_triggered' events
--   4. Classify unmatched new PDVs as new/reopened + write 'detected'/'reopened' events
--   5. Count new critical findings for notification roll-up
--   6. Carry-forward semgrep status (fingerprint preferred, tuple fallback)
--   7. Carry-forward secret status by (detector_type, file_path, redacted_value)
--   8. Compute SLA deadlines for newly-detected PDVs (tier-aware via get_effective_sla_policy)
--   9. Flip active_extraction_run_id pointer (atomic visibility switch)
--  10. Reap rows from extractions older than (new_active, previous_active)
--  11. Return summary JSONB for notification emission
--
-- commit_extraction (phase19_2) remains available for any future caller that
-- wants to pass data via JSONB instead of streaming writes.

CREATE OR REPLACE FUNCTION finalize_extraction(
  p_job_id UUID,
  p_project_id UUID,
  p_extraction_run_id TEXT
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
  v_deps_removed INTEGER := 0;
  v_pdv_carried INTEGER := 0;
  v_pdv_new INTEGER := 0;
  v_pdv_reopened INTEGER := 0;
  v_pdv_critical_new INTEGER := 0;
  v_pdv_rereview_fired INTEGER := 0;
  v_sla_set INTEGER := 0;
  v_sla_row RECORD;
  v_sla_hours INTEGER;
  v_sla_warn_pct INTEGER;
  v_now TIMESTAMPTZ := NOW();
  v_reap_result JSONB;
BEGIN
  -- Lock project + capture prev_active + org/tier context
  SELECT p.active_extraction_run_id, p.organization_id, p.asset_tier_id,
         (o.sla_paused_at IS NOT NULL)
    INTO v_prev_active, v_org_id, v_asset_tier_id, v_sla_paused
  FROM projects p
  JOIN organizations o ON o.id = p.organization_id
  WHERE p.id = p_project_id
  FOR UPDATE OF p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'finalize_extraction: project % not found', p_project_id;
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

  -- 1. Mark deps missing from this extraction as removed
  UPDATE project_dependencies
  SET removed_at = v_now
  WHERE project_id = p_project_id
    AND removed_at IS NULL
    AND (last_seen_extraction_run_id IS DISTINCT FROM p_extraction_run_id);
  GET DIAGNOSTICS v_deps_removed = ROW_COUNT;

  -- 2+3+4. Carry-forward + trigger detection + new/reopened classification
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
        -- Bug-002 fix: pick exactly one old source row per new target
        -- (new_pd_id, osv_id) pair. Prior code joined by (project_id, name)
        -- alone, which in monorepos with the same dep at multiple versions
        -- (or same name as direct+transitive / prod+dev) produced N×M rows;
        -- Postgres' UPDATE…FROM then picked one arbitrarily, silently swapping
        -- suppression/SLA/re_review state between PDVs. DISTINCT ON preserves
        -- version-bump carry-forward (name match still fires when UUIDs differ)
        -- while enforcing uniqueness of the source row per target.
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
          (npd.id = opd.id) DESC,            -- 1. exact UUID match wins
          (npd.version = opd.version) DESC,  -- 2. same version next
          opdv.detected_at ASC NULLS LAST    -- 3. oldest detection (stable)
      ) AS old_data
      WHERE new_pdv.project_id = p_project_id
        AND new_pdv.extraction_run_id = p_extraction_run_id
        AND new_pdv.project_dependency_id = old_data.new_pd_id
        AND new_pdv.osv_id = old_data.osv_id
      RETURNING new_pdv.id
    )
    SELECT COUNT(*) INTO v_pdv_carried FROM carried;

    IF v_enabled THEN
      -- Bug-001 fix: trigger_calc uses DISTINCT ON (npdv.id) to pick exactly
      -- one old (opd, old_pdv) pair per new PDV. Prior code filtered via
      -- "opd.last_seen IS DISTINCT FROM current_run", which silently excluded
      -- every same-version dep (the upsert updates the single PD row in place
      -- so its last_seen advances to the current run) — so triggers never
      -- fired for the most common re-review case: unchanged dep, drifted CVE
      -- metadata. The rewritten join matches by (project_id, name) and ranks
      -- by (UUID match, same version) so version-bump triggers still fire
      -- and monorepo multi-version cases pick a deterministic winner.
      --
      -- Known limitation: same-version case has opd.id = npd.id, so r_direct
      -- and r_env never fire (is_direct/environment on the same row are
      -- always equal). Detecting cross-run is_direct/environment changes on
      -- an unchanged dep needs per-run snapshotting — tracked as follow-up.
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
          (opd.id = npd.id) DESC,            -- 1. exact UUID match wins
          (opd.version = npd.version) DESC,  -- 2. same version next
          old_pdv.detected_at ASC NULLS LAST -- 3. oldest detection (stable)
      ),
      new_reasons AS (
        SELECT pdv_id, osv_id,
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
        INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, metadata, created_at)
        SELECT p_project_id, osv_id, 'rereview_triggered', p_extraction_run_id,
               jsonb_build_object('reasons', reasons),
               v_now
        FROM fired
        ON CONFLICT (project_id, osv_id, event_type, extraction_run_id)
          WHERE extraction_run_id IS NOT NULL
          DO NOTHING
      )
      SELECT COUNT(*) INTO v_pdv_rereview_fired FROM fired;
    END IF;

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
      SELECT u.pdv_id, u.osv_id, u.dep_name,
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
      INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, metadata, created_at)
      SELECT
        p_project_id, c.osv_id,
        CASE WHEN c.is_reopened THEN 'reopened' ELSE 'detected' END,
        p_extraction_run_id,
        jsonb_build_object('dep_name', c.dep_name),
        v_now
      FROM classified c
      ON CONFLICT (project_id, osv_id, event_type, extraction_run_id)
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
    -- First extraction: write 'detected' events for every PDV
    INSERT INTO project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected', p_extraction_run_id,
           jsonb_build_object('dep_name', npd.name),
           v_now
    FROM project_dependency_vulnerabilities npdv
    JOIN project_dependencies npd ON npd.id = npdv.project_dependency_id
    WHERE npdv.project_id = p_project_id
      AND npdv.extraction_run_id = p_extraction_run_id
    ON CONFLICT (project_id, osv_id, event_type, extraction_run_id)
      WHERE extraction_run_id IS NOT NULL
      DO NOTHING;

    SELECT COUNT(*) INTO v_pdv_new
    FROM project_dependency_vulnerabilities
    WHERE project_id = p_project_id AND extraction_run_id = p_extraction_run_id;
  END IF;

  -- 5. Count new critical / KEV findings
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

  -- 6+7. Semgrep + secret status carry-forward
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

  -- 8. Compute SLA deadlines for newly-detected PDVs
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

  -- 9. Pointer flip — atomic visibility switch
  UPDATE projects
  SET
    previous_extraction_run_id = active_extraction_run_id,
    active_extraction_run_id = p_extraction_run_id
  WHERE id = p_project_id;

  -- 10. Reap rows from extractions older than (active, previous)
  v_reap_result := reap_old_extractions(p_project_id);

  -- 11. Return summary
  RETURN jsonb_build_object(
    'extraction_run_id', p_extraction_run_id,
    'previous_extraction_run_id', v_prev_active,
    'deps_removed', v_deps_removed,
    'vulns_carried_forward', v_pdv_carried,
    'vulns_new', v_pdv_new,
    'vulns_reopened', v_pdv_reopened,
    'vulns_critical_new', v_pdv_critical_new,
    'vulns_re_review_fired', v_pdv_rereview_fired,
    'sla_computed', v_sla_set,
    'rereview_enabled', v_enabled,
    'reap', v_reap_result
  );
END;
$$;

COMMENT ON FUNCTION finalize_extraction IS
  'Phase 19.3: primary commit path. Called at the end of an extraction pipeline after rows have been streamed to soft-switched tables under the new extraction_run_id. Mark-removed + carry-forward + triggers + events + SLA + pointer flip + reap, single transaction. Returns summary JSONB for notification emission.';
