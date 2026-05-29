-- Phase 41: Replace asset_tier + organization_asset_tiers with projects.importance
--
-- The dual asset_tier (legacy enum) + asset_tier_id (custom per-org tier table)
-- model is replaced by a single numeric `projects.importance` field in
-- [0.5, 2.0] which IS the depscore multiplier (no lookup table).
--
-- Re-review (silent backend bookkeeping that flipped re_review_triggered_at /
-- re_review_reasons on PDVs when a vuln got worse) is removed entirely — never
-- wired up to a user-facing surface, zero callers in app code.
--
-- Per-tier SLA overrides also removed: organization_sla_policies becomes one
-- row per severity, no tier dimension. get_effective_sla_policy loses its
-- third argument.
--
-- Single transactional migration. Order:
--   1.  Add projects.importance (nullable, no constraint yet)
--   2.  Backfill from asset_tier + asset_tier_id (clamp to [0.5, 2.0])
--   3.  Constrain importance (NOT NULL, DEFAULT 1.0, CHECK)
--   4.  Drop re-review columns + index
--   5.  Rewrite get_effective_sla_policy (drops tier arg)
--   6.  Rewrite commit_extraction (no asset_tier, no re-review)
--   7.  Rewrite finalize_extraction (same)
--   8.  Rewrite confirm_pdvs_from_dast_run (no tier rereview gate)
--   9.  Rewrite backfill_sla_for_organization (no tier arg)
--   10. SLA policies: drop asset_tier_id + dedupe + new UNIQUE
--   11. Drop organization_reachability_settings.trigger_asset_tier_max_rank
--   12. Drop projects.asset_tier_id + projects.asset_tier
--   13. Drop organization_asset_tiers table
--   14. Drop CREATE TYPE asset_tier

BEGIN;

-- ============================================================
-- 1. Add projects.importance (nullable initially for backfill)
-- ============================================================
ALTER TABLE public.projects ADD COLUMN IF NOT EXISTS importance numeric(3,2);

-- ============================================================
-- 2. Backfill from existing asset_tier / asset_tier_id
--    Prefer custom-tier environmental_multiplier when set,
--    else map the legacy enum, else default to 1.0.
-- ============================================================
UPDATE public.projects p
SET importance = LEAST(
  2.0::numeric,
  GREATEST(
    0.5::numeric,
    COALESCE(
      (SELECT oat.environmental_multiplier
         FROM public.organization_asset_tiers oat
        WHERE oat.id = p.asset_tier_id),
      CASE p.asset_tier
        WHEN 'CROWN_JEWELS'   THEN 1.5
        WHEN 'EXTERNAL'       THEN 1.0
        WHEN 'INTERNAL'       THEN 0.8
        WHEN 'NON_PRODUCTION' THEN 0.6
        ELSE 1.0
      END::numeric
    )
  )
)
WHERE p.importance IS NULL;

-- ============================================================
-- 3. Constrain importance
-- ============================================================
ALTER TABLE public.projects
  ALTER COLUMN importance SET NOT NULL,
  ALTER COLUMN importance SET DEFAULT 1.0;

ALTER TABLE public.projects
  ADD CONSTRAINT chk_importance_range
  CHECK (importance >= 0.5 AND importance <= 2.0);

COMMENT ON COLUMN public.projects.importance IS
  'Project importance multiplier in [0.5, 2.0]. Multiplied into the depscore
   formula as tierWeight. Replaces the legacy asset_tier enum + the
   organization_asset_tiers custom-tier table (both removed in phase41).';

-- ============================================================
-- 4. Drop re-review machinery on PDVs (never surfaced to UI)
-- ============================================================
DROP INDEX IF EXISTS public.idx_pdv_rereview_triggered;
ALTER TABLE public.project_dependency_vulnerabilities
  DROP COLUMN IF EXISTS re_review_triggered_at,
  DROP COLUMN IF EXISTS re_review_reasons;

-- ============================================================
-- 5. Rewrite get_effective_sla_policy — drop the tier param
--    Must run BEFORE we drop organization_sla_policies.asset_tier_id, since
--    callers (commit_extraction, finalize_extraction, backfill_sla_for_organization)
--    will be re-pointed to this new signature in the same transaction below.
-- ============================================================
DROP FUNCTION IF EXISTS public.get_effective_sla_policy(uuid, text, uuid);

CREATE OR REPLACE FUNCTION public.get_effective_sla_policy(
  p_organization_id uuid,
  p_severity text
)
RETURNS TABLE(max_hours integer, warning_threshold_percent integer)
LANGUAGE sql
STABLE
AS $function$
  SELECT osp.max_hours, osp.warning_threshold_percent
  FROM public.organization_sla_policies osp
  WHERE osp.organization_id = p_organization_id
    AND osp.severity = p_severity
    AND osp.enabled = true
  LIMIT 1;
$function$;

-- ============================================================
-- 6. Rewrite commit_extraction:
--    - Drop SELECT of p.asset_tier_id + v_asset_tier_id var
--    - Drop the LEFT JOIN organization_asset_tiers for rereview_settings
--    - Drop all re-review machinery (trigger_calc CTE, fired CTE, event_insert
--      for 'rereview_triggered')
--    - Drop carry-forward of re_review_triggered_at / re_review_reasons
--    - Drop vulns_re_review_fired + rereview_enabled from RETURN payload
--    - Call get_effective_sla_policy without the tier arg
-- ============================================================
CREATE OR REPLACE FUNCTION public.commit_extraction(
  p_job_id uuid,
  p_project_id uuid,
  p_extraction_run_id text,
  p_dependencies jsonb,
  p_vulnerabilities jsonb,
  p_semgrep_findings jsonb,
  p_secret_findings jsonb,
  p_reachable_flows jsonb,
  p_usage_slices jsonb,
  p_dependency_files jsonb,
  p_dependency_functions jsonb
)
RETURNS jsonb
LANGUAGE plpgsql
AS $function$
DECLARE
  v_prev_active TEXT;
  v_org_id UUID;
  v_sla_paused BOOLEAN;
  v_deps_inserted INTEGER := 0;
  v_deps_updated INTEGER := 0;
  v_deps_removed INTEGER := 0;
  v_pdv_inserted INTEGER := 0;
  v_pdv_carried INTEGER := 0;
  v_pdv_new INTEGER := 0;
  v_pdv_reopened INTEGER := 0;
  v_pdv_critical_new INTEGER := 0;
  v_semgrep_inserted INTEGER := 0;
  v_secret_inserted INTEGER := 0;
  v_sla_set INTEGER := 0;
  v_sla_row RECORD;
  v_sla_hours INTEGER;
  v_sla_warn_pct INTEGER;
  v_now TIMESTAMPTZ := NOW();
  v_reap_result JSONB;
BEGIN
  SELECT p.active_extraction_run_id, p.organization_id,
         (o.sla_paused_at IS NOT NULL)
    INTO v_prev_active, v_org_id, v_sla_paused
  FROM public.projects p
  JOIN public.organizations o ON o.id = p.organization_id
  WHERE p.id = p_project_id
  FOR UPDATE OF p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_extraction: project % not found', p_project_id;
  END IF;

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
    INSERT INTO public.project_dependencies (
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

  UPDATE public.project_dependencies
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
  INSERT INTO public.project_dependency_vulnerabilities (
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
  JOIN public.project_dependencies pd
    ON pd.project_id = p_project_id
   AND pd.name = v.dep_name
   AND pd.version = v.dep_version
   AND pd.is_direct = COALESCE(v.dep_is_direct, false)
   AND pd.source = v.dep_source
   AND pd.last_seen_extraction_run_id = p_extraction_run_id;
  GET DIAGNOSTICS v_pdv_inserted = ROW_COUNT;

  INSERT INTO public.project_semgrep_findings (
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

  INSERT INTO public.project_secret_findings (
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

  INSERT INTO public.project_reachable_flows (
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

  INSERT INTO public.project_usage_slices (
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

  INSERT INTO public.project_dependency_files (
    project_dependency_id, file_path, extraction_run_id, created_at
  )
  SELECT pd.id, df.file_path, p_extraction_run_id, v_now
  FROM jsonb_to_recordset(p_dependency_files) AS df(
    dep_name TEXT, dep_version TEXT, dep_is_direct BOOLEAN, dep_source TEXT, file_path TEXT
  )
  JOIN public.project_dependencies pd
    ON pd.project_id = p_project_id
   AND pd.name = df.dep_name
   AND pd.version = df.dep_version
   AND pd.is_direct = COALESCE(df.dep_is_direct, false)
   AND pd.source = df.dep_source
   AND pd.last_seen_extraction_run_id = p_extraction_run_id;

  INSERT INTO public.project_dependency_functions (
    project_dependency_id, function_name, extraction_run_id, created_at
  )
  SELECT pd.id, dfn.function_name, p_extraction_run_id, v_now
  FROM jsonb_to_recordset(p_dependency_functions) AS dfn(
    dep_name TEXT, dep_version TEXT, dep_is_direct BOOLEAN, dep_source TEXT, function_name TEXT
  )
  JOIN public.project_dependencies pd
    ON pd.project_id = p_project_id
   AND pd.name = dfn.dep_name
   AND pd.version = dfn.dep_version
   AND pd.is_direct = COALESCE(dfn.dep_is_direct, false)
   AND pd.source = dfn.dep_source
   AND pd.last_seen_extraction_run_id = p_extraction_run_id;

  IF v_prev_active IS NOT NULL THEN
    WITH carried AS (
      UPDATE public.project_dependency_vulnerabilities new_pdv
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
        runtime_confirmed_at = old_data.runtime_confirmed_at,
        runtime_confirmed_dast_finding_id = old_data.runtime_confirmed_dast_finding_id,
        runtime_confirmed_prior_level = old_data.runtime_confirmed_prior_level,
        reachability_level = CASE
          WHEN old_data.runtime_confirmed_at IS NOT NULL THEN 'confirmed'
          ELSE new_pdv.reachability_level END
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
          opdv.runtime_confirmed_at, opdv.runtime_confirmed_dast_finding_id, opdv.runtime_confirmed_prior_level
        FROM public.project_dependency_vulnerabilities opdv
        JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
        JOIN public.project_dependencies npd
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

    WITH unmatched AS (
      SELECT npdv.id AS pdv_id, npdv.project_dependency_id AS pd_id, npd.name AS dep_name, npdv.osv_id
      FROM public.project_dependency_vulnerabilities npdv
      JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
      WHERE npdv.project_id = p_project_id
        AND npdv.extraction_run_id = p_extraction_run_id
        AND NOT EXISTS (
          SELECT 1
          FROM public.project_dependency_vulnerabilities opdv
          JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
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
          FROM public.project_dependency_vulnerabilities opdv
          JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
          WHERE opdv.project_id = p_project_id
            AND opdv.extraction_run_id IS DISTINCT FROM p_extraction_run_id
            AND opdv.extraction_run_id IS DISTINCT FROM v_prev_active
            AND opd.name = u.dep_name
            AND opdv.osv_id = u.osv_id
        ) AS is_reopened
      FROM unmatched u
    ),
    events_inserted AS (
      INSERT INTO public.project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
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
    INSERT INTO public.project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected', p_extraction_run_id, npdv.project_dependency_id,
           jsonb_build_object('dep_name', npd.name),
           v_now
    FROM public.project_dependency_vulnerabilities npdv
    JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
    WHERE npdv.project_id = p_project_id
      AND npdv.extraction_run_id = p_extraction_run_id
    ON CONFLICT (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
      WHERE extraction_run_id IS NOT NULL
      DO NOTHING;

    v_pdv_carried := 0;
    v_pdv_reopened := 0;
    v_pdv_new := v_pdv_inserted;
  END IF;

  SELECT COUNT(*) INTO v_pdv_critical_new
  FROM public.project_dependency_vulnerabilities npdv
  JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
  WHERE npdv.project_id = p_project_id
    AND npdv.extraction_run_id = p_extraction_run_id
    AND (lower(COALESCE(npdv.severity, '')) = 'critical' OR npdv.cisa_kev = true)
    AND (
      v_prev_active IS NULL
      OR NOT EXISTS (
        SELECT 1
        FROM public.project_dependency_vulnerabilities opdv
        JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
        WHERE opdv.project_id = p_project_id
          AND opdv.extraction_run_id = v_prev_active
          AND opd.name = npd.name
          AND opdv.osv_id = npdv.osv_id
      )
    );

  IF v_prev_active IS NOT NULL THEN
    UPDATE public.project_semgrep_findings new_sf
    SET status = old_sf.status
    FROM public.project_semgrep_findings old_sf
    WHERE new_sf.project_id = p_project_id
      AND new_sf.extraction_run_id = p_extraction_run_id
      AND new_sf.semgrep_fingerprint IS NOT NULL
      AND old_sf.project_id = p_project_id
      AND old_sf.extraction_run_id = v_prev_active
      AND old_sf.semgrep_fingerprint = new_sf.semgrep_fingerprint;

    UPDATE public.project_semgrep_findings new_sf
    SET status = old_sf.status
    FROM public.project_semgrep_findings old_sf
    WHERE new_sf.project_id = p_project_id
      AND new_sf.extraction_run_id = p_extraction_run_id
      AND new_sf.semgrep_fingerprint IS NULL
      AND old_sf.project_id = p_project_id
      AND old_sf.extraction_run_id = v_prev_active
      AND old_sf.rule_id = new_sf.rule_id
      AND old_sf.file_path = new_sf.file_path
      AND old_sf.start_line IS NOT DISTINCT FROM new_sf.start_line;

    UPDATE public.project_secret_findings new_secf
    SET status = old_secf.status
    FROM public.project_secret_findings old_secf
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
      FROM public.project_dependency_vulnerabilities pdv
      WHERE pdv.project_id = p_project_id
        AND pdv.extraction_run_id = p_extraction_run_id
        AND pdv.sla_status IS NULL
        AND pdv.severity IN ('critical', 'high', 'medium', 'low')
    LOOP
      SELECT max_hours, warning_threshold_percent INTO v_sla_hours, v_sla_warn_pct
      FROM public.get_effective_sla_policy(v_org_id, v_sla_row.severity);

      IF v_sla_hours IS NOT NULL THEN
        UPDATE public.project_dependency_vulnerabilities
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

  UPDATE public.projects
  SET
    previous_extraction_run_id = active_extraction_run_id,
    active_extraction_run_id = p_extraction_run_id
  WHERE id = p_project_id;

  v_reap_result := public.reap_old_extractions(p_project_id);

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
    'semgrep_inserted', v_semgrep_inserted,
    'secret_inserted', v_secret_inserted,
    'sla_computed', v_sla_set,
    'reap', v_reap_result
  );
END;
$function$;

-- ============================================================
-- 7. Rewrite finalize_extraction (same surgical removals)
-- ============================================================
CREATE OR REPLACE FUNCTION public.finalize_extraction(
  p_job_id uuid,
  p_project_id uuid,
  p_extraction_run_id text
)
RETURNS jsonb
LANGUAGE plpgsql
AS $function$
DECLARE
  v_prev_active TEXT;
  v_org_id UUID;
  v_sla_paused BOOLEAN;
  v_deps_removed INTEGER := 0;
  v_pdv_carried INTEGER := 0;
  v_pdv_new INTEGER := 0;
  v_pdv_reopened INTEGER := 0;
  v_pdv_critical_new INTEGER := 0;
  v_sla_set INTEGER := 0;
  v_sla_row RECORD;
  v_sla_hours INTEGER;
  v_sla_warn_pct INTEGER;
  v_now TIMESTAMPTZ := NOW();
  v_reap_result JSONB;
BEGIN
  SELECT p.active_extraction_run_id, p.organization_id,
         (o.sla_paused_at IS NOT NULL)
    INTO v_prev_active, v_org_id, v_sla_paused
  FROM public.projects p
  JOIN public.organizations o ON o.id = p.organization_id
  WHERE p.id = p_project_id
  FOR UPDATE OF p;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'finalize_extraction: project % not found', p_project_id;
  END IF;

  UPDATE public.project_dependencies
  SET removed_at = v_now
  WHERE project_id = p_project_id
    AND removed_at IS NULL
    AND (last_seen_extraction_run_id IS DISTINCT FROM p_extraction_run_id);
  GET DIAGNOSTICS v_deps_removed = ROW_COUNT;

  IF v_prev_active IS NOT NULL THEN
    WITH carried AS (
      UPDATE public.project_dependency_vulnerabilities new_pdv
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
        runtime_confirmed_at = old_data.runtime_confirmed_at,
        runtime_confirmed_dast_finding_id = old_data.runtime_confirmed_dast_finding_id,
        runtime_confirmed_prior_level = old_data.runtime_confirmed_prior_level,
        reachability_level = CASE
          WHEN old_data.runtime_confirmed_at IS NOT NULL THEN 'confirmed'
          ELSE new_pdv.reachability_level END
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
          opdv.runtime_confirmed_at, opdv.runtime_confirmed_dast_finding_id, opdv.runtime_confirmed_prior_level
        FROM public.project_dependency_vulnerabilities opdv
        JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
        JOIN public.project_dependencies npd
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

    WITH unmatched AS (
      SELECT npdv.id AS pdv_id, npdv.project_dependency_id AS pd_id, npd.name AS dep_name, npdv.osv_id
      FROM public.project_dependency_vulnerabilities npdv
      JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
      WHERE npdv.project_id = p_project_id
        AND npdv.extraction_run_id = p_extraction_run_id
        AND NOT EXISTS (
          SELECT 1
          FROM public.project_dependency_vulnerabilities opdv
          JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
          WHERE opdv.project_id = p_project_id
            AND opdv.extraction_run_id = v_prev_active
            AND opd.name = npd.name
            AND opdv.osv_id = npdv.osv_id
        )
    ),
    classified AS (
      SELECT u.pdv_id, u.pd_id, u.osv_id, u.dep_name,
        EXISTS (
          SELECT 1
          FROM public.project_dependency_vulnerabilities opdv
          JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
          WHERE opdv.project_id = p_project_id
            AND opdv.extraction_run_id IS DISTINCT FROM p_extraction_run_id
            AND opdv.extraction_run_id IS DISTINCT FROM v_prev_active
            AND opd.name = u.dep_name
            AND opdv.osv_id = u.osv_id
        ) AS is_reopened
      FROM unmatched u
    ),
    events_inserted AS (
      INSERT INTO public.project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
      SELECT
        p_project_id, c.osv_id,
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
    INSERT INTO public.project_vulnerability_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected', p_extraction_run_id, npdv.project_dependency_id,
           jsonb_build_object('dep_name', npd.name),
           v_now
    FROM public.project_dependency_vulnerabilities npdv
    JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
    WHERE npdv.project_id = p_project_id
      AND npdv.extraction_run_id = p_extraction_run_id
    ON CONFLICT (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
      WHERE extraction_run_id IS NOT NULL
      DO NOTHING;

    SELECT COUNT(*) INTO v_pdv_new
    FROM public.project_dependency_vulnerabilities
    WHERE project_id = p_project_id AND extraction_run_id = p_extraction_run_id;
  END IF;

  SELECT COUNT(*) INTO v_pdv_critical_new
  FROM public.project_dependency_vulnerabilities npdv
  JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
  WHERE npdv.project_id = p_project_id
    AND npdv.extraction_run_id = p_extraction_run_id
    AND (lower(COALESCE(npdv.severity, '')) = 'critical' OR npdv.cisa_kev = true)
    AND (
      v_prev_active IS NULL
      OR NOT EXISTS (
        SELECT 1
        FROM public.project_dependency_vulnerabilities opdv
        JOIN public.project_dependencies opd ON opd.id = opdv.project_dependency_id
        WHERE opdv.project_id = p_project_id
          AND opdv.extraction_run_id = v_prev_active
          AND opd.name = npd.name
          AND opdv.osv_id = npdv.osv_id
      )
    );

  IF v_prev_active IS NOT NULL THEN
    UPDATE public.project_semgrep_findings new_sf
    SET status = old_sf.status
    FROM public.project_semgrep_findings old_sf
    WHERE new_sf.project_id = p_project_id
      AND new_sf.extraction_run_id = p_extraction_run_id
      AND new_sf.semgrep_fingerprint IS NOT NULL
      AND old_sf.project_id = p_project_id
      AND old_sf.extraction_run_id = v_prev_active
      AND old_sf.semgrep_fingerprint = new_sf.semgrep_fingerprint;

    UPDATE public.project_semgrep_findings new_sf
    SET status = old_sf.status
    FROM public.project_semgrep_findings old_sf
    WHERE new_sf.project_id = p_project_id
      AND new_sf.extraction_run_id = p_extraction_run_id
      AND new_sf.semgrep_fingerprint IS NULL
      AND old_sf.project_id = p_project_id
      AND old_sf.extraction_run_id = v_prev_active
      AND old_sf.rule_id = new_sf.rule_id
      AND old_sf.file_path = new_sf.file_path
      AND old_sf.start_line IS NOT DISTINCT FROM new_sf.start_line;

    UPDATE public.project_secret_findings new_secf
    SET status = old_secf.status
    FROM public.project_secret_findings old_secf
    WHERE new_secf.project_id = p_project_id
      AND new_secf.extraction_run_id = p_extraction_run_id
      AND old_secf.project_id = p_project_id
      AND old_secf.extraction_run_id = v_prev_active
      AND old_secf.detector_type = new_secf.detector_type
      AND old_secf.file_path = new_secf.file_path
      AND old_secf.redacted_value IS NOT DISTINCT FROM new_secf.redacted_value;

    UPDATE public.project_iac_findings new_if
    SET
      status = old_if.status,
      suppressed = old_if.suppressed,
      suppressed_by = old_if.suppressed_by,
      suppressed_at = old_if.suppressed_at,
      risk_accepted = old_if.risk_accepted,
      risk_accepted_by = old_if.risk_accepted_by,
      risk_accepted_at = old_if.risk_accepted_at,
      risk_accepted_reason = old_if.risk_accepted_reason
    FROM public.project_iac_findings old_if
    WHERE new_if.project_id = p_project_id
      AND new_if.extraction_run_id = p_extraction_run_id
      AND new_if.iac_fingerprint IS NOT NULL
      AND old_if.project_id = p_project_id
      AND old_if.extraction_run_id = v_prev_active
      AND old_if.iac_fingerprint IS NOT NULL
      AND old_if.scanner = new_if.scanner
      AND old_if.iac_fingerprint = new_if.iac_fingerprint;

    UPDATE public.project_container_findings new_cf
    SET
      status = old_cf.status,
      suppressed = old_cf.suppressed,
      suppressed_by = old_cf.suppressed_by,
      suppressed_at = old_cf.suppressed_at,
      risk_accepted = old_cf.risk_accepted,
      risk_accepted_by = old_cf.risk_accepted_by,
      risk_accepted_at = old_cf.risk_accepted_at,
      risk_accepted_reason = old_cf.risk_accepted_reason
    FROM public.project_container_findings old_cf
    WHERE new_cf.project_id = p_project_id
      AND new_cf.extraction_run_id = p_extraction_run_id
      AND new_cf.container_fingerprint IS NOT NULL
      AND old_cf.project_id = p_project_id
      AND old_cf.extraction_run_id = v_prev_active
      AND old_cf.container_fingerprint IS NOT NULL
      AND old_cf.container_fingerprint = new_cf.container_fingerprint;
  END IF;

  IF NOT v_sla_paused THEN
    FOR v_sla_row IN
      SELECT pdv.id, pdv.severity, pdv.detected_at
      FROM public.project_dependency_vulnerabilities pdv
      WHERE pdv.project_id = p_project_id
        AND pdv.extraction_run_id = p_extraction_run_id
        AND pdv.sla_status IS NULL
        AND pdv.severity IN ('critical', 'high', 'medium', 'low')
    LOOP
      SELECT max_hours, warning_threshold_percent INTO v_sla_hours, v_sla_warn_pct
      FROM public.get_effective_sla_policy(v_org_id, v_sla_row.severity);

      IF v_sla_hours IS NOT NULL THEN
        UPDATE public.project_dependency_vulnerabilities
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

  UPDATE public.projects
  SET
    previous_extraction_run_id = active_extraction_run_id,
    active_extraction_run_id = p_extraction_run_id
  WHERE id = p_project_id;

  v_reap_result := public.reap_old_extractions(p_project_id);

  RETURN jsonb_build_object(
    'extraction_run_id', p_extraction_run_id,
    'previous_extraction_run_id', v_prev_active,
    'deps_removed', v_deps_removed,
    'vulns_carried_forward', v_pdv_carried,
    'vulns_new', v_pdv_new,
    'vulns_reopened', v_pdv_reopened,
    'vulns_critical_new', v_pdv_critical_new,
    'sla_computed', v_sla_set,
    'reap', v_reap_result
  );
END;
$function$;

-- ============================================================
-- 8. Rewrite confirm_pdvs_from_dast_run — drops the tier rereview gate
--    and the re_review_triggered_at/re_review_reasons writes. Runtime DAST
--    confirmation still bumps reachability_level → confirmed.
-- ============================================================
CREATE OR REPLACE FUNCTION public.confirm_pdvs_from_dast_run(
  p_project_id uuid,
  p_dast_run_id text
)
RETURNS TABLE(pdv_id uuid, osv_id text, prior_reachability_level text, new_reachability_level text)
LANGUAGE plpgsql
SET search_path TO 'public'
SET statement_timeout TO '5s'
AS $function$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.project_dast_findings
     WHERE dast_run_id = p_dast_run_id
       AND project_id = p_project_id
       AND engine = 'nuclei'
  ) THEN
    RAISE EXCEPTION 'dast_run_id % has no Nuclei findings in project %',
      p_dast_run_id, p_project_id USING ERRCODE = 'P0001';
  END IF;

  RETURN QUERY
  WITH matches AS (
    SELECT DISTINCT ON (pdv.id)
      pdv.id  AS pdv_id,
      pdv.osv_id,
      pdv.reachability_level AS prior_level,
      f.id    AS dast_finding_id
    FROM public.project_dast_findings f
    CROSS JOIN LATERAL (
      SELECT array_agg(upper(c)) AS cves
        FROM jsonb_array_elements_text(f.cross_link_metadata->'nuclei'->'cve_ids') c
    ) cve_set
    JOIN public.project_dependency_vulnerabilities pdv
      ON pdv.project_id = f.project_id
     AND pdv.project_dependency_id = f.linked_sca_project_dependency_id
     AND (
       upper(pdv.osv_id) = ANY(cve_set.cves)
       OR EXISTS (
         SELECT 1 FROM unnest(COALESCE(pdv.aliases, ARRAY[]::text[])) a
          WHERE upper(a) = ANY(cve_set.cves)
       )
     )
    WHERE f.project_id = p_project_id
      AND f.dast_run_id = p_dast_run_id
      AND f.engine = 'nuclei'
      AND f.linked_sca_project_dependency_id IS NOT NULL
      AND cve_set.cves IS NOT NULL
      AND public._pdv_reachability_rank(pdv.reachability_level) < public._pdv_reachability_rank('confirmed')
    ORDER BY pdv.id, public._pdv_severity_rank(f.severity) DESC, f.created_at ASC
  ),
  updated AS (
    UPDATE public.project_dependency_vulnerabilities pdv
       SET reachability_level             = 'confirmed',
           runtime_confirmed_at           = now(),
           runtime_confirmed_dast_finding_id = m.dast_finding_id,
           runtime_confirmed_prior_level  = m.prior_level
      FROM matches m
     WHERE pdv.id = m.pdv_id
    RETURNING pdv.id, pdv.osv_id, m.prior_level AS prior_level,
              pdv.reachability_level AS new_level
  )
  SELECT updated.id, updated.osv_id, updated.prior_level, updated.new_level FROM updated;
END;
$function$;

-- ============================================================
-- 9. Rewrite backfill_sla_for_organization — drops asset_tier_id from
--    SELECT + drops the third arg from get_effective_sla_policy call.
-- ============================================================
CREATE OR REPLACE FUNCTION public.backfill_sla_for_organization(p_organization_id uuid)
RETURNS integer
LANGUAGE plpgsql
AS $function$
DECLARE
  v_updated INTEGER := 0;
  v_row RECORD;
  v_detected_at TIMESTAMPTZ;
  v_max_hours INTEGER;
  v_warning_pct INTEGER;
BEGIN
  FOR v_row IN
    SELECT pdv.id, pdv.project_id, pdv.osv_id, pdv.severity, pdv.created_at
    FROM public.project_dependency_vulnerabilities pdv
    JOIN public.projects p ON p.id = pdv.project_id
    WHERE p.organization_id = p_organization_id
      AND (pdv.suppressed = false OR pdv.suppressed IS NULL)
      AND (pdv.risk_accepted = false OR pdv.risk_accepted IS NULL)
      AND pdv.sla_status IS NULL
      AND pdv.severity IN ('critical', 'high', 'medium', 'low')
  LOOP
    SELECT MIN(pve.created_at) INTO v_detected_at
    FROM public.project_vulnerability_events pve
    WHERE pve.project_id = v_row.project_id
      AND pve.osv_id = v_row.osv_id
      AND pve.event_type = 'detected';

    IF v_detected_at IS NULL THEN
      v_detected_at := v_row.created_at;
    END IF;

    SELECT f.max_hours, f.warning_threshold_percent INTO v_max_hours, v_warning_pct
    FROM public.get_effective_sla_policy(p_organization_id, v_row.severity) f;

    IF v_max_hours IS NULL THEN
      CONTINUE;
    END IF;

    UPDATE public.project_dependency_vulnerabilities
    SET
      detected_at = v_detected_at,
      sla_deadline_at = v_detected_at + (v_max_hours || ' hours')::INTERVAL,
      sla_warning_at = v_detected_at + (v_max_hours * COALESCE(v_warning_pct, 75) / 100.0 || ' hours')::INTERVAL,
      sla_status = CASE
        WHEN NOW() > v_detected_at + (v_max_hours || ' hours')::INTERVAL THEN 'breached'
        WHEN NOW() >= v_detected_at + (v_max_hours * COALESCE(v_warning_pct, 75) / 100.0 || ' hours')::INTERVAL THEN 'warning'
        ELSE 'on_track'
      END,
      sla_breached_at = CASE
        WHEN NOW() > v_detected_at + (v_max_hours || ' hours')::INTERVAL THEN v_detected_at + (v_max_hours || ' hours')::INTERVAL
        ELSE NULL
      END
    WHERE public.project_dependency_vulnerabilities.id = v_row.id;

    v_updated := v_updated + 1;
  END LOOP;

  RETURN v_updated;
END;
$function$;

-- ============================================================
-- 10. organization_sla_policies: drop asset_tier_id + dedupe + new UNIQUE
-- ============================================================
ALTER TABLE public.organization_sla_policies
  DROP CONSTRAINT IF EXISTS uq_sla_policies_org_severity_tier;
DROP INDEX IF EXISTS public.idx_sla_policies_asset_tier;
ALTER TABLE public.organization_sla_policies
  DROP CONSTRAINT IF EXISTS organization_sla_policies_asset_tier_id_fkey;

-- Collapse rows: when a NULL-tier ("default") row exists for (org, severity),
-- drop all tier-specific rows for that group. Then drop any remaining
-- duplicates by ctid order (keeps the row with the highest ctid).
DELETE FROM public.organization_sla_policies a
WHERE a.asset_tier_id IS NOT NULL
  AND EXISTS (
    SELECT 1 FROM public.organization_sla_policies b
    WHERE b.organization_id = a.organization_id
      AND b.severity = a.severity
      AND b.asset_tier_id IS NULL
  );

DELETE FROM public.organization_sla_policies a
USING public.organization_sla_policies b
WHERE a.ctid < b.ctid
  AND a.organization_id = b.organization_id
  AND a.severity = b.severity;

ALTER TABLE public.organization_sla_policies DROP COLUMN IF EXISTS asset_tier_id;

ALTER TABLE public.organization_sla_policies
  ADD CONSTRAINT uq_sla_policies_org_severity UNIQUE (organization_id, severity);

-- ============================================================
-- 11. Drop organization_reachability_settings.trigger_asset_tier_max_rank
-- ============================================================
ALTER TABLE public.organization_reachability_settings
  DROP COLUMN IF EXISTS trigger_asset_tier_max_rank;

-- ============================================================
-- 12. Drop projects.asset_tier + projects.asset_tier_id
-- ============================================================
DROP INDEX IF EXISTS public.idx_projects_asset_tier_id;
ALTER TABLE public.projects DROP CONSTRAINT IF EXISTS projects_asset_tier_id_fkey;
ALTER TABLE public.projects
  DROP COLUMN IF EXISTS asset_tier_id,
  DROP COLUMN IF EXISTS asset_tier;

-- ============================================================
-- 13. Drop organization_asset_tiers table (CASCADE clears stragglers)
-- ============================================================
DROP TABLE IF EXISTS public.organization_asset_tiers CASCADE;

-- ============================================================
-- 14. Drop the asset_tier enum type
-- ============================================================
DROP TYPE IF EXISTS public.asset_tier;

COMMIT;
