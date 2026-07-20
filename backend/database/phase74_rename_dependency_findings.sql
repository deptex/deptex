-- ============================================================================
-- phase74_rename_dependency_findings.sql
--
-- DB naming realignment: the SCA finding family joins the project_*_findings
-- convention used by every other finding family.
--
--   project_dependency_vulnerabilities  ->  project_dependency_findings
--   project_vulnerability_events        ->  project_dependency_finding_events
--
-- Pure rename — no behavior change. Postgres stores function bodies as text,
-- so renaming a table does NOT rewrite the functions that reference it; every
-- function whose body names one of the renamed tables is recreated verbatim
-- below (bodies identical except for the table names).
--
-- Naming decisions (see also the PR's MAPPING.md):
--   * "pdv" is RETAINED as the abbreviation for a row of
--     project_dependency_findings (historically "project dependency
--     vulnerability"): columns project_composition_partners.pdv_id and
--     silence_events.pdv_id, trigger trg_pdv_finding_status, the idx_pdv_* /
--     chk_pdv_* / pdv_extraction_run_unique objects, the *_from_pdv RPC
--     suffix, and the pdv_id JSON key in the composition payload. The natural
--     successor initialism "pdf" collides with the document format, and pdv is
--     wired through the worker, backend, and historical migrations. It is now
--     an opaque legacy token, documented via COMMENT ON TABLE below.
--     "pve" (idx_pve_*) is retained for project_dependency_finding_events on
--     the same policy. Only object names that spell out a full old table name
--     are renamed.
--   * The global advisory catalog `dependency_vulnerabilities` KEEPS its name:
--     it stores vulnerabilities/advisories (facts about CVEs), not findings
--     (observations in a project).
--   * The polymorphic subtype label finding_type = 'vulnerability' KEEPS its
--     value: "Dependency vulnerabilities" is still the category name.
--
-- Also included (trivial): ai_usage_logs_tier_check drops the dead 'byok'
-- value (BYOK retired in phase29_drop_byok). Recreated NOT VALID so
-- historical byok rows survive; new writes must be 'platform'.
--
-- Forward-only, idempotent: safe to re-run.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Table renames
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF to_regclass('public.project_dependency_vulnerabilities') IS NOT NULL THEN
    ALTER TABLE public.project_dependency_vulnerabilities RENAME TO project_dependency_findings;
  END IF;
  IF to_regclass('public.project_vulnerability_events') IS NOT NULL THEN
    ALTER TABLE public.project_vulnerability_events RENAME TO project_dependency_finding_events;
  END IF;
END $$;

-- ---------------------------------------------------------------------------
-- 2. Constraint renames — only names that spell out an old table name.
--    (pdv/pve-abbreviated constraint names are intentionally retained.)
-- ---------------------------------------------------------------------------
DO $$
DECLARE
  r record;
BEGIN
  FOR r IN
    SELECT * FROM (VALUES
      ('project_dependency_findings',       'project_dependency_vulnerabilities_pkey',                         'project_dependency_findings_pkey'),
      ('project_dependency_findings',       'project_dependency_vulnerabilities_project_dependency_id_fkey',   'project_dependency_findings_project_dependency_id_fkey'),
      ('project_dependency_findings',       'project_dependency_vulnerabilities_project_id_fkey',              'project_dependency_findings_project_id_fkey'),
      -- old name was truncated to 63 chars by Postgres; new name is deliberate
      ('project_dependency_findings',       'project_dependency_vulnerabilities_runtime_confirmed_dast_findi', 'project_dependency_findings_runtime_confirmed_dast_fkey'),
      ('project_dependency_finding_events', 'project_vulnerability_events_pkey',                               'project_dependency_finding_events_pkey'),
      ('project_dependency_finding_events', 'project_vulnerability_events_project_dependency_id_fkey',         'project_dependency_finding_events_project_dependency_id_fkey'),
      ('project_dependency_finding_events', 'project_vulnerability_events_project_id_fkey',                    'project_dependency_finding_events_project_id_fkey')
    ) AS t(tbl, old_name, new_name)
  LOOP
    IF EXISTS (
      SELECT 1 FROM pg_constraint c
      WHERE c.conname  = r.old_name
        AND c.conrelid = ('public.' || r.tbl)::regclass
    ) THEN
      EXECUTE format('ALTER TABLE public.%I RENAME CONSTRAINT %I TO %I', r.tbl, r.old_name, r.new_name);
    END IF;
  END LOOP;
END $$;

-- ---------------------------------------------------------------------------
-- 3. Index renames — same policy (idx_pdv_* / idx_pve_* / idx_pcp_* retained).
--    Constraint-backed indexes (pkey, unique) were renamed with their
--    constraints above.
-- ---------------------------------------------------------------------------
ALTER INDEX IF EXISTS public.idx_project_dependency_vulnerabilities_osv_id RENAME TO idx_project_dependency_findings_osv_id;
ALTER INDEX IF EXISTS public.idx_project_dependency_vulnerabilities_project_dependency_id RENAME TO idx_project_dependency_findings_project_dependency_id;
ALTER INDEX IF EXISTS public.idx_project_dependency_vulnerabilities_project_id RENAME TO idx_project_dependency_findings_project_id;
ALTER INDEX IF EXISTS public.idx_project_dependency_vulnerabilities_severity RENAME TO idx_project_dependency_findings_severity;
ALTER INDEX IF EXISTS public.project_dependency_vulnerabilities_runtime_confirmed_fk RENAME TO project_dependency_findings_runtime_confirmed_fk;

-- ---------------------------------------------------------------------------
-- 4. Document the retained "pdv" / "pve" abbreviations on the tables
-- ---------------------------------------------------------------------------
COMMENT ON TABLE public.project_dependency_findings IS
  'SCA findings: one row per (project, dependency, advisory, extraction run). Formerly project_dependency_vulnerabilities; rows are still abbreviated "pdv" in column, index, trigger, and function names — retained because the successor initialism collides with the PDF document format.';
COMMENT ON TABLE public.project_dependency_finding_events IS
  'Timeline events (introduced / resolved / reachability changes) for dependency findings. Formerly project_vulnerability_events; still abbreviated "pve" in index names.';

-- ---------------------------------------------------------------------------
-- 5. Renamed RPCs — old names dropped, recreated under the findings noun.
--
--      get_project_vulnerabilities           -> get_project_dependency_findings
--      get_project_vulnerabilities_from_pdv  -> get_project_dependency_findings_from_pdv
--      get_vulnerability_detail_bundle       -> get_dependency_finding_detail_bundle
--
--    commit_extraction keeps its name but its p_vulnerabilities parameter
--    becomes p_dependency_findings; Postgres cannot rename an input parameter
--    via CREATE OR REPLACE, so it is dropped and recreated. (The RPC currently
--    has no live caller — the worker writes rows directly and calls
--    finalize_extraction — but it is kept as-is apart from the rename.)
-- ---------------------------------------------------------------------------
DROP FUNCTION IF EXISTS public.get_project_vulnerabilities(uuid);
DROP FUNCTION IF EXISTS public.get_project_vulnerabilities_from_pdv(uuid);
DROP FUNCTION IF EXISTS public.get_vulnerability_detail_bundle(uuid, text);
DROP FUNCTION IF EXISTS public.commit_extraction(uuid, uuid, text, jsonb, jsonb, jsonb, jsonb, jsonb, jsonb, jsonb, jsonb);

CREATE OR REPLACE FUNCTION public.get_project_dependency_findings(p_project_id uuid)
 RETURNS TABLE(id uuid, dependency_id uuid, osv_id text, severity text, summary text, details text, aliases text[], fixed_versions text[], published_at timestamp with time zone, modified_at timestamp with time zone, created_at timestamp with time zone, dependency_name text, dependency_version text)
 LANGUAGE sql
 STABLE
AS $function$
  SELECT
    dv.id,
    dv.dependency_id,
    dv.osv_id,
    dv.severity,
    dv.summary,
    dv.details,
    dv.aliases,
    dv.fixed_versions,
    dv.published_at,
    dv.modified_at,
    dv.created_at,
    pd.name AS dependency_name,
    pd.version AS dependency_version
  FROM dependency_vulnerabilities dv
  INNER JOIN project_dependencies pd
    ON pd.dependency_id = dv.dependency_id
   AND pd.project_id = p_project_id;
$function$
;

CREATE OR REPLACE FUNCTION public.get_project_dependency_findings_from_pdv(p_project_id uuid)
 RETURNS TABLE(id uuid, dependency_id uuid, osv_id text, severity text, summary text, details text, aliases text[], fixed_versions text[], published_at timestamp with time zone, modified_at timestamp with time zone, created_at timestamp with time zone, dependency_name text, dependency_version text, is_reachable boolean, reachability_level text, reachability_details jsonb, epss_score numeric, cvss_score numeric, cisa_kev boolean, depscore integer, contextual_depscore numeric, entry_point_classification text, epd_status text, sla_status text, sla_deadline_at timestamp with time zone, runtime_confirmed_at timestamp with time zone, finding_key text, status text, auto_ignored boolean, auto_ignore_reason text, ignore_reason text, ignore_note text, suppressed boolean, risk_accepted boolean)
 LANGUAGE sql
 STABLE
AS $function$
  SELECT
    pdv.id, pd.dependency_id, pdv.osv_id, pdv.severity, pdv.summary,
    NULL::TEXT AS details, pdv.aliases, pdv.fixed_versions, pdv.published_at,
    NULL::TIMESTAMPTZ AS modified_at, pdv.created_at,
    CASE
      WHEN pd.namespace IS NOT NULL AND pd.namespace <> '' AND left(pd.namespace, 1) = '@'
        THEN pd.namespace || '/' || pd.name
      ELSE pd.name
    END AS dependency_name,
    pd.version AS dependency_version, pdv.is_reachable, pdv.reachability_level,
    pdv.reachability_details, pdv.epss_score, pdv.cvss_score, pdv.cisa_kev,
    pdv.depscore, pdv.contextual_depscore, pdv.entry_point_classification,
    pdv.epd_status, pdv.sla_status, pdv.sla_deadline_at, pdv.runtime_confirmed_at,
    pdv.finding_key, pdv.status, pdv.auto_ignored, pdv.auto_ignore_reason,
    pdv.ignore_reason, pdv.ignore_note, pdv.suppressed, pdv.risk_accepted
  FROM project_dependency_findings pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id AND pd.project_id = pdv.project_id
  INNER JOIN projects p ON p.id = pdv.project_id
  WHERE pdv.project_id = p_project_id
    AND pdv.extraction_run_id = p.active_extraction_run_id;
$function$
;

CREATE OR REPLACE FUNCTION public.get_dependency_finding_detail_bundle(p_project_id uuid, p_osv_id text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE
AS $function$
WITH proj AS (
  SELECT organization_id, active_extraction_run_id, importance
  FROM projects
  WHERE id = p_project_id
),
pdv AS (
  SELECT *
  FROM project_dependency_findings v
  WHERE v.project_id = p_project_id
    AND v.osv_id = p_osv_id
    AND v.extraction_run_id = (SELECT active_extraction_run_id FROM proj)
),
deps AS (
  SELECT pd.id, pd.name, pd.version, pd.is_direct, pd.dependency_id,
         pd.files_importing_count, pd.environment
  FROM project_dependencies pd
  WHERE pd.id IN (SELECT v.project_dependency_id FROM pdv v WHERE v.project_dependency_id IS NOT NULL)
    AND pd.removed_at IS NULL
),
advisory AS (
  SELECT dv.summary, dv.details, dv.aliases, dv.affected_versions,
         dv.fixed_versions, dv.published_at, dv.modified_at
  FROM dependency_vulnerabilities dv
  WHERE dv.osv_id = p_osv_id OR dv.aliases @> ARRAY[p_osv_id]
  ORDER BY (dv.osv_id = p_osv_id) DESC
  LIMIT 1
),
flow_osv_ids AS (
  SELECT p_osv_id AS osv_id
  UNION
  SELECT unnest(COALESCE((SELECT v.aliases FROM pdv v LIMIT 1), '{}'::text[]))
  UNION
  SELECT unnest(COALESCE((SELECT a.aliases FROM advisory a), '{}'::text[]))
),
flows AS (
  SELECT f.*
  FROM project_reachable_flows f
  WHERE f.project_id = p_project_id
    AND f.dependency_id IN (SELECT d.dependency_id FROM deps d WHERE d.dependency_id IS NOT NULL)
    AND f.osv_id IN (SELECT osv_id FROM flow_osv_ids)
    AND f.extraction_run_id = (SELECT active_extraction_run_id FROM proj)
  ORDER BY f.flow_length ASC
  LIMIT 20
)
SELECT jsonb_build_object(
  'importance', (SELECT importance FROM proj),
  'vulnerabilities', COALESCE((SELECT jsonb_agg(to_jsonb(v)) FROM pdv v), '[]'::jsonb),
  'affected_dependencies', COALESCE((
    SELECT jsonb_agg(
      to_jsonb(d) || jsonb_build_object(
        'files', COALESCE((
          SELECT jsonb_agg(f.file_path)
          FROM project_dependency_files f
          WHERE f.project_dependency_id = d.id
            AND f.extraction_run_id = (SELECT active_extraction_run_id FROM proj)
        ), '[]'::jsonb),
        'package_score', (SELECT COALESCE(dd.score, 0) FROM dependencies dd WHERE dd.id = d.dependency_id)
      )
    )
    FROM deps d
  ), '[]'::jsonb),
  'version_candidates', COALESCE((
    SELECT jsonb_agg(to_jsonb(c))
    FROM project_version_candidates c
    WHERE c.project_id = p_project_id
      AND c.package_name = (SELECT d.name FROM deps d LIMIT 1)
  ), '[]'::jsonb),
  'timeline_events', COALESCE((
    SELECT jsonb_agg(to_jsonb(e) ORDER BY e.created_at DESC)
    FROM (
      SELECT *
      FROM project_dependency_finding_events ev
      WHERE ev.project_id = p_project_id
        AND ev.osv_id = p_osv_id
      ORDER BY ev.created_at DESC
      LIMIT 50
    ) e
  ), '[]'::jsonb),
  'advisory', (SELECT to_jsonb(a) FROM advisory a),
  'reachable_flows', COALESCE((
    SELECT jsonb_agg(
      to_jsonb(fl) || jsonb_build_object(
        'is_suppressed',
        CASE
          WHEN fl.flow_signature_hash IS NULL THEN false
          ELSE EXISTS (
            SELECT 1 FROM project_reachable_flow_suppressions s
            WHERE s.project_id = p_project_id
              AND s.flow_signature_hash = fl.flow_signature_hash
          )
        END
      )
      ORDER BY fl.flow_length ASC
    )
    FROM flows fl
  ), '[]'::jsonb)
);
$function$
;

CREATE OR REPLACE FUNCTION public.commit_extraction(p_job_id uuid, p_project_id uuid, p_extraction_run_id text, p_dependencies jsonb, p_dependency_findings jsonb, p_semgrep_findings jsonb, p_secret_findings jsonb, p_reachable_flows jsonb, p_usage_slices jsonb, p_dependency_files jsonb, p_dependency_functions jsonb)
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
    SELECT * FROM jsonb_to_recordset(p_dependency_findings) AS v(
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
  INSERT INTO public.project_dependency_findings (
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
      UPDATE public.project_dependency_findings new_pdv
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
        FROM public.project_dependency_findings opdv
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
      FROM public.project_dependency_findings npdv
      JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
      WHERE npdv.project_id = p_project_id
        AND npdv.extraction_run_id = p_extraction_run_id
        AND NOT EXISTS (
          SELECT 1
          FROM public.project_dependency_findings opdv
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
          FROM public.project_dependency_findings opdv
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
      INSERT INTO public.project_dependency_finding_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
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
    INSERT INTO public.project_dependency_finding_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected', p_extraction_run_id, npdv.project_dependency_id,
           jsonb_build_object('dep_name', npd.name),
           v_now
    FROM public.project_dependency_findings npdv
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
  FROM public.project_dependency_findings npdv
  JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
  WHERE npdv.project_id = p_project_id
    AND npdv.extraction_run_id = p_extraction_run_id
    AND (lower(COALESCE(npdv.severity, '')) = 'critical' OR npdv.cisa_kev = true)
    AND (
      v_prev_active IS NULL
      OR NOT EXISTS (
        SELECT 1
        FROM public.project_dependency_findings opdv
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
      FROM public.project_dependency_findings pdv
      WHERE pdv.project_id = p_project_id
        AND pdv.extraction_run_id = p_extraction_run_id
        AND pdv.sla_status IS NULL
        AND pdv.severity IN ('critical', 'high', 'medium', 'low')
    LOOP
      SELECT max_hours, warning_threshold_percent INTO v_sla_hours, v_sla_warn_pct
      FROM public.get_effective_sla_policy(v_org_id, v_sla_row.severity);

      IF v_sla_hours IS NOT NULL THEN
        UPDATE public.project_dependency_findings
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
$function$
;


-- ---------------------------------------------------------------------------
-- 6. Recreated functions (names unchanged) — every remaining function whose
--    body references a renamed table, recreated verbatim with the new names.
--    Bodies are byte-identical to backend/database/schema.sql.
--    (trg_pdv_finding_status needs no recreation: its body references no
--    renamed table, and the trigger itself follows the table rename by OID.)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION public.apply_composition_results(p_project_id uuid, p_run_id text, p_updates jsonb)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'pg_catalog'
AS $function$
DECLARE
  updated_count integer;
BEGIN
  WITH updates AS (
    SELECT (e->>'pdv_id')::uuid  AS pdv_id,
           (e->>'factor')::numeric AS factor
      FROM jsonb_array_elements(p_updates) e
  ),
  result AS (
    UPDATE public.project_dependency_findings pdv
       SET composition_factor = u.factor,
           contextual_depscore = ROUND(pdv.contextual_depscore * u.factor, 4)
      FROM updates u
     WHERE pdv.id = u.pdv_id
       AND pdv.project_id = p_project_id
       AND pdv.extraction_run_id = p_run_id
       AND pdv.contextual_depscore IS NOT NULL
    RETURNING 1
  )
  SELECT count(*) INTO updated_count FROM result;
  RETURN updated_count;
END;
$function$
;

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
    FROM public.project_dependency_findings pdv
    JOIN public.projects p ON p.id = pdv.project_id
    WHERE p.organization_id = p_organization_id
      AND (pdv.suppressed = false OR pdv.suppressed IS NULL)
      AND (pdv.risk_accepted = false OR pdv.risk_accepted IS NULL)
      AND pdv.sla_status IS NULL
      AND pdv.severity IN ('critical', 'high', 'medium', 'low')
  LOOP
    SELECT MIN(pve.created_at) INTO v_detected_at
    FROM public.project_dependency_finding_events pve
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

    UPDATE public.project_dependency_findings
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
    WHERE public.project_dependency_findings.id = v_row.id;

    v_updated := v_updated + 1;
  END LOOP;

  RETURN v_updated;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.confirm_pdvs_from_dast_run(p_project_id uuid, p_dast_run_id text)
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
    JOIN public.project_dependency_findings pdv
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
    UPDATE public.project_dependency_findings pdv
       SET reachability_level             = 'confirmed',
           runtime_confirmed_at           = now(),
           runtime_confirmed_dast_finding_id = m.dast_finding_id,
           runtime_confirmed_prior_level  = m.prior_level,
           contextual_depscore = CASE
             WHEN pdv.contextual_depscore IS NULL THEN
               ROUND(
                 COALESCE(pdv.base_depscore_no_reachability, pdv.depscore, 0)
                   * COALESCE(pdv.epd_factor, 1.0),
                 4)
             ELSE pdv.contextual_depscore
           END
      FROM matches m
     WHERE pdv.id = m.pdv_id
    RETURNING pdv.id, pdv.osv_id, m.prior_level AS prior_level,
              pdv.reachability_level AS new_level
  )
  SELECT updated.id, updated.osv_id, updated.prior_level, updated.new_level FROM updated;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.enforce_composition_same_project()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
DECLARE
  pcf_project UUID;
  pdv_project UUID;
BEGIN
  SELECT project_id INTO pcf_project FROM public.project_container_findings WHERE id = NEW.container_finding_id;
  SELECT project_id INTO pdv_project FROM public.project_dependency_findings WHERE id = NEW.pdv_id;
  IF pcf_project IS NULL OR pdv_project IS NULL THEN
    RAISE EXCEPTION 'composition partner finding not found (pcf=% pdv=%)', NEW.container_finding_id, NEW.pdv_id;
  END IF;
  IF pcf_project != pdv_project OR pcf_project != NEW.project_id THEN
    RAISE EXCEPTION 'composition partner findings must belong to same project';
  END IF;
  RETURN NEW;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.finalize_extraction(p_job_id uuid, p_project_id uuid, p_extraction_run_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SET statement_timeout TO '300s'
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
      UPDATE public.project_dependency_findings new_pdv
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
        FROM public.project_dependency_findings opdv
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
      FROM public.project_dependency_findings npdv
      JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
      WHERE npdv.project_id = p_project_id
        AND npdv.extraction_run_id = p_extraction_run_id
        AND NOT EXISTS (
          SELECT 1
          FROM public.project_dependency_findings opdv
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
          FROM public.project_dependency_findings opdv
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
      INSERT INTO public.project_dependency_finding_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
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
    INSERT INTO public.project_dependency_finding_events (project_id, osv_id, event_type, extraction_run_id, project_dependency_id, metadata, created_at)
    SELECT p_project_id, npdv.osv_id, 'detected', p_extraction_run_id, npdv.project_dependency_id,
           jsonb_build_object('dep_name', npd.name),
           v_now
    FROM public.project_dependency_findings npdv
    JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
    WHERE npdv.project_id = p_project_id
      AND npdv.extraction_run_id = p_extraction_run_id
    ON CONFLICT (project_id, osv_id, event_type, extraction_run_id, project_dependency_id)
      WHERE extraction_run_id IS NOT NULL
      DO NOTHING;

    SELECT COUNT(*) INTO v_pdv_new
    FROM public.project_dependency_findings
    WHERE project_id = p_project_id AND extraction_run_id = p_extraction_run_id;
  END IF;

  SELECT COUNT(*) INTO v_pdv_critical_new
  FROM public.project_dependency_findings npdv
  JOIN public.project_dependencies npd ON npd.id = npdv.project_dependency_id
  WHERE npdv.project_id = p_project_id
    AND npdv.extraction_run_id = p_extraction_run_id
    AND (lower(COALESCE(npdv.severity, '')) = 'critical' OR npdv.cisa_kev = true)
    AND (
      v_prev_active IS NULL
      OR NOT EXISTS (
        SELECT 1
        FROM public.project_dependency_findings opdv
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
      FROM public.project_dependency_findings pdv
      WHERE pdv.project_id = p_project_id
        AND pdv.extraction_run_id = p_extraction_run_id
        AND pdv.sla_status IS NULL
        AND pdv.severity IN ('critical', 'high', 'medium', 'low')
    LOOP
      SELECT max_hours, warning_threshold_percent INTO v_sla_hours, v_sla_warn_pct
      FROM public.get_effective_sla_policy(v_org_id, v_sla_row.severity);

      IF v_sla_hours IS NOT NULL THEN
        UPDATE public.project_dependency_findings
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
$function$
;

CREATE OR REPLACE FUNCTION public.get_sla_approaching_warning(p_batch_limit integer DEFAULT 200)
 RETURNS TABLE(id uuid, project_id uuid, organization_id uuid, osv_id text, severity text, sla_deadline_at timestamp with time zone, hours_remaining numeric)
 LANGUAGE sql
 STABLE
AS $function$
  SELECT pdv.id, pdv.project_id, p.organization_id, pdv.osv_id, pdv.severity,
         pdv.sla_deadline_at,
         EXTRACT(EPOCH FROM (pdv.sla_deadline_at - NOW())) / 3600 AS hours_remaining
  FROM project_dependency_findings pdv
  JOIN projects p ON p.id = pdv.project_id
  JOIN organizations o ON o.id = p.organization_id
  WHERE pdv.sla_status = 'on_track'
    AND pdv.sla_deadline_at IS NOT NULL
    AND pdv.sla_warning_at IS NOT NULL
    AND pdv.sla_warning_notified_at IS NULL
    AND o.sla_paused_at IS NULL
    AND NOW() >= pdv.sla_warning_at
    AND NOW() < pdv.sla_deadline_at
  ORDER BY pdv.sla_deadline_at ASC
  LIMIT p_batch_limit;
$function$
;

CREATE OR REPLACE FUNCTION public.get_sla_newly_breached(p_batch_limit integer DEFAULT 200)
 RETURNS TABLE(id uuid, project_id uuid, organization_id uuid, osv_id text, severity text, sla_deadline_at timestamp with time zone, hours_overdue numeric)
 LANGUAGE sql
 STABLE
AS $function$
  SELECT pdv.id, pdv.project_id, p.organization_id, pdv.osv_id, pdv.severity,
         pdv.sla_deadline_at,
         EXTRACT(EPOCH FROM (NOW() - pdv.sla_deadline_at)) / 3600 AS hours_overdue
  FROM project_dependency_findings pdv
  JOIN projects p ON p.id = pdv.project_id
  JOIN organizations o ON o.id = p.organization_id
  WHERE pdv.sla_status IN ('on_track', 'warning')
    AND pdv.sla_deadline_at IS NOT NULL
    AND pdv.sla_breach_notified_at IS NULL
    AND o.sla_paused_at IS NULL
    AND NOW() > pdv.sla_deadline_at
  ORDER BY pdv.sla_deadline_at ASC
  LIMIT p_batch_limit;
$function$
;

CREATE OR REPLACE FUNCTION public.project_stats_counts(p_project_id uuid, p_active_run_id text)
 RETURNS TABLE(vuln_total bigint, vuln_critical bigint, vuln_high bigint, vuln_medium bigint, vuln_low bigint, reachable_count bigint, sla_on_track bigint, sla_warning bigint, sla_breached bigint, sla_exempt bigint, sla_met bigint, sla_resolved_late bigint, deps_total bigint, deps_direct bigint, deps_transitive bigint, deps_outdated bigint, deps_compliant bigint, deps_failing bigint, deps_vulnerable bigint)
 LANGUAGE sql
 STABLE
AS $function$
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
    FROM project_dependency_findings
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
$function$
;

CREATE OR REPLACE FUNCTION public.reap_old_extractions(p_project_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_active TEXT;
  v_previous TEXT;
  v_pdv_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_iac_deleted INTEGER := 0;
  v_container_deleted INTEGER := 0;
  v_malicious_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
  v_entry_points_deleted INTEGER := 0;
  v_mal_dep_ids uuid[];
BEGIN
  SELECT active_extraction_run_id, previous_extraction_run_id
    INTO v_active, v_previous
  FROM projects WHERE id = p_project_id;

  IF v_active IS NULL THEN
    RETURN jsonb_build_object('skipped', true, 'reason', 'no_active_run');
  END IF;

  DELETE FROM project_dependency_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_pdv_deleted = ROW_COUNT;

  DELETE FROM project_semgrep_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_semgrep_deleted = ROW_COUNT;

  DELETE FROM project_secret_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_secret_deleted = ROW_COUNT;

  DELETE FROM project_iac_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_iac_deleted = ROW_COUNT;

  DELETE FROM project_container_findings
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_container_deleted = ROW_COUNT;

  WITH del AS (
    DELETE FROM project_malicious_findings
    WHERE project_id = p_project_id
      AND extraction_run_id IS NOT NULL
      AND extraction_run_id <> v_active
      AND (v_previous IS NULL OR extraction_run_id <> v_previous)
    RETURNING dependency_id
  )
  SELECT array_agg(DISTINCT dependency_id), count(*)::integer
    INTO v_mal_dep_ids, v_malicious_deleted
  FROM del;

  IF v_mal_dep_ids IS NOT NULL AND array_length(v_mal_dep_ids, 1) > 0 THEN
    PERFORM public.recompute_dependency_is_malicious(v_mal_dep_ids);
  END IF;

  DELETE FROM project_reachable_flows
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_flows_deleted = ROW_COUNT;

  DELETE FROM project_usage_slices
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
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

  DELETE FROM project_entry_points
  WHERE project_id = p_project_id
    AND extraction_run_id IS NOT NULL
    AND extraction_run_id <> v_active
    AND (v_previous IS NULL OR extraction_run_id <> v_previous);
  GET DIAGNOSTICS v_entry_points_deleted = ROW_COUNT;

  RETURN jsonb_build_object(
    'project_id', p_project_id,
    'active', v_active,
    'previous', v_previous,
    'pdv_deleted', v_pdv_deleted,
    'semgrep_deleted', v_semgrep_deleted,
    'secret_deleted', v_secret_deleted,
    'iac_deleted', v_iac_deleted,
    'container_deleted', v_container_deleted,
    'malicious_deleted', v_malicious_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'dep_files_deleted', v_files_deleted,
    'dep_functions_deleted', v_fns_deleted,
    'entry_points_deleted', v_entry_points_deleted
  );
END;
$function$
;

CREATE OR REPLACE FUNCTION public.reap_orphaned_extractions(p_older_than_hours integer DEFAULT 24)
 RETURNS jsonb
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_orphan RECORD;
  v_cutoff TIMESTAMPTZ := NOW() - (p_older_than_hours || ' hours')::INTERVAL;
  v_runs_reaped INTEGER := 0;
  v_pdv_deleted INTEGER := 0;
  v_pd_deleted INTEGER := 0;
  v_semgrep_deleted INTEGER := 0;
  v_secret_deleted INTEGER := 0;
  v_iac_deleted INTEGER := 0;
  v_container_deleted INTEGER := 0;
  v_flows_deleted INTEGER := 0;
  v_slices_deleted INTEGER := 0;
  v_files_deleted INTEGER := 0;
  v_fns_deleted INTEGER := 0;
  v_events_deleted INTEGER := 0;
  v_entry_points_deleted INTEGER := 0;
  v_temp INTEGER;
  v_orphan_runs JSONB := '[]'::JSONB;
BEGIN
  FOR v_orphan IN
    SELECT DISTINCT sj.project_id, sj.id::TEXT AS run_id
    FROM scan_jobs sj
    JOIN projects p ON p.id = sj.project_id
    WHERE sj.type = 'extraction'
      AND sj.status IN ('failed', 'cancelled')
      AND sj.created_at < v_cutoff
      AND sj.id::TEXT IS DISTINCT FROM COALESCE(p.active_extraction_run_id, '')
      AND sj.id::TEXT IS DISTINCT FROM COALESCE(p.previous_extraction_run_id, '')
      AND NOT EXISTS (
        SELECT 1 FROM scan_jobs sj2
        WHERE sj2.project_id = sj.project_id
          AND sj2.type = 'extraction'
          AND sj2.status IN ('queued', 'processing')
      )
  LOOP
    DELETE FROM project_dependency_files
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_files_deleted := v_files_deleted + v_temp;

    DELETE FROM project_dependency_functions
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_fns_deleted := v_fns_deleted + v_temp;

    DELETE FROM project_dependency_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_pdv_deleted := v_pdv_deleted + v_temp;

    DELETE FROM project_semgrep_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_semgrep_deleted := v_semgrep_deleted + v_temp;

    DELETE FROM project_secret_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_secret_deleted := v_secret_deleted + v_temp;

    DELETE FROM project_iac_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_iac_deleted := v_iac_deleted + v_temp;

    DELETE FROM project_container_findings
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_container_deleted := v_container_deleted + v_temp;

    DELETE FROM project_reachable_flows
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_flows_deleted := v_flows_deleted + v_temp;

    DELETE FROM project_usage_slices
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_slices_deleted := v_slices_deleted + v_temp;

    DELETE FROM project_dependency_finding_events
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_events_deleted := v_events_deleted + v_temp;

    DELETE FROM project_entry_points
    WHERE extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_entry_points_deleted := v_entry_points_deleted + v_temp;

    DELETE FROM project_dependencies
    WHERE project_id = v_orphan.project_id
      AND last_seen_extraction_run_id = v_orphan.run_id;
    GET DIAGNOSTICS v_temp = ROW_COUNT;
    v_pd_deleted := v_pd_deleted + v_temp;

    v_orphan_runs := v_orphan_runs || jsonb_build_object(
      'project_id', v_orphan.project_id,
      'run_id', v_orphan.run_id
    );
    v_runs_reaped := v_runs_reaped + 1;
  END LOOP;

  RETURN jsonb_build_object(
    'cutoff_hours', p_older_than_hours,
    'runs_reaped', v_runs_reaped,
    'pdv_deleted', v_pdv_deleted,
    'pd_deleted', v_pd_deleted,
    'semgrep_deleted', v_semgrep_deleted,
    'secret_deleted', v_secret_deleted,
    'iac_deleted', v_iac_deleted,
    'container_deleted', v_container_deleted,
    'flows_deleted', v_flows_deleted,
    'slices_deleted', v_slices_deleted,
    'files_deleted', v_files_deleted,
    'fns_deleted', v_fns_deleted,
    'events_deleted', v_events_deleted,
    'entry_points_deleted', v_entry_points_deleted,
    'orphan_runs', v_orphan_runs
  );
END;
$function$
;

CREATE OR REPLACE FUNCTION public.resume_sla_shift_deadlines(p_organization_id uuid, p_pause_duration_seconds integer)
 RETURNS integer
 LANGUAGE plpgsql
AS $function$
DECLARE
  v_count INTEGER;
BEGIN
  UPDATE project_dependency_findings pdv
  SET
    sla_deadline_at = pdv.sla_deadline_at + (p_pause_duration_seconds || ' seconds')::INTERVAL,
    sla_warning_at = pdv.sla_warning_at + (p_pause_duration_seconds || ' seconds')::INTERVAL
  WHERE pdv.project_id IN (SELECT id FROM projects WHERE organization_id = p_organization_id)
    AND pdv.sla_status IN ('on_track', 'warning')
    AND pdv.sla_deadline_at IS NOT NULL;

  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$function$
;

CREATE OR REPLACE FUNCTION public.security_summary_counts(p_project_ids uuid[], p_active_run_ids text[])
 RETURNS TABLE(project_id uuid, vuln_count bigint, critical_count bigint, reachable_count bigint, worst_depscore numeric, band_critical bigint, band_high bigint, band_medium bigint, band_low bigint, ignored_count bigint, semgrep_count bigint, secret_count bigint, verified_secret_count bigint, has_container boolean, has_dast boolean, last_scan_at timestamp with time zone)
 LANGUAGE sql
 STABLE
AS $function$
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
      FROM project_dependency_findings pdv
      WHERE pdv.project_id = p.id
        AND pdv.extraction_run_id = ANY(p_active_run_ids)
        AND pdv.status NOT IN ('ignored', 'resolved')
    ) r
  ) v ON true
  LEFT JOIN LATERAL (
    SELECT count(*) AS ignored_count
    FROM project_dependency_findings pdv
    WHERE pdv.project_id = p.id
      AND pdv.extraction_run_id = ANY(p_active_run_ids)
      AND (
        pdv.status = 'ignored'
        OR COALESCE(pdv.suppressed, false) = true
        OR COALESCE(pdv.risk_accepted, false) = true
        OR (pdv.auto_ignored AND pdv.runtime_confirmed_at IS NULL)
      )
  ) ig ON true
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
$function$
;

CREATE OR REPLACE FUNCTION public.team_stats_counts(p_project_ids uuid[], p_active_run_ids text[])
 RETURNS TABLE(vuln_total bigint, vuln_critical bigint, vuln_high bigint, vuln_medium bigint, vuln_low bigint, sla_on_track bigint, sla_warning bigint, sla_breached bigint, sla_exempt bigint, sla_met bigint, sla_resolved_late bigint)
 LANGUAGE sql
 STABLE
AS $function$
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
  FROM project_dependency_findings
  WHERE project_id = ANY(p_project_ids)
    AND extraction_run_id = ANY(p_active_run_ids);
$function$
;

CREATE OR REPLACE FUNCTION public.team_top_vulns(p_project_ids uuid[], p_active_run_ids text[])
 RETURNS TABLE(osv_id text, depscore numeric, severity text, worst_project_id uuid, affected_project_count bigint)
 LANGUAGE sql
 STABLE
AS $function$
  WITH team_vulns AS (
    SELECT project_id, osv_id, severity, depscore
    FROM project_dependency_findings
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
$function$
;


-- ---------------------------------------------------------------------------
-- 7. Drop the dead 'byok' value from ai_usage_logs_tier_check.
--    BYOK was retired in phase29_drop_byok; new writes are always 'platform'.
--    NOT VALID: historical byok rows are left untouched, new rows are checked.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname  = 'ai_usage_logs_tier_check'
      AND conrelid = 'public.ai_usage_logs'::regclass
  ) THEN
    ALTER TABLE public.ai_usage_logs DROP CONSTRAINT ai_usage_logs_tier_check;
  END IF;
  ALTER TABLE public.ai_usage_logs ADD CONSTRAINT ai_usage_logs_tier_check CHECK (tier = 'platform'::text) NOT VALID;
END $$;
