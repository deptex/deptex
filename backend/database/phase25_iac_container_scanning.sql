-- Phase 25: IaC + Container scanning v1 (Foundation Lite)
-- New tables: project_iac_findings, project_container_findings
-- New column: projects.infra_types
-- Amends: finalize_extraction RPC for new-table carry-forward
--
-- Phase 23/24 numbers were already taken (semgrep_reachability + EPD work) so
-- this migration uses phase25 even though the plan filename said phase23.

-- ============================================================
-- IaC findings (Checkov + Trivy Dockerfile misconfigurations)
-- ============================================================
CREATE TABLE IF NOT EXISTS project_iac_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  scanner TEXT NOT NULL CHECK (scanner IN ('trivy', 'checkov')),
  scanner_version TEXT,
  rule_id TEXT NOT NULL,
  framework TEXT NOT NULL CHECK (framework IN ('terraform', 'kubernetes', 'dockerfile')),
  file_path TEXT NOT NULL,
  start_line INTEGER,
  -- Patch A: stored generated key so plain column-list onConflict can target the UNIQUE.
  -- Functional indexes (e.g. COALESCE(start_line, -1)) cannot be targeted by supabase-js
  -- .upsert onConflict, which only accepts a column list.
  start_line_key INTEGER NOT NULL GENERATED ALWAYS AS (COALESCE(start_line, -1)) STORED,
  end_line INTEGER,
  severity TEXT,
  depscore INTEGER,
  message TEXT,
  description TEXT,
  cwe_ids TEXT[],
  code_snippet TEXT,
  rule_doc_url TEXT,
  iac_fingerprint TEXT,
  metadata JSONB,
  status TEXT NOT NULL DEFAULT 'open',
  suppressed BOOLEAN DEFAULT false,
  suppressed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  suppressed_at TIMESTAMPTZ,
  risk_accepted BOOLEAN DEFAULT false,
  risk_accepted_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  risk_accepted_at TIMESTAMPTZ,
  risk_accepted_reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Patch A: plain column-list UNIQUE so supabase-js onConflict can target it.
-- start_line_key is the stored generated column above (COALESCE(start_line, -1)).
CREATE UNIQUE INDEX IF NOT EXISTS idx_piacf_unique
  ON project_iac_findings (project_id, rule_id, file_path, start_line_key, extraction_run_id);

-- Fingerprint partial UNIQUE for line-drift-tolerant status carryover.
-- `scanner` column included to defend against fingerprint format collisions
-- between Trivy (`trivy:AVD-...`) and Checkov (`checkov:CKV_...`) writers.
CREATE UNIQUE INDEX IF NOT EXISTS idx_piacf_fingerprint
  ON project_iac_findings (project_id, scanner, iac_fingerprint)
  WHERE iac_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_piacf_project_run
  ON project_iac_findings(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_piacf_org_status_depscore
  ON project_iac_findings(organization_id, status, depscore DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_piacf_severity ON project_iac_findings(severity);
CREATE INDEX IF NOT EXISTS idx_piacf_framework ON project_iac_findings(framework);

-- ============================================================
-- Container CVE findings (Trivy on pulled Dockerfile base images)
-- ============================================================
CREATE TABLE IF NOT EXISTS project_container_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  scanner_version TEXT,
  image_reference TEXT NOT NULL,
  image_digest TEXT NOT NULL,
  image_source TEXT NOT NULL CHECK (image_source IN ('dockerfile_base')),
  os_package_name TEXT NOT NULL,
  os_package_version TEXT NOT NULL,
  os_package_ecosystem TEXT,
  osv_id TEXT,
  cve_id TEXT,
  -- Patch B: GENERATED column resolves NULL osv_id/cve_id pair to a stable
  -- non-null value for inclusion in the UNIQUE index. Storage layer MUST NOT
  -- include vulnerability_id in upsert payloads — Postgres rejects explicit
  -- values for GENERATED ALWAYS columns.
  vulnerability_id TEXT NOT NULL GENERATED ALWAYS AS (
    COALESCE(osv_id, cve_id, 'unknown:' || md5(image_digest || ':' || os_package_name || ':' || os_package_version))
  ) STORED,
  severity TEXT,
  cvss_score NUMERIC(4, 1),
  epss_score NUMERIC(8, 6),
  is_kev BOOLEAN DEFAULT false,
  fix_versions TEXT[],
  layer_digest TEXT,
  depscore INTEGER,
  description TEXT,
  rule_doc_url TEXT,
  -- Digest-independent fingerprint survives base-image bumps (same package + CVE
  -- reappears on the new digest after a base-image rebuild).
  container_fingerprint TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  suppressed BOOLEAN DEFAULT false,
  suppressed_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  suppressed_at TIMESTAMPTZ,
  risk_accepted BOOLEAN DEFAULT false,
  risk_accepted_by UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  risk_accepted_at TIMESTAMPTZ,
  risk_accepted_reason TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pcf_unique
  ON project_container_findings (project_id, image_digest, os_package_name, os_package_version, vulnerability_id, extraction_run_id);

CREATE UNIQUE INDEX IF NOT EXISTS idx_pcf_fingerprint
  ON project_container_findings (project_id, container_fingerprint)
  WHERE container_fingerprint IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_pcf_project_run
  ON project_container_findings(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pcf_org_status_depscore
  ON project_container_findings(organization_id, status, depscore DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_pcf_severity ON project_container_findings(severity);

-- ============================================================
-- projects.infra_types (auto-populated by detect-infra step)
-- No GIN index at v1; v1.5 will add one via CREATE INDEX CONCURRENTLY in a
-- standalone migration when an org-wide "projects by framework" query lands.
-- ============================================================
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS infra_types TEXT[] NOT NULL DEFAULT '{}'::TEXT[];

-- ============================================================
-- Patch D: enforce organization_id on findings server-side.
-- Worker passes only project_id; trigger derives organization_id from projects.
-- Tampered/incorrect organization_id values from the caller are silently overwritten.
-- ============================================================
CREATE OR REPLACE FUNCTION enforce_finding_org_id() RETURNS TRIGGER AS $$
BEGIN
  NEW.organization_id := (SELECT organization_id FROM projects WHERE id = NEW.project_id);
  IF NEW.organization_id IS NULL THEN
    RAISE EXCEPTION 'enforce_finding_org_id: project % not found', NEW.project_id;
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS project_iac_findings_enforce_org_id ON project_iac_findings;
CREATE TRIGGER project_iac_findings_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON project_iac_findings
  FOR EACH ROW EXECUTE FUNCTION enforce_finding_org_id();

DROP TRIGGER IF EXISTS project_container_findings_enforce_org_id ON project_container_findings;
CREATE TRIGGER project_container_findings_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON project_container_findings
  FOR EACH ROW EXECUTE FUNCTION enforce_finding_org_id();

-- ============================================================
-- Amend finalize_extraction RPC for new-table carry-forward.
-- Mirrors existing project_semgrep_findings carry-forward but FINGERPRINT-ONLY:
-- no tuple fallback. Trivy/Checkov rule_id+file_path tuples are not as
-- semantically stable as Semgrep rule signatures — a renamed Terraform resource
-- block keeps the file_path but is, in user terms, a different finding. We
-- accept that fingerprint-NULL rows lose their decisions across re-extractions.
-- ============================================================
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
      SELECT u.pdv_id, u.pd_id, u.osv_id, u.dep_name,
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

  -- 6+7. Semgrep + secret status carry-forward (pre-existing behaviour)
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

    -- Phase 25: IaC findings carry-forward (fingerprint-only, scoped by scanner).
    -- Carries status + suppression + risk-accept across runs when the scanner
    -- emits a stable iac_fingerprint. Fingerprint-NULL rows lose decisions
    -- (intentional — see plan rationale).
    UPDATE project_iac_findings new_if
    SET
      status = old_if.status,
      suppressed = old_if.suppressed,
      suppressed_by = old_if.suppressed_by,
      suppressed_at = old_if.suppressed_at,
      risk_accepted = old_if.risk_accepted,
      risk_accepted_by = old_if.risk_accepted_by,
      risk_accepted_at = old_if.risk_accepted_at,
      risk_accepted_reason = old_if.risk_accepted_reason
    FROM project_iac_findings old_if
    WHERE new_if.project_id = p_project_id
      AND new_if.extraction_run_id = p_extraction_run_id
      AND new_if.iac_fingerprint IS NOT NULL
      AND old_if.project_id = p_project_id
      AND old_if.extraction_run_id = v_prev_active
      AND old_if.iac_fingerprint IS NOT NULL
      AND old_if.scanner = new_if.scanner
      AND old_if.iac_fingerprint = new_if.iac_fingerprint;

    -- Phase 25: Container findings carry-forward (fingerprint-only).
    -- container_fingerprint = `${package_name}@${vulnerability_id}` is digest-
    -- independent, so a base-image bump preserving the same package+CVE keeps
    -- the user's decision.
    UPDATE project_container_findings new_cf
    SET
      status = old_cf.status,
      suppressed = old_cf.suppressed,
      suppressed_by = old_cf.suppressed_by,
      suppressed_at = old_cf.suppressed_at,
      risk_accepted = old_cf.risk_accepted,
      risk_accepted_by = old_cf.risk_accepted_by,
      risk_accepted_at = old_cf.risk_accepted_at,
      risk_accepted_reason = old_cf.risk_accepted_reason
    FROM project_container_findings old_cf
    WHERE new_cf.project_id = p_project_id
      AND new_cf.extraction_run_id = p_extraction_run_id
      AND new_cf.container_fingerprint IS NOT NULL
      AND old_cf.project_id = p_project_id
      AND old_cf.extraction_run_id = v_prev_active
      AND old_cf.container_fingerprint IS NOT NULL
      AND old_cf.container_fingerprint = new_cf.container_fingerprint;
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
  'Phase 19.3 + Phase 25 amendment: primary commit path. Streams + carry-forward + triggers + events + SLA + pointer flip + reap. Phase 25 added IaC + container fingerprint carry-forward.';
