-- Phase 23b: DAST schema — config + findings + atomic-commit + concurrency caps.
--
-- Builds on phase23 (scan_jobs consolidation). Adds:
--   1. project_dast_config           — per-project target URL + scan settings
--   2. project_dast_findings         — DAST findings, atomic-commit-keyed by dast_run_id
--   3. projects.active/previous_dast_run_id  — Phase 19-style atomic pointer
--   4. commit_dast_run RPC           — suppression carry-forward + pointer flip
--   5. queue_scan_job hardening      — DAST concurrency caps (1/project, 3/org)
--                                     + DB-layer SSRF defense (literal-IP block)
--
-- v1 scope: ZAP only, anon scans, single target_url, manual trigger. Phase 2
-- ALTERs target_url → TEXT[], adds auth_strategy + encrypted_credentials,
-- scan-on-extraction trigger, scheduled scans.
--
-- See `.cursor/plans/dast.plan.md` v3 for the locked architecture.

-- =============================================================================
-- 1. project_dast_config
-- =============================================================================
CREATE TABLE IF NOT EXISTS project_dast_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  enabled BOOLEAN NOT NULL DEFAULT false,
  target_url TEXT,
  scan_profile TEXT NOT NULL DEFAULT 'auto'
    CHECK (scan_profile IN ('auto', 'quick', 'full', 'api')),
  scan_timeout_minutes INTEGER NOT NULL DEFAULT 30
    CHECK (scan_timeout_minutes BETWEEN 5 AND 60),

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id)
);

CREATE INDEX IF NOT EXISTS idx_project_dast_config_org
  ON project_dast_config(organization_id);

ALTER TABLE project_dast_config ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS project_dast_config_org_select ON project_dast_config;
CREATE POLICY project_dast_config_org_select
  ON project_dast_config FOR SELECT
  USING (
    organization_id IN (
      SELECT om.organization_id
      FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

COMMENT ON TABLE project_dast_config IS
  'Phase 23b: per-project DAST settings (target URL, scan profile, timeout). v1 ships single target_url; phase 2 ALTERs to TEXT[] for staging+prod.';

-- =============================================================================
-- 2. project_dast_findings
-- =============================================================================
CREATE TABLE IF NOT EXISTS project_dast_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  dast_run_id TEXT NOT NULL,

  endpoint_url TEXT NOT NULL,
  http_method TEXT NOT NULL,
  vulnerability_type TEXT NOT NULL,
  severity TEXT NOT NULL
    CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
  cwe_id TEXT,
  owasp_top10_ref TEXT,
  rule_id TEXT,
  message TEXT,

  payload_redacted TEXT,
  response_evidence_redacted TEXT,
  confidence TEXT NOT NULL DEFAULT 'medium'
    CHECK (confidence IN ('confirmed', 'high', 'medium', 'low')),

  -- Cross-link target: handler resolved via project_entry_points + route-matcher.
  -- NULL when the DAST endpoint did not match any framework-detected route.
  handler_file_path TEXT,
  handler_function_name TEXT,
  handler_line INTEGER,

  -- SCA cross-link via stable identity (osv_id + project_dependency_id).
  -- v1 ships SCA only; SAST cross-link deferred to phase 2.
  linked_sca_osv_id TEXT,
  linked_sca_project_dependency_id UUID
    REFERENCES project_dependencies(id) ON DELETE SET NULL,
  cross_link_metadata JSONB DEFAULT '{}'::jsonb,

  status TEXT NOT NULL DEFAULT 'open'
    CHECK (status IN ('open', 'suppressed', 'risk_accepted', 'fixed')),
  risk_accepted_by UUID REFERENCES auth.users(id),
  risk_accepted_at TIMESTAMPTZ,
  risk_accepted_reason TEXT,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Atomic-commit dedup. Two partial unique indexes split by handler-resolution.
-- handler_file_path is the "stable identity" key when the cross-link resolved;
-- otherwise endpoint_url + method is the fallback.
DROP INDEX IF EXISTS project_dast_findings_resolved;
CREATE UNIQUE INDEX project_dast_findings_resolved
  ON project_dast_findings(
    project_id, dast_run_id, rule_id,
    handler_file_path, handler_function_name, vulnerability_type
  )
  WHERE handler_file_path IS NOT NULL;

DROP INDEX IF EXISTS project_dast_findings_unresolved;
CREATE UNIQUE INDEX project_dast_findings_unresolved
  ON project_dast_findings(
    project_id, dast_run_id, rule_id,
    endpoint_url, http_method, vulnerability_type
  )
  WHERE handler_file_path IS NULL;

CREATE INDEX IF NOT EXISTS idx_project_dast_findings_run
  ON project_dast_findings(project_id, dast_run_id);
CREATE INDEX IF NOT EXISTS idx_project_dast_findings_org_severity
  ON project_dast_findings(organization_id, severity, status)
  WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_project_dast_findings_handler
  ON project_dast_findings(project_id, handler_file_path, handler_function_name)
  WHERE handler_file_path IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_project_dast_findings_sca_link
  ON project_dast_findings(linked_sca_project_dependency_id)
  WHERE linked_sca_project_dependency_id IS NOT NULL;

ALTER TABLE project_dast_findings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS project_dast_findings_org_select ON project_dast_findings;
CREATE POLICY project_dast_findings_org_select
  ON project_dast_findings FOR SELECT
  USING (
    organization_id IN (
      SELECT om.organization_id
      FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

-- Realtime publication for live finding updates on the Security tab.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND schemaname = 'public'
      AND tablename = 'project_dast_findings'
  ) THEN
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE project_dast_findings';
  END IF;
END $$;

COMMENT ON TABLE project_dast_findings IS
  'Phase 23b: DAST findings. Atomic-commit-keyed: visibility gated by projects.active_dast_run_id. Cross-link to SCA via linked_sca_osv_id + linked_sca_project_dependency_id when route-matcher resolves the handler.';

-- =============================================================================
-- 3. projects.active_dast_run_id + previous_dast_run_id
-- =============================================================================
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS active_dast_run_id TEXT,
  ADD COLUMN IF NOT EXISTS previous_dast_run_id TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_active_dast_run
  ON projects(active_dast_run_id)
  WHERE active_dast_run_id IS NOT NULL;

COMMENT ON COLUMN projects.active_dast_run_id IS
  'Phase 23b atomic-commit pointer: which DAST run is currently visible. Findings query WHERE dast_run_id = projects.active_dast_run_id. NULL = no completed DAST scan yet.';
COMMENT ON COLUMN projects.previous_dast_run_id IS
  'Phase 23b: prior visible DAST run, kept for backend rollback. Reaper preserves this generation.';

-- =============================================================================
-- 4. commit_dast_run RPC — suppression carry-forward + atomic pointer flip
-- =============================================================================
CREATE OR REPLACE FUNCTION commit_dast_run(
  p_project_id UUID,
  p_dast_run_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
  v_prior_run_id TEXT;
BEGIN
  SELECT active_dast_run_id INTO v_prior_run_id
  FROM projects WHERE id = p_project_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_dast_run: project % not found', p_project_id;
  END IF;

  -- Carry forward suppression / risk-accepted state by stable identity.
  -- Match strategy: handler-resolved findings join on (rule_id, handler_*,
  -- vulnerability_type); unresolved on (rule_id, endpoint_url, http_method,
  -- vulnerability_type). Mirrors the partial unique indexes.
  IF v_prior_run_id IS NOT NULL THEN
    UPDATE project_dast_findings new_f
    SET status = old_f.status,
        risk_accepted_by = old_f.risk_accepted_by,
        risk_accepted_at = old_f.risk_accepted_at,
        risk_accepted_reason = old_f.risk_accepted_reason
    FROM project_dast_findings old_f
    WHERE new_f.project_id = p_project_id
      AND new_f.dast_run_id = p_dast_run_id
      AND old_f.project_id = p_project_id
      AND old_f.dast_run_id = v_prior_run_id
      AND old_f.rule_id IS NOT DISTINCT FROM new_f.rule_id
      AND old_f.vulnerability_type = new_f.vulnerability_type
      AND old_f.status <> 'open'
      AND (
        (old_f.handler_file_path IS NOT NULL
          AND new_f.handler_file_path IS NOT NULL
          AND old_f.handler_file_path = new_f.handler_file_path
          AND old_f.handler_function_name IS NOT DISTINCT FROM new_f.handler_function_name)
        OR
        (old_f.handler_file_path IS NULL
          AND new_f.handler_file_path IS NULL
          AND old_f.endpoint_url = new_f.endpoint_url
          AND old_f.http_method = new_f.http_method)
      );
  END IF;

  -- Atomic pointer flip.
  UPDATE projects
  SET previous_dast_run_id = active_dast_run_id,
      active_dast_run_id = p_dast_run_id
  WHERE id = p_project_id;
END;
$$;

COMMENT ON FUNCTION commit_dast_run IS
  'Phase 23b: atomic commit of a DAST run. Carries forward suppressed/risk_accepted state from the prior active run by stable identity (handler-resolved or endpoint+method), then flips active_dast_run_id pointer.';

-- =============================================================================
-- 5. queue_scan_job hardening — DAST concurrency caps + literal-IP SSRF defense
--    (full DNS-resolved SSRF check stays in TS validateExternalUrl;
--     this layer is defense-in-depth at the DB boundary.)
-- =============================================================================
DROP FUNCTION IF EXISTS queue_scan_job(UUID, UUID, TEXT, JSONB, TEXT, TEXT, INTEGER, TEXT, UUID);

CREATE OR REPLACE FUNCTION queue_scan_job(
  p_project_id      UUID,
  p_organization_id UUID,
  p_type            TEXT,
  p_payload         JSONB,
  p_target_url       TEXT    DEFAULT NULL,
  p_scan_profile     TEXT    DEFAULT NULL,
  p_timeout_minutes  INTEGER DEFAULT NULL,
  p_trigger_source   TEXT    DEFAULT NULL,
  p_triggered_by     UUID    DEFAULT NULL
)
RETURNS scan_jobs
LANGUAGE plpgsql AS $$
DECLARE
  v_project_concurrent INTEGER;
  v_org_concurrent INTEGER;
  v_host TEXT;
  v_inserted scan_jobs%ROWTYPE;
BEGIN
  -- DAST-specific guards. Extraction path bypasses these.
  IF p_type = 'dast' THEN
    -- 1. SSRF defense-in-depth: block obvious literal-IP loopback / RFC1918 /
    --    link-local at the DB layer. Full hostname DNS resolution lives in
    --    backend/src/lib/url-guard.ts; this catches the case where someone
    --    bypasses the route handler.
    IF p_target_url IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: target_url is required for type=dast'
        USING ERRCODE = 'P0001';
    END IF;

    -- Extract host segment. Matches scheme://host:port/path with host capturing
    -- up to the first ':' or '/'.
    v_host := lower(
      substring(p_target_url FROM '^[a-z]+://([^:/?#]+)')
    );

    IF v_host IS NULL OR v_host = '' THEN
      RAISE EXCEPTION 'queue_scan_job: target_url must be http(s) URL with host'
        USING ERRCODE = 'P0001';
    END IF;

    -- Block literal localhost + literal IPv4/IPv6 in the loopback / private /
    -- link-local / IMDS / Fly internal classes. Hostnames go through
    -- validateExternalUrl()'s DNS check at the route layer.
    IF v_host = 'localhost'
       OR v_host = '0.0.0.0'
       OR v_host = '::1'
       OR v_host LIKE '127.%'
       OR v_host LIKE '10.%'
       OR v_host LIKE '192.168.%'
       OR v_host ~ '^172\.(1[6-9]|2[0-9]|3[0-1])\.'
       OR v_host LIKE '169.254.%'
       OR v_host LIKE 'fe80:%'
       OR v_host LIKE 'fdaa:%'
       OR v_host LIKE '%.internal'
       OR v_host LIKE '%.fly.dev.internal' THEN
      RAISE EXCEPTION 'queue_scan_job: target_url host % rejected (private/loopback/internal)', v_host
        USING ERRCODE = 'P0001';
    END IF;

    -- 2. Per-project concurrency cap: 1 active DAST job at a time.
    SELECT COUNT(*) INTO v_project_concurrent
    FROM scan_jobs
    WHERE project_id = p_project_id
      AND type = 'dast'
      AND status IN ('queued', 'processing');

    IF v_project_concurrent >= 1 THEN
      RAISE EXCEPTION 'queue_scan_job: project_concurrent_dast_blocked'
        USING ERRCODE = 'P0001',
              DETAIL = 'A DAST scan is already queued or running for this project.';
    END IF;

    -- 3. Per-org concurrency cap: 3 concurrent DAST jobs.
    SELECT COUNT(*) INTO v_org_concurrent
    FROM scan_jobs
    WHERE organization_id = p_organization_id
      AND type = 'dast'
      AND status IN ('queued', 'processing');

    IF v_org_concurrent >= 3 THEN
      RAISE EXCEPTION 'queue_scan_job: org_concurrent_dast_cap'
        USING ERRCODE = 'P0001',
              DETAIL = 'Organization is at the 3-concurrent DAST scan cap.';
    END IF;
  END IF;

  INSERT INTO scan_jobs (
    project_id, organization_id, type, payload,
    target_url, scan_profile, timeout_minutes, trigger_source, triggered_by
  )
  VALUES (
    p_project_id, p_organization_id, p_type, COALESCE(p_payload, '{}'::jsonb),
    p_target_url, p_scan_profile, p_timeout_minutes, p_trigger_source, p_triggered_by
  )
  RETURNING * INTO v_inserted;

  RETURN v_inserted;
END;
$$;

COMMENT ON FUNCTION queue_scan_job IS
  'Phase 23b: type-aware scan-job insert. For type=dast, enforces 1-concurrent-per-project + 3-concurrent-per-org caps and a literal-IP SSRF defense (hostname DNS check is in TS validateExternalUrl). Extraction inserts unchanged.';
