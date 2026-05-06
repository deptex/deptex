-- Phase 24a: DAST v2 engine — additive half of the two-phase migration.
--
-- v2.1a is the engine foundation carved out of the original v2.1 plan after
-- /review-plan returned REWORK 12/0/0. This migration is additive only — every
-- old RPC, every old column, every old finding-table shape stays in place;
-- new RPCs and new columns are added alongside via wrapper shims.
--
-- The destructive half (drop projects.active_dast_run_id, flip findings.target_id
-- NOT NULL, drop wrapper RPCs, drop DAST_RUNNER_MODE=helper_script flag) lands
-- in phase24b after a >= 7-day shadow window proves the new path safe and
-- pg_stat_user_functions shows zero calls to legacy commit_dast_run(uuid, text).
--
-- Adds:
--   1. project_dast_targets        — multi-target schema (1..N targets per project)
--   2. project_dast_credentials    — encrypted form/JWT/cookie auth, one per target
--   3. project_dast_config.scope_config (JSONB) — include/exclude regex + header rules
--   4. project_dast_findings.target_id / auth_state / engine / cross-link forward-prep
--   5. scan_jobs.target_id / credential_id / credential_payload_hash + widened trigger_source
--   6. commit_dast_target_run RPC (canonical, target-scoped)
--   7. commit_dast_run RPC (legacy wrapper delegating to canonical)
--   8. queue_scan_job RPC (new optional p_target_id arg + tenant-drift assert + per-org cap 5)
--   9. Realtime publication for project_dast_targets / project_dast_credentials
--   10. Two-pass backfill: synthetic-legacy targets + findings.target_id update
--
-- See `.cursor/plans/dast-v2-1a-engine.plan.md` for the full plan + 5 P0 cluster patches.

-- pgcrypto for SHA-256 digest used in queue_scan_job credential audit.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =============================================================================
-- 1. project_dast_targets — 1..N targets per project
-- =============================================================================
CREATE TABLE IF NOT EXISTS project_dast_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  target_url TEXT NOT NULL,
  label TEXT,
  enabled BOOLEAN NOT NULL DEFAULT true,

  -- SPA detection cache. Probe runs at POST /dast/scan time so machine-shape
  -- dispatch picks correct DAST_CONFIG BEFORE Fly machine provisions
  -- (eliminates SPA-OOM on shared-cpu-4x).
  detected_runtime TEXT NOT NULL DEFAULT 'unknown'
    CHECK (detected_runtime IN ('unknown', 'classic', 'spa')),
  detected_runtime_at TIMESTAMPTZ,
  detected_runtime_ttl_at TIMESTAMPTZ,

  -- Per-target atomic-commit pointer. Mirrors projects.active_dast_run_id but
  -- target-scoped. v2.1a writes to BOTH (legacy projects column + this column)
  -- via the wrapper RPC; phase24b drops the legacy projects columns.
  active_dast_run_id  TEXT,
  previous_dast_run_id TEXT,
  last_scanned_at TIMESTAMPTZ,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(project_id, target_url)
);

-- Per data-model-auditor P2: prevent two targets in same project sharing a label.
CREATE UNIQUE INDEX IF NOT EXISTS project_dast_targets_label_unique
  ON project_dast_targets(project_id, label)
  WHERE label IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_project_dast_targets_project
  ON project_dast_targets(project_id);
CREATE INDEX IF NOT EXISTS idx_project_dast_targets_org
  ON project_dast_targets(organization_id);
CREATE INDEX IF NOT EXISTS idx_project_dast_targets_active_run
  ON project_dast_targets(active_dast_run_id) WHERE active_dast_run_id IS NOT NULL;

ALTER TABLE project_dast_targets ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS project_dast_targets_org_select ON project_dast_targets;
CREATE POLICY project_dast_targets_org_select
  ON project_dast_targets FOR SELECT
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

-- INSERT/UPDATE/DELETE WITH CHECK — required for self-host RLS-as-enforcement-boundary
-- per multi-tenant-design-auditor cluster-3 patch.
DROP POLICY IF EXISTS project_dast_targets_org_insert ON project_dast_targets;
CREATE POLICY project_dast_targets_org_insert
  ON project_dast_targets FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS project_dast_targets_org_update ON project_dast_targets;
CREATE POLICY project_dast_targets_org_update
  ON project_dast_targets FOR UPDATE
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  )
  WITH CHECK (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS project_dast_targets_org_delete ON project_dast_targets;
CREATE POLICY project_dast_targets_org_delete
  ON project_dast_targets FOR DELETE
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

COMMENT ON TABLE project_dast_targets IS
  'Phase 24a: per-project DAST scan targets. Multi-target replaces v1 single project_dast_config.target_url. SPA detection cached on detected_runtime + 30-day TTL. Per-target atomic-commit pointer mirrors projects.active_dast_run_id during the v2.1a/b shadow window.';

-- =============================================================================
-- 2. project_dast_credentials — one encrypted credential per target
-- =============================================================================
CREATE TABLE IF NOT EXISTS project_dast_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target_id UUID NOT NULL UNIQUE REFERENCES project_dast_targets(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

  -- v2.1a: form|jwt|cookie. CHECK widened for forward-compat with v2.1d 'recorded'.
  auth_strategy TEXT NOT NULL
    CHECK (auth_strategy IN ('form', 'jwt', 'cookie', 'recorded')),
  -- AES-256-GCM ciphertext, base64-encoded. DAST_CREDENTIAL_KEY confined to
  -- depscanner env. Plaintext NEVER appears in scan_jobs.payload, error_details,
  -- worker stderr, or QStash payload (test-enforced via dast-log-scrub fixture).
  encrypted_payload TEXT NOT NULL,
  encryption_key_version INTEGER NOT NULL DEFAULT 1,

  -- Burp/StackHawk-style auth verification regex.
  logged_in_indicator  TEXT,
  logged_out_indicator TEXT,
  retry_login_on_lost  BOOLEAN NOT NULL DEFAULT false,

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_project_dast_credentials_org
  ON project_dast_credentials(organization_id);

ALTER TABLE project_dast_credentials ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS project_dast_credentials_org_select ON project_dast_credentials;
CREATE POLICY project_dast_credentials_org_select
  ON project_dast_credentials FOR SELECT
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS project_dast_credentials_org_insert ON project_dast_credentials;
CREATE POLICY project_dast_credentials_org_insert
  ON project_dast_credentials FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS project_dast_credentials_org_update ON project_dast_credentials;
CREATE POLICY project_dast_credentials_org_update
  ON project_dast_credentials FOR UPDATE
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  )
  WITH CHECK (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS project_dast_credentials_org_delete ON project_dast_credentials;
CREATE POLICY project_dast_credentials_org_delete
  ON project_dast_credentials FOR DELETE
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
    )
  );

COMMENT ON TABLE project_dast_credentials IS
  'Phase 24a: encrypted DAST auth credentials per target. v2.1a strategies: form/jwt/cookie. Recorded-login (HAR replay) deferred to v2.1d. Plaintext is decrypted only at worker spawn time inside buildAutomationYaml() and zeroed via Buffer.fill(0) immediately after.';

-- =============================================================================
-- 3. project_dast_config: additive scope_config column
-- =============================================================================
-- No DROP/RE-ADD on existing columns (would silently destroy customer settings).
-- target_url / scan_profile / scan_timeout_minutes stay live; phase24b drops
-- target_url after orphan sweep.
ALTER TABLE project_dast_config
  ADD COLUMN IF NOT EXISTS scope_config JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN project_dast_config.scope_config IS
  'Phase 24a: per-project DAST scope rules. Shape: { include_patterns:[regex], exclude_patterns:[regex], header_rules:[{name,value,scope}] }. Route layer rejects sensitive header names (Authorization/Cookie/etc.) and ReDoS-vulnerable patterns at PUT time.';

-- =============================================================================
-- 4. project_dast_findings: additive columns
-- =============================================================================
-- target_id NULLABLE in v2.1a; phase24b flips to NOT NULL after orphan sweep.
ALTER TABLE project_dast_findings
  ADD COLUMN IF NOT EXISTS target_id UUID
    REFERENCES project_dast_targets(id) ON DELETE CASCADE,
  ADD COLUMN IF NOT EXISTS auth_state TEXT NOT NULL DEFAULT 'anonymous'
    CHECK (auth_state IN ('anonymous', 'authenticated', 'authentication_lost')),
  ADD COLUMN IF NOT EXISTS engine TEXT NOT NULL DEFAULT 'zap'
    CHECK (engine IN ('zap', 'nuclei', 'merged'));

-- Forward-prep for v2.3 SAST cross-link (opportunity-scout-f1 P3).
ALTER TABLE project_dast_findings
  ADD COLUMN IF NOT EXISTS linked_sast_finding_id UUID
    REFERENCES project_semgrep_findings(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS cross_link_methods TEXT[] DEFAULT ARRAY[]::TEXT[];

COMMENT ON COLUMN project_dast_findings.target_id IS
  'Phase 24a: per-target finding scope. NULLABLE during the v2.1a shadow window (legacy v1 findings have no target). Phase 24b flips NOT NULL after backfill orphan sweep.';
COMMENT ON COLUMN project_dast_findings.auth_state IS
  'Phase 24a: anonymous (no cred), authenticated (cred + no logged_out hits), authentication_lost (cred + >=4 logged_out hits in 5min window). authentication_lost is a finding tag, not a synthetic finding row — the job-state lives on scan_jobs.error_category.';
COMMENT ON COLUMN project_dast_findings.engine IS
  'Phase 24a: zap (only value used in v2.1a). nuclei + merged reserved for v2.1c (template-based engine).';

-- New target-keyed partial unique indexes ALONGSIDE the existing project-keyed
-- ones. Per migration-safety-auditor cluster-1 patch: additive only in v2.1a;
-- phase24b drops the project-keyed indexes after the shadow window.
CREATE UNIQUE INDEX IF NOT EXISTS project_dast_findings_target_resolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    handler_file_path, handler_function_name, vulnerability_type
  )
  WHERE handler_file_path IS NOT NULL AND target_id IS NOT NULL;

CREATE UNIQUE INDEX IF NOT EXISTS project_dast_findings_target_unresolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    endpoint_url, http_method, vulnerability_type
  )
  WHERE handler_file_path IS NULL AND target_id IS NOT NULL;

-- =============================================================================
-- 5. scan_jobs: additive columns + widened trigger_source CHECK
-- =============================================================================
ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS target_id UUID
    REFERENCES project_dast_targets(id) ON DELETE SET NULL,
  -- Per cluster-2 patch: per-scan credential audit captures the credential
  -- snapshot at queue time (id + SHA-256 of encrypted_payload). Eliminates the
  -- TOCTOU race where a credential is replaced between queue and worker spawn.
  ADD COLUMN IF NOT EXISTS credential_id UUID
    REFERENCES project_dast_credentials(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS credential_payload_hash TEXT;

COMMENT ON COLUMN scan_jobs.credential_payload_hash IS
  'Phase 24a: SHA-256 hex of project_dast_credentials.encrypted_payload at queue-time snapshot. Worker compares this hash against current credential row at spawn time; mismatch implies credential was rotated mid-flight and the worker aborts with error_category=dast_credential_rotated.';

-- Widen trigger_source CHECK (opportunity-scout-f3 P3): reserve scheduled +
-- on_deploy + recovery for v2.2 to avoid CHECK shuffle later. Keep existing
-- 'aegis' value to avoid breaking any in-flight rows from the pre-v2.1a window.
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_trigger_source_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_trigger_source_check
  CHECK (
    trigger_source IS NULL OR trigger_source IN (
      'manual', 'webhook', 'recovery', 'scheduled', 'on_deploy', 'aegis'
    )
  );

-- Widen scan_jobs.type CHECK to forward-reserve 'dast_zap' + 'dast_nuclei' for
-- v2.1c. v2.1a continues inserting type='dast' (helper-script and AF YAML alike).
ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_type_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_type_check
  CHECK (
    type IN ('extraction', 'dast', 'dast_zap', 'dast_nuclei')
  );

-- =============================================================================
-- 6. commit_dast_target_run — canonical, target-scoped
-- =============================================================================
CREATE OR REPLACE FUNCTION commit_dast_target_run(
  p_target_id   UUID,
  p_dast_run_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
  v_prior_run_id TEXT;
  v_project_id UUID;
BEGIN
  SELECT active_dast_run_id, project_id INTO v_prior_run_id, v_project_id
  FROM project_dast_targets WHERE id = p_target_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_dast_target_run: target % not found', p_target_id;
  END IF;

  -- Suppression carry-forward, target-scoped. Mirrors v1 commit_dast_run logic
  -- but joins on target_id rather than project_id.
  IF v_prior_run_id IS NOT NULL THEN
    UPDATE project_dast_findings new_f
    SET status = old_f.status,
        risk_accepted_by = old_f.risk_accepted_by,
        risk_accepted_at = old_f.risk_accepted_at,
        risk_accepted_reason = old_f.risk_accepted_reason
    FROM project_dast_findings old_f
    WHERE new_f.target_id = p_target_id
      AND new_f.dast_run_id = p_dast_run_id
      AND old_f.target_id = p_target_id
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

  UPDATE project_dast_targets
  SET previous_dast_run_id = active_dast_run_id,
      active_dast_run_id   = p_dast_run_id,
      last_scanned_at      = NOW()
  WHERE id = p_target_id;

  -- Shadow-window double-write to legacy projects column for v1 readers.
  -- Phase 24b drops this UPDATE.
  UPDATE projects
  SET previous_dast_run_id = active_dast_run_id,
      active_dast_run_id   = p_dast_run_id
  WHERE id = v_project_id;
END;
$$;

COMMENT ON FUNCTION commit_dast_target_run IS
  'Phase 24a: canonical atomic-commit for a DAST run. Target-scoped (vs v1 project-scoped). Carries forward suppressed/risk_accepted state by stable identity, flips per-target active_dast_run_id, and double-writes legacy projects.active_dast_run_id during the v2.1a shadow window. Phase 24b drops the projects double-write.';

-- =============================================================================
-- 7. commit_dast_run — legacy wrapper delegating to canonical
-- =============================================================================
-- Existing callers (recovery cron, any deploy-time-baked workers) keep working.
-- Wrapper looks up "first target row for project" via created_at ORDER BY.
-- Phase 24b drops this wrapper after pg_stat_user_functions shows zero calls.
CREATE OR REPLACE FUNCTION commit_dast_run(
  p_project_id  UUID,
  p_dast_run_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql SECURITY DEFINER AS $$
DECLARE
  v_target_id UUID;
BEGIN
  SELECT id INTO v_target_id
  FROM project_dast_targets
  WHERE project_id = p_project_id
  ORDER BY created_at
  LIMIT 1;

  IF v_target_id IS NULL THEN
    -- Backfill should have created one synthetic-legacy target per project; if
    -- missing, something is wrong. RAISE so we don't silently corrupt state.
    RAISE EXCEPTION 'commit_dast_run wrapper: no target found for project %', p_project_id;
  END IF;

  PERFORM commit_dast_target_run(v_target_id, p_dast_run_id);
END;
$$;

COMMENT ON FUNCTION commit_dast_run IS
  'Phase 24a: legacy v1 signature delegating to commit_dast_target_run via "first target row for project." Dropped in phase24b after pg_stat_user_functions shows zero calls in last 24h.';

-- =============================================================================
-- 8. queue_scan_job — new optional p_target_id arg + tenant-drift assert
-- =============================================================================
-- Drop the v1 9-arg signature so we can re-create with the new 10-arg shape.
-- Legacy callers that don't yet pass target_id work unchanged because
-- p_target_id defaults NULL; body resolves NULL to "first target row for
-- project" via the same lookup as commit_dast_run wrapper.
DROP FUNCTION IF EXISTS queue_scan_job(UUID, UUID, TEXT, JSONB, TEXT, TEXT, INTEGER, TEXT, UUID);

CREATE OR REPLACE FUNCTION queue_scan_job(
  p_project_id      UUID,
  p_organization_id UUID,
  p_type            TEXT,
  p_payload         JSONB,
  p_target_id       UUID    DEFAULT NULL,
  p_target_url      TEXT    DEFAULT NULL,
  p_scan_profile    TEXT    DEFAULT NULL,
  p_timeout_minutes INTEGER DEFAULT NULL,
  p_trigger_source  TEXT    DEFAULT NULL,
  p_triggered_by    UUID    DEFAULT NULL
)
RETURNS scan_jobs
LANGUAGE plpgsql AS $$
DECLARE
  v_resolved_target_id UUID;
  v_target_org_id UUID;
  v_target_project_id UUID;
  v_org_concurrent INT;
  v_proj_concurrent INT;
  v_inserted scan_jobs%ROWTYPE;
  v_credential_id UUID;
  v_credential_hash TEXT;
  v_host TEXT;
BEGIN
  -- DAST-specific guards. Extraction path bypasses these.
  IF p_type IN ('dast', 'dast_zap', 'dast_nuclei') THEN
    -- Resolve target_id (NULL → first target row for project; back-compat
    -- pathway for legacy single-target callers during shadow window).
    IF p_target_id IS NULL THEN
      SELECT id INTO v_resolved_target_id
      FROM project_dast_targets
      WHERE project_id = p_project_id
      ORDER BY created_at
      LIMIT 1;
    ELSE
      v_resolved_target_id := p_target_id;
    END IF;

    IF v_resolved_target_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: no DAST target found for project %', p_project_id
        USING ERRCODE = 'P0001';
    END IF;

    -- Cluster-3 patch: RPC layer asserts (target.project_id, target.organization_id)
    -- match the caller's args. RAISE on mismatch — three-layer enforcement
    -- (route loadTargetOrDeny + this assert + worker tenant-drift check).
    SELECT project_id, organization_id INTO v_target_project_id, v_target_org_id
    FROM project_dast_targets
    WHERE id = v_resolved_target_id;

    IF v_target_project_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: target % vanished mid-call', v_resolved_target_id
        USING ERRCODE = 'P0001';
    END IF;

    IF v_target_project_id <> p_project_id OR v_target_org_id <> p_organization_id THEN
      RAISE EXCEPTION
        'queue_scan_job: tenant drift — target % belongs to (project=%, org=%); caller passed (project=%, org=%)',
        v_resolved_target_id, v_target_project_id, v_target_org_id, p_project_id, p_organization_id
        USING ERRCODE = 'P0001';
    END IF;

    -- SSRF defense-in-depth: literal-IP block at the DB layer (mirrors v1
    -- behavior; full DNS check stays in TS validateExternalUrl).
    IF p_target_url IS NULL THEN
      -- Fall back to target row's URL. Worker re-validates before scan start.
      SELECT target_url INTO p_target_url
      FROM project_dast_targets
      WHERE id = v_resolved_target_id;
    END IF;

    v_host := lower(substring(p_target_url FROM '^[a-z]+://([^:/?#]+)'));

    IF v_host IS NULL OR v_host = '' THEN
      RAISE EXCEPTION 'queue_scan_job: target_url must be http(s) URL with host'
        USING ERRCODE = 'P0001';
    END IF;

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

    -- Cluster-2 patch: capture credential snapshot at queue time. v_credential_id
    -- may be NULL (anonymous scan); that's expected.
    SELECT id, encode(digest(encrypted_payload, 'sha256'), 'hex')
    INTO v_credential_id, v_credential_hash
    FROM project_dast_credentials
    WHERE target_id = v_resolved_target_id;

    -- Per-project cap: 1 active DAST scan_job (any dast* type).
    SELECT COUNT(*) INTO v_proj_concurrent
    FROM scan_jobs
    WHERE project_id = p_project_id
      AND type IN ('dast', 'dast_zap', 'dast_nuclei')
      AND status IN ('queued', 'processing');

    IF v_proj_concurrent >= 1 THEN
      RAISE EXCEPTION 'queue_scan_job: project_concurrent_dast_blocked'
        USING ERRCODE = 'P0001',
              DETAIL = 'A DAST scan is already queued or running for this project.';
    END IF;

    -- Per-org cap: 5 (raised from v1's 3, per brief decision 10).
    SELECT COUNT(*) INTO v_org_concurrent
    FROM scan_jobs
    WHERE organization_id = p_organization_id
      AND type IN ('dast', 'dast_zap', 'dast_nuclei')
      AND status IN ('queued', 'processing');

    IF v_org_concurrent >= 5 THEN
      RAISE EXCEPTION 'queue_scan_job: org_concurrent_dast_cap'
        USING ERRCODE = 'P0001',
              DETAIL = 'Organization is at the 5-concurrent DAST scan cap.';
    END IF;
  END IF;

  INSERT INTO scan_jobs (
    project_id, organization_id, type, status, payload,
    target_id, target_url,
    scan_profile, timeout_minutes,
    trigger_source, triggered_by,
    credential_id, credential_payload_hash
  ) VALUES (
    p_project_id, p_organization_id, p_type, 'queued', COALESCE(p_payload, '{}'::jsonb),
    v_resolved_target_id, p_target_url,
    p_scan_profile, p_timeout_minutes,
    p_trigger_source, p_triggered_by,
    v_credential_id, v_credential_hash
  )
  RETURNING * INTO v_inserted;

  RETURN v_inserted;
END;
$$;

COMMENT ON FUNCTION queue_scan_job IS
  'Phase 24a: type-aware scan-job insert with new optional p_target_id arg. For dast* types: resolves target_id (NULL → first target), asserts tenant alignment (project_id + organization_id), captures credential snapshot (id + SHA-256 hash), and enforces 1/project + 5/org concurrency caps. SSRF literal-IP defense in DB layer (DNS check stays in TS validateExternalUrl). Phase 24b drops the NULL→first-target fallback once all callers pass p_target_id explicitly.';

-- =============================================================================
-- 9. Realtime publication for new tables
-- =============================================================================
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND schemaname = 'public'
      AND tablename = 'project_dast_targets'
  ) THEN
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE project_dast_targets';
  END IF;

  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime'
      AND schemaname = 'public'
      AND tablename = 'project_dast_credentials'
  ) THEN
    EXECUTE 'ALTER PUBLICATION supabase_realtime ADD TABLE project_dast_credentials';
  END IF;
END $$;

-- =============================================================================
-- 10. Two-pass backfill (cluster-1 patch)
-- =============================================================================
-- Pass 1 — synthetic-legacy targets: every project that has any
-- project_dast_config row gets at least one project_dast_targets row, seeded
-- from the legacy single-target column (or 'https://unknown.local' fallback for
-- empty configs).
INSERT INTO project_dast_targets (
  project_id, organization_id, target_url, label,
  active_dast_run_id, previous_dast_run_id
)
SELECT
  pdc.project_id,
  pdc.organization_id,
  COALESCE(NULLIF(pdc.target_url, ''), 'https://unknown.local'),
  'legacy',
  p.active_dast_run_id,
  p.previous_dast_run_id
FROM project_dast_config pdc
JOIN projects p ON p.id = pdc.project_id
WHERE NOT EXISTS (
  SELECT 1 FROM project_dast_targets t
  WHERE t.project_id = pdc.project_id
);

-- Pass 2 — backfill findings.target_id by joining on project_id.
-- Per cluster-1 patch: log orphan count via RAISE NOTICE rather than ABORT.
-- Phase 24b's NOT NULL flip handles cleanup later.
UPDATE project_dast_findings f
SET target_id = (
  SELECT t.id FROM project_dast_targets t
  WHERE t.project_id = f.project_id
  ORDER BY t.created_at
  LIMIT 1
)
WHERE f.target_id IS NULL;

-- =============================================================================
-- 11. Verification SELECTs (logged via RAISE NOTICE — non-blocking)
-- =============================================================================
DO $$
DECLARE
  v_target_count INT;
  v_distinct_projects INT;
  v_orphan_findings INT;
  v_in_flight_jobs INT;
BEGIN
  SELECT COUNT(*) INTO v_target_count FROM project_dast_targets;
  SELECT COUNT(DISTINCT project_id) INTO v_distinct_projects FROM project_dast_config;
  SELECT COUNT(*) INTO v_orphan_findings
    FROM project_dast_findings WHERE target_id IS NULL;
  SELECT COUNT(*) INTO v_in_flight_jobs
    FROM scan_jobs
    WHERE type IN ('dast', 'dast_zap', 'dast_nuclei')
      AND status IN ('queued', 'processing');

  RAISE NOTICE 'phase24a backfill: % project_dast_targets rows (>=% expected from project_dast_config distinct project_ids)',
    v_target_count, v_distinct_projects;
  RAISE NOTICE 'phase24a backfill: % project_dast_findings rows remain target_id=NULL (orphans — phase24b NOT NULL flip handles cleanup)',
    v_orphan_findings;
  RAISE NOTICE 'phase24a precondition: % in-flight DAST scan_jobs (drain runbook precondition expects 0)',
    v_in_flight_jobs;

  IF v_target_count < v_distinct_projects THEN
    RAISE WARNING 'phase24a backfill anomaly: target count (%) < distinct project count from project_dast_config (%) — investigate before phase24b', v_target_count, v_distinct_projects;
  END IF;
END $$;
