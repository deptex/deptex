-- =============================================================================
-- Phase 24b — DAST v2 destructive cleanup
--
-- Pairs with phase24a (additive landing). Drops every legacy v1 surface that
-- phase24a left in place behind wrapper RPCs and shadow-window double-writes.
--
-- Apply order: backend code drop (route fallback + DTO field) deploys via
-- Vercel FIRST → this migration applies via Supabase MCP SECOND. Eliminates
-- the apply→deploy gap where the live backend would 500 on dropped columns.
--
-- Per feedback_solo_user_prelaunch, we DELETE the DAST tables rather than
-- backfilling orphan rows; re-extraction repopulates.
--
-- Single-transaction migration. Any failure between BEGIN and COMMIT aborts
-- atomically; the database is unchanged. Safe to rerun after diagnosing.
-- =============================================================================

BEGIN;

-- -----------------------------------------------------------------------------
-- 1. Delete DAST data (explicit ordered DELETEs, NOT TRUNCATE CASCADE)
-- -----------------------------------------------------------------------------
-- TRUNCATE … CASCADE ignores ON DELETE SET NULL and would unconditionally wipe
-- scan_jobs (which holds extraction/IaC/container/malicious/secrets/SAST/DAST
-- history) via scan_jobs.target_id_fkey and scan_jobs.credential_id_fkey.
-- Use ordered DELETEs that respect those FKs: clear children first.

DO $$
DECLARE
  v_findings INT; v_creds INT; v_targets INT; v_dast_jobs INT;
BEGIN
  SELECT count(*) INTO v_findings  FROM project_dast_findings;
  SELECT count(*) INTO v_creds     FROM project_dast_credentials;
  SELECT count(*) INTO v_targets   FROM project_dast_targets;
  SELECT count(*) INTO v_dast_jobs FROM scan_jobs WHERE type IN ('dast','dast_zap','dast_nuclei');
  RAISE NOTICE 'Phase 24b pre-delete counts: findings=%, credentials=%, targets=%, dast_jobs=%',
    v_findings, v_creds, v_targets, v_dast_jobs;
END $$;

-- Delete DAST-typed scan_jobs rows first (their FKs into DAST tables go away).
DELETE FROM scan_jobs WHERE type IN ('dast', 'dast_zap', 'dast_nuclei');

-- NULL any non-DAST scan_jobs.target_id / credential_id pointers (defensive —
-- v2.1a never populates these on extraction-typed rows, but be explicit).
UPDATE scan_jobs SET target_id     = NULL WHERE target_id     IS NOT NULL;
UPDATE scan_jobs SET credential_id = NULL WHERE credential_id IS NOT NULL;

-- Now nothing references DAST tables. Order mirrors logical dependency for
-- clarity (children of project_dast_targets first).
DELETE FROM project_dast_findings;
DELETE FROM project_dast_credentials;
DELETE FROM project_dast_targets;

-- (project_dast_runs does not exist — DAST run identity lives as TEXT columns
--  on project_dast_findings.dast_run_id and project_dast_targets.active_dast_run_id,
--  both already cleared by the deletes above.)

-- The legacy projects.* DAST pointers are about to be dropped (Step 3); no
-- explicit NULLing needed — DROP COLUMN drops the data regardless.
-- Same for project_dast_config.target_url (Step 4).

-- -----------------------------------------------------------------------------
-- 2. Flip project_dast_findings.target_id → NOT NULL
-- -----------------------------------------------------------------------------
-- Safe post-delete (zero rows). Existing FK + ON DELETE CASCADE preserved.
ALTER TABLE project_dast_findings
  ALTER COLUMN target_id SET NOT NULL;

COMMENT ON COLUMN project_dast_findings.target_id IS
  'Phase 24b: NOT NULL — every finding must belong to a project_dast_targets row. v2.1a allowed NULL during the shadow window.';

-- -----------------------------------------------------------------------------
-- 3. Drop legacy projects.* DAST pointer columns
-- -----------------------------------------------------------------------------
-- Note: idx_projects_active_dast_run partial index (phase23b:169-171) cascades
-- automatically with the column drop. No explicit DROP INDEX needed.
ALTER TABLE projects DROP COLUMN IF EXISTS active_dast_run_id;
ALTER TABLE projects DROP COLUMN IF EXISTS previous_dast_run_id;

-- -----------------------------------------------------------------------------
-- 4. Drop legacy project_dast_config.target_url column
-- -----------------------------------------------------------------------------
ALTER TABLE project_dast_config DROP COLUMN IF EXISTS target_url;

-- -----------------------------------------------------------------------------
-- 5. Drop legacy project-keyed partial unique indexes
-- -----------------------------------------------------------------------------
-- Correct names per phase23b:106,114 — NO `_unique` suffix.
DROP INDEX IF EXISTS project_dast_findings_resolved;
DROP INDEX IF EXISTS project_dast_findings_unresolved;

-- Sanity: fail loud if names drifted and DROP became a silent no-op.
DO $$ BEGIN
  IF EXISTS (
    SELECT 1 FROM pg_indexes
    WHERE schemaname = 'public'
      AND indexname IN ('project_dast_findings_resolved', 'project_dast_findings_unresolved')
  ) THEN
    RAISE EXCEPTION 'phase24b: legacy project-keyed indexes still present — DROP INDEX names mismatch';
  END IF;
END $$;

-- -----------------------------------------------------------------------------
-- 6. Rebuild target-keyed partial unique indexes without redundant predicate
-- -----------------------------------------------------------------------------
-- After Step 2, target_id is NOT NULL — `AND target_id IS NOT NULL` in the
-- phase24a indexes is dead weight and misleading. Rebuild without it (cheap on
-- the post-delete table — zero rows).
DROP INDEX IF EXISTS project_dast_findings_target_resolved;
DROP INDEX IF EXISTS project_dast_findings_target_unresolved;

CREATE UNIQUE INDEX project_dast_findings_target_resolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    handler_file_path, handler_function_name, vulnerability_type
  )
  WHERE handler_file_path IS NOT NULL;

CREATE UNIQUE INDEX project_dast_findings_target_unresolved
  ON project_dast_findings(
    target_id, dast_run_id, rule_id,
    endpoint_url, http_method, vulnerability_type
  )
  WHERE handler_file_path IS NULL;

-- -----------------------------------------------------------------------------
-- 7. Replace commit_dast_target_run — drop shadow-window double-write + dead var
-- -----------------------------------------------------------------------------
-- Same body as phase24a:299-359 MINUS:
--   • the v_project_id DECLARE + the project_id slot in the SELECT INTO
--   • the trailing UPDATE projects block (phase24a:352-357)
CREATE OR REPLACE FUNCTION commit_dast_target_run(
  p_target_id   UUID,
  p_dast_run_id TEXT
)
RETURNS VOID
LANGUAGE plpgsql AS $$
DECLARE
  v_prior_run_id TEXT;
BEGIN
  SELECT active_dast_run_id INTO v_prior_run_id
  FROM project_dast_targets WHERE id = p_target_id
  FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'commit_dast_target_run: target % not found', p_target_id;
  END IF;

  -- Suppression carry-forward, target-scoped. Mirrors v1 logic but joins on target_id.
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

  -- (Phase 24b: removed shadow-window double-write to projects.active_dast_run_id
  --  AND removed dead v_project_id variable.)
END;
$$;

COMMENT ON FUNCTION commit_dast_target_run IS
  'Phase 24b: canonical atomic-commit for a DAST run. Target-scoped. Carries forward suppressed/risk_accepted state by stable identity, flips per-target active_dast_run_id, and updates last_scanned_at.';

-- -----------------------------------------------------------------------------
-- 8. Drop legacy commit_dast_run wrapper (2-arg)
-- -----------------------------------------------------------------------------
DROP FUNCTION IF EXISTS commit_dast_run(UUID, TEXT);

-- -----------------------------------------------------------------------------
-- 9. queue_scan_job — drop the p_target_id IS NULL fallback path
-- -----------------------------------------------------------------------------
-- Same body as phase24a:407-553 MINUS the lines 436-444 NULL→first-target
-- fallback. Callers must now pass p_target_id explicitly.
DROP FUNCTION IF EXISTS queue_scan_job(UUID, UUID, TEXT, JSONB, UUID, TEXT, TEXT, INTEGER, TEXT, UUID);

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
  v_target_org_id UUID;
  v_target_project_id UUID;
  v_org_concurrent INT;
  v_proj_concurrent INT;
  v_inserted scan_jobs%ROWTYPE;
  v_credential_id UUID;
  v_credential_hash TEXT;
  v_host TEXT;
BEGIN
  IF p_type IN ('dast', 'dast_zap', 'dast_nuclei') THEN
    -- Phase 24b: p_target_id MUST be provided. v2.1a's NULL→first-target
    -- fallback is removed; callers without a target_id are a bug.
    IF p_target_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: p_target_id is required for dast* types'
        USING ERRCODE = 'P0001';
    END IF;

    -- Tenant-alignment assertion (unchanged from phase24a).
    SELECT project_id, organization_id INTO v_target_project_id, v_target_org_id
    FROM project_dast_targets
    WHERE id = p_target_id;

    IF v_target_project_id IS NULL THEN
      RAISE EXCEPTION 'queue_scan_job: target % not found', p_target_id
        USING ERRCODE = 'P0001';
    END IF;

    IF v_target_project_id <> p_project_id OR v_target_org_id <> p_organization_id THEN
      RAISE EXCEPTION
        'queue_scan_job: tenant drift — target % belongs to (project=%, org=%); caller passed (project=%, org=%)',
        p_target_id, v_target_project_id, v_target_org_id, p_project_id, p_organization_id
        USING ERRCODE = 'P0001';
    END IF;

    -- SSRF defense-in-depth: literal-IP block at the DB layer (mirrors v1
    -- behavior; full DNS check stays in TS validateExternalUrl).
    IF p_target_url IS NULL THEN
      SELECT target_url INTO p_target_url
      FROM project_dast_targets
      WHERE id = p_target_id;
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

    -- Per-scan credential audit (unchanged from phase24a).
    SELECT id, encode(digest(encrypted_payload, 'sha256'), 'hex')
    INTO v_credential_id, v_credential_hash
    FROM project_dast_credentials
    WHERE target_id = p_target_id;

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

    -- Per-org cap: 5 (raised from v1's 3).
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
    p_target_id, p_target_url,
    p_scan_profile, p_timeout_minutes,
    p_trigger_source, p_triggered_by,
    v_credential_id, v_credential_hash
  )
  RETURNING * INTO v_inserted;

  RETURN v_inserted;
END;
$$;

COMMENT ON FUNCTION queue_scan_job IS
  'Phase 24b: type-aware scan-job insert. For dast* types: requires p_target_id (NO NULL fallback), asserts tenant alignment, captures credential snapshot, enforces 1/project + 5/org concurrency caps, blocks SSRF literal IPs at the DB layer.';

-- Sanity: exactly one queue_scan_job overload exists post-recreation.
DO $$ BEGIN
  IF (SELECT count(*) FROM pg_proc WHERE proname = 'queue_scan_job') <> 1 THEN
    RAISE EXCEPTION 'phase24b: unexpected queue_scan_job overload count';
  END IF;
END $$;

COMMIT;

-- =============================================================================
-- After applying: regenerate schema.sql via `cd depscanner && npm run schema:dump`
-- =============================================================================
