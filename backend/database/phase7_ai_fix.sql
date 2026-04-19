-- Phase 7: AI-Powered Security Fixing
-- Creates the project_security_fixes table for tracking AI fix jobs,
-- and RPCs for atomic job claiming, queuing, and recovery.

CREATE TABLE IF NOT EXISTS project_security_fixes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  run_id UUID NOT NULL DEFAULT gen_random_uuid(),

  fix_type TEXT NOT NULL CHECK (fix_type IN ('vulnerability', 'semgrep', 'secret')),
  strategy TEXT NOT NULL CHECK (strategy IN (
    'bump_version', 'code_patch', 'add_wrapper', 'pin_transitive',
    'remove_unused', 'fix_semgrep', 'remediate_secret'
  )),
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN (
    'queued', 'running', 'completed', 'failed', 'cancelled',
    'pr_closed', 'merged', 'superseded'
  )),
  triggered_by UUID NOT NULL REFERENCES auth.users(id),

  osv_id TEXT,
  dependency_id UUID REFERENCES dependencies(id),
  project_dependency_id UUID,
  semgrep_finding_id UUID,
  secret_finding_id UUID,
  target_version TEXT,

  payload JSONB NOT NULL DEFAULT '{}',

  machine_id TEXT,
  heartbeat_at TIMESTAMPTZ,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,

  pr_url TEXT,
  pr_number INTEGER,
  pr_branch TEXT,
  pr_provider TEXT,
  pr_repo_full_name TEXT,
  diff_summary TEXT,
  tokens_used INTEGER,
  estimated_cost NUMERIC(10, 4),
  error_message TEXT,
  error_category TEXT,
  introduced_vulns TEXT[],
  validation_result JSONB,

  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_psf_project_status ON project_security_fixes(project_id, status);
CREATE INDEX IF NOT EXISTS idx_psf_org_status ON project_security_fixes(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_psf_queued ON project_security_fixes(status, created_at) WHERE status = 'queued';
CREATE INDEX IF NOT EXISTS idx_psf_running ON project_security_fixes(status, heartbeat_at) WHERE status = 'running';
CREATE INDEX IF NOT EXISTS idx_psf_osv ON project_security_fixes(project_id, osv_id) WHERE osv_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_psf_run ON project_security_fixes(run_id);

-- Atomic job claiming with same-project serialization
CREATE OR REPLACE FUNCTION claim_fix_job(p_machine_id TEXT)
RETURNS SETOF project_security_fixes AS $$
BEGIN
  RETURN QUERY
  WITH candidate AS (
    SELECT psf.*
    FROM project_security_fixes psf
    WHERE psf.status = 'queued'
      AND NOT EXISTS (
        SELECT 1 FROM project_security_fixes running
        WHERE running.project_id = psf.project_id
          AND running.status = 'running'
      )
    ORDER BY psf.created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  )
  UPDATE project_security_fixes
  SET status = 'running',
      machine_id = p_machine_id,
      started_at = NOW(),
      heartbeat_at = NOW(),
      attempts = attempts + 1
  FROM candidate
  WHERE project_security_fixes.id = candidate.id
  RETURNING project_security_fixes.*;
END;
$$ LANGUAGE plpgsql;

-- Atomic concurrent cap + insert
CREATE OR REPLACE FUNCTION queue_fix_job(
  p_project_id UUID,
  p_organization_id UUID,
  p_fix_type TEXT,
  p_strategy TEXT,
  p_triggered_by UUID,
  p_osv_id TEXT DEFAULT NULL,
  p_dependency_id UUID DEFAULT NULL,
  p_project_dependency_id UUID DEFAULT NULL,
  p_semgrep_finding_id UUID DEFAULT NULL,
  p_secret_finding_id UUID DEFAULT NULL,
  p_target_version TEXT DEFAULT NULL,
  p_payload JSONB DEFAULT '{}'
) RETURNS UUID AS $$
DECLARE
  v_org_count INTEGER;
  v_job_id UUID;
BEGIN
  PERFORM 1 FROM organizations WHERE id = p_organization_id FOR UPDATE;

  SELECT COUNT(*) INTO v_org_count
  FROM project_security_fixes
  WHERE organization_id = p_organization_id
    AND status IN ('queued', 'running');

  IF v_org_count >= 5 THEN
    RAISE EXCEPTION 'MAX_CONCURRENT_FIXES: Organization has reached the maximum of 5 concurrent fix jobs';
  END IF;

  INSERT INTO project_security_fixes (
    project_id, organization_id, fix_type, strategy, triggered_by,
    osv_id, dependency_id, project_dependency_id,
    semgrep_finding_id, secret_finding_id, target_version, payload
  ) VALUES (
    p_project_id, p_organization_id, p_fix_type, p_strategy, p_triggered_by,
    p_osv_id, p_dependency_id, p_project_dependency_id,
    p_semgrep_finding_id, p_secret_finding_id, p_target_version, p_payload
  ) RETURNING id INTO v_job_id;

  RETURN v_job_id;
END;
$$ LANGUAGE plpgsql;

-- Recovery: requeue stuck jobs (heartbeat stale >5 min, under max attempts)
CREATE OR REPLACE FUNCTION recover_stuck_fix_jobs()
RETURNS SETOF project_security_fixes AS $$
BEGIN
  RETURN QUERY
  UPDATE project_security_fixes
  SET status = 'queued',
      machine_id = NULL,
      heartbeat_at = NULL,
      run_id = gen_random_uuid()
  WHERE status = 'running'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts < max_attempts
  RETURNING *;
END;
$$ LANGUAGE plpgsql;

-- Recovery: fail jobs that exceeded max attempts
CREATE OR REPLACE FUNCTION fail_exhausted_fix_jobs()
RETURNS SETOF project_security_fixes AS $$
BEGIN
  RETURN QUERY
  UPDATE project_security_fixes
  SET status = 'failed',
      error_message = 'Fix machine terminated unexpectedly after ' || attempts || ' attempt(s).',
      error_category = 'machine_crash',
      completed_at = NOW()
  WHERE status = 'running'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts >= max_attempts
  RETURNING *;
END;
$$ LANGUAGE plpgsql;

-- Enable Realtime for live fix status updates
ALTER PUBLICATION supabase_realtime ADD TABLE project_security_fixes;
