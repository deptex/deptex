-- Aegis Fix Agent v1: extend project_security_fixes for plan-then-approve-then-execute flow.
-- Replaces the legacy aider-worker direct-execute model.
--
-- Lifecycle: planning -> awaiting_approval -> approved -> executing -> completed
--                                                              \-> failed
--                       \-> rejected
--                       \-> failed (planner refusal)
--
-- The aider-worker is retired in a later milestone. Until then it polls claim_fix_job(),
-- which now claims only 'approved' rows -- so the legacy worker harmlessly finds nothing.

-- Wipe legacy aider-worker rows (clean slate, no backfill).
TRUNCATE TABLE project_security_fixes;

-- Schema additions for plan-based flow.
ALTER TABLE project_security_fixes
  ADD COLUMN plan jsonb,
  ADD COLUMN plan_generated_at timestamptz,
  ADD COLUMN plan_base_sha text,
  ADD COLUMN plan_base_branch text,
  ADD COLUMN approved_at timestamptz,
  ADD COLUMN approved_by_user_id uuid REFERENCES auth.users(id),
  ADD COLUMN approval_token text,
  ADD COLUMN rejected_at timestamptz,
  ADD COLUMN rejected_by_user_id uuid REFERENCES auth.users(id),
  ADD COLUMN rejection_reason text;

-- Replace status CHECK with new enum values.
ALTER TABLE project_security_fixes
  DROP CONSTRAINT IF EXISTS project_security_fixes_status_check;

ALTER TABLE project_security_fixes
  ADD CONSTRAINT project_security_fixes_status_check
    CHECK (status IN (
      'planning',
      'awaiting_approval',
      'approved',
      'executing',
      'completed',
      'failed',
      'rejected'
    ));

ALTER TABLE project_security_fixes ALTER COLUMN status SET DEFAULT 'planning';

-- Drop legacy partial indexes -- their predicates ('queued', 'running') are no longer
-- valid status values, so the indexes can never match a row.
DROP INDEX IF EXISTS idx_psf_queued;
DROP INDEX IF EXISTS idx_psf_running;

-- Pending-approval lookups (Aegis inbox, plan-card refreshes).
CREATE INDEX IF NOT EXISTS idx_psf_org_status_pending
  ON project_security_fixes (organization_id, status)
  WHERE status IN ('planning', 'awaiting_approval');

-- Worker job claim.
CREATE INDEX IF NOT EXISTS idx_psf_status_approved
  ON project_security_fixes (status, approved_at)
  WHERE status = 'approved';

-- Heartbeat scan for the new recover_stuck_fix_jobs.
CREATE INDEX IF NOT EXISTS idx_psf_status_executing
  ON project_security_fixes (status, heartbeat_at)
  WHERE status = 'executing';

-- Redefine claim_fix_job: claim oldest 'approved' row, transition to 'executing'.
-- Returns a slim row shape (no SELECT *) so the new fix-worker only depends on the
-- columns it actually reads. Drop required because the return type changes.
DROP FUNCTION IF EXISTS public.claim_fix_job(text);

CREATE OR REPLACE FUNCTION public.claim_fix_job(p_machine_id text)
RETURNS TABLE(
  id uuid,
  project_id uuid,
  organization_id uuid,
  payload jsonb,
  plan jsonb,
  attempts integer
)
LANGUAGE plpgsql AS $$
DECLARE
  v_job_id uuid;
BEGIN
  SELECT psf.id INTO v_job_id
    FROM project_security_fixes psf
    WHERE psf.status = 'approved'
      AND psf.attempts < psf.max_attempts
    ORDER BY psf.approved_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED;

  IF v_job_id IS NULL THEN
    RETURN;
  END IF;

  RETURN QUERY
  UPDATE project_security_fixes
    SET status = 'executing',
        machine_id = p_machine_id,
        heartbeat_at = NOW(),
        started_at = NOW(),
        attempts = attempts + 1
    WHERE project_security_fixes.id = v_job_id
    RETURNING
      project_security_fixes.id,
      project_security_fixes.project_id,
      project_security_fixes.organization_id,
      project_security_fixes.payload,
      project_security_fixes.plan,
      project_security_fixes.attempts;
END;
$$;

-- Redefine recover_stuck_fix_jobs: revert 'executing' rows with stale heartbeat back
-- to 'approved' for re-claim. Mirrors recover_stuck_extraction_jobs pattern.
-- Drop required because return type changes from SETOF to integer.
DROP FUNCTION IF EXISTS public.recover_stuck_fix_jobs();

CREATE OR REPLACE FUNCTION public.recover_stuck_fix_jobs()
RETURNS integer
LANGUAGE plpgsql AS $$
DECLARE
  v_count integer;
BEGIN
  UPDATE project_security_fixes
    SET status = 'approved',
        machine_id = NULL,
        heartbeat_at = NULL,
        error_message = COALESCE(error_message, '') ||
          E'\n[recovered from stuck state at ' || NOW()::text || ']'
    WHERE status = 'executing'
      AND heartbeat_at < NOW() - INTERVAL '5 minutes'
      AND attempts < max_attempts;
  GET DIAGNOSTICS v_count = ROW_COUNT;
  RETURN v_count;
END;
$$;
