-- Aegis Fix Agent recovery lifecycle fix.
--
-- aegis_fix_agent_v1.sql redefined the lifecycle to use 'approved' / 'executing'
-- instead of the legacy 'queued' / 'running', and rewrote claim_fix_job and
-- recover_stuck_fix_jobs to match. fail_exhausted_fix_jobs was missed: it still
-- filters status = 'running', which never matches a real fix row, so exhausted
-- 'executing' jobs accumulate forever. Cron sees them, fail-RPC silently returns
-- zero rows, dashboard shows them stuck.
--
-- recover_stuck_fix_jobs was changed to RETURNS integer (a row count), but the
-- recovery cron handler in backend/src/routes/fix-recovery.ts treats the result
-- as an array of rows and tries to per-row insert extraction_logs entries. With
-- an integer return, Array.isArray() is false, so the requeue notification log
-- never fires AND the count reported in the cron response is always 0 even when
-- real recovery happened.
--
-- This migration:
--  1. Repoints fail_exhausted_fix_jobs at status='executing' (the real terminal
--     pre-completion state).
--  2. Restores recover_stuck_fix_jobs to RETURNS SETOF project_security_fixes so
--     the cron handler can iterate per-job and emit correct user-facing logs.
--     The DROP-then-CREATE dance is required because the return type is changing.

-- Recover stuck fix jobs: return the affected rows so the cron can log per-job.
DROP FUNCTION IF EXISTS public.recover_stuck_fix_jobs();

CREATE OR REPLACE FUNCTION public.recover_stuck_fix_jobs()
RETURNS SETOF project_security_fixes
LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY
  UPDATE project_security_fixes
  SET status = 'approved',
      machine_id = NULL,
      heartbeat_at = NULL,
      error_message = COALESCE(error_message, '') ||
        E'\n[recovered from stuck state at ' || NOW()::text || ']'
  WHERE status = 'executing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts < max_attempts
  RETURNING *;
END;
$$;

-- Fail exhausted fix jobs: filter on the real lifecycle state.
DROP FUNCTION IF EXISTS public.fail_exhausted_fix_jobs();

CREATE OR REPLACE FUNCTION public.fail_exhausted_fix_jobs()
RETURNS SETOF project_security_fixes
LANGUAGE plpgsql AS $$
BEGIN
  RETURN QUERY
  UPDATE project_security_fixes
  SET status = 'failed',
      error_message = 'Fix machine terminated unexpectedly after ' || attempts || ' attempt(s).',
      error_category = 'machine_crash',
      completed_at = NOW()
  WHERE status = 'executing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts >= max_attempts
  RETURNING *;
END;
$$;
