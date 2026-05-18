-- Phase 29: scan_jobs lifecycle hardening — recover_stuck_scan_jobs across types.
--
-- recover_stuck_scan_jobs filtered `type = 'extraction'` only (carried over
-- from phase23_dast_consolidation.sql with a "PR 2 will extend to DAST"
-- comment that never landed). DAST jobs (and any future scan type added to
-- the queue — malicious_pkg, iac, container) that lost their machine never
-- came back to the queue: they sat in `status='processing'` with stale
-- heartbeats forever, eventually getting fail_exhausted_scan_jobs'd once
-- attempts >= max_attempts but never retried in between.
--
-- The 5min stuck threshold matches the heartbeat cadence (60s); per-type
-- thresholds are an explicit non-goal here — if a type needs a different
-- SLA, add a CASE arm. The recovery cron also already filters
-- type='extraction' for the extraction_logs writeback (recovery.ts), so
-- DAST recovery is silent in the user-facing log stream by design until
-- DAST gets its own log surface.
--
-- See depscanner-hardening-report.md (P0 — recovery cron).

CREATE OR REPLACE FUNCTION public.recover_stuck_scan_jobs()
RETURNS SETOF scan_jobs
LANGUAGE sql AS $$
  UPDATE scan_jobs
  SET status      = 'queued',
      machine_id  = NULL,
      started_at  = NULL,
      heartbeat_at = NULL,
      run_id      = gen_random_uuid()
  WHERE status = 'processing'
    AND heartbeat_at < NOW() - INTERVAL '5 minutes'
    AND attempts < max_attempts
  RETURNING *;
$$;

COMMENT ON FUNCTION public.recover_stuck_scan_jobs IS
  'Phase 29: requeue scan jobs of ANY type whose worker stopped sending heartbeats. Was extraction-only at phase 23 ship; DAST/IaC/container/malicious-pkg scan types were leaking stuck jobs that never recovered. Threshold remains 5min — if a type needs a longer SLA, add a CASE arm.';
