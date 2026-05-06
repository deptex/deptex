-- Phase 24a (worker pipeline): widen scan_jobs.error_category to cover the
-- new abort categories produced by the v2.1a depscanner DAST pipeline, and
-- add a structured error_payload column for the auth-failed job-state.
--
-- Categories added:
--   * tenant_drift_detected         — worker SELECT(target+project+scan_jobs)
--                                     finds organization_id mismatch; abort
--                                     before any decrypt.
--   * dast_credential_key_missing   — target.has_credentials=true but
--                                     DAST_CREDENTIAL_KEY not configured on
--                                     the worker. Pipeline NEVER falls back
--                                     to anonymous (non-negotiable invariant).
--   * dast_credential_key_stale     — decryptCredential threw after current+
--                                     previous-key fallback. Same hard-fail
--                                     rule as missing.
--   * dast_credential_rotated       — credential_payload_hash captured at
--                                     queue time no longer matches the row's
--                                     SHA-256 at spawn time.
--
-- error_payload (JSONB) carries structured state for the auth_failed case:
--   {consecutive_lost_count, last_logged_out_url, last_logged_out_at}.
-- Authentication_lost is a JOB STATE, not a synthetic finding row — see plan
-- §"Auth-failure UI (P1 patch)".

ALTER TABLE scan_jobs DROP CONSTRAINT IF EXISTS scan_jobs_error_category_check;
ALTER TABLE scan_jobs ADD CONSTRAINT scan_jobs_error_category_check
  CHECK (
    error_category IS NULL
    OR error_category IN (
      'timeout',
      'unreachable_target',
      'ssrf_blocked',
      'auth_failed',
      'engine_crash',
      'unknown',
      'tenant_drift_detected',
      'dast_credential_key_missing',
      'dast_credential_key_stale',
      'dast_credential_rotated'
    )
  );

ALTER TABLE scan_jobs
  ADD COLUMN IF NOT EXISTS error_payload JSONB;

COMMENT ON COLUMN scan_jobs.error_payload IS
  'Phase 24a: structured error metadata. For error_category=auth_failed: {consecutive_lost_count, last_logged_out_url, last_logged_out_at}. For dast_credential_key_*: {key_version_attempted}. For tenant_drift_detected: {expected_org_id, expected_project_id} (no actual values to avoid leaking foreign-tenant ids).';
