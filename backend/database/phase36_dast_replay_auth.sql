-- Phase 36 (v1.1) — DAST replay-based authentication strategy.
--
-- Widens project_dast_credentials.auth_strategy_check to admit 'replay'
-- alongside the existing form / jwt / cookie / recorded values.
--
-- Why single-cutover-safe (no two-phase needed):
--   The only producer of `auth_strategy = 'replay'` rows is the backend
--   route `PUT /credentials` with `payload.kind === 'replay'` accepted by
--   `validateAndPrepareCredential`. Until the backend code that issues
--   that branch ships, the validator path rejects the request regardless
--   of whether this migration has been applied. depscanner is scale-to-
--   zero on Fly — the image current at machine cold-start is what runs,
--   no rolling-worker hazard.
--
--   Deploy order: depscanner image FIRST -> merge backend code (and this
--   migration) -> frontend auto-deploys. Migration may apply at any
--   point in that sequence without producing rows that fail the
--   constraint or scan_jobs that fail at worker claim.
--
-- Idempotent: DROP IF EXISTS + ADD wrapped in BEGIN/COMMIT. No data
-- backfill. Safe to re-apply.

BEGIN;

ALTER TABLE public.project_dast_credentials
  DROP CONSTRAINT IF EXISTS project_dast_credentials_auth_strategy_check;

ALTER TABLE public.project_dast_credentials
  ADD CONSTRAINT project_dast_credentials_auth_strategy_check
  CHECK ((auth_strategy = ANY (ARRAY[
    'form'::text,
    'jwt'::text,
    'cookie'::text,
    'recorded'::text,
    'replay'::text
  ])));

COMMIT;

-- Sanity: assert 'replay' is now admitted.
DO $$
DECLARE v_ok BOOLEAN;
BEGIN
  SELECT pg_get_constraintdef(oid) LIKE '%''replay''%'
  INTO v_ok
  FROM pg_constraint
  WHERE conname = 'project_dast_credentials_auth_strategy_check';

  IF NOT COALESCE(v_ok, FALSE) THEN
    RAISE EXCEPTION 'phase36: project_dast_credentials_auth_strategy_check is missing replay after migration';
  END IF;
END $$;
