-- phase34b — cancel_scan_job extended with p_project_id + type filter.
--
-- /criticalreview HEH-1 (P1): the phase34 cancel_scan_job RPC matched by
-- (id, organization_id, status) only — no project_id binding. A user with
-- org-level manage_integrations on project P1 (org X) could POST
-- /api/projects/P1/dast/jobs/J2/cancel where J2 belonged to project P2
-- (same org X, different team), and the RPC would happily UPDATE J2 to
-- 'cancelled'. Also, the cancel route had no type filter — a DAST-shaped
-- URL could cancel an extraction job.
--
-- This migration:
--   1. Drops the old cancel_scan_job(UUID, UUID) signature.
--   2. Recreates with cancel_scan_job(p_job_id, p_organization_id, p_project_id)
--      — UPDATE WHERE clause now AND-binds project_id AND filters type to
--      the DAST family (cancellation is a DAST-only feature today).
--   3. Pins SET search_path = pg_catalog, public on the SECURITY DEFINER
--      function (closes /criticalreview MIG-1 — search-path hijack vector).
--
-- Route changes (separate commit, same PR):
--   - backend/src/routes/dast.ts cancel handler now passes projectId.
--   - Probe fallback (404/409 disambiguation) also binds project_id.
--
-- Migration shape: signature change. DROP+CREATE on the function. The route
-- handler ships in the same release; no skew window because the old shape
-- is removed atomically and the new shape is installed in the same TX.

BEGIN;

DROP FUNCTION IF EXISTS public.cancel_scan_job(UUID, UUID);

CREATE OR REPLACE FUNCTION public.cancel_scan_job(
  p_job_id          UUID,
  p_organization_id UUID,
  p_project_id      UUID
)
RETURNS SETOF scan_jobs
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
BEGIN
  RETURN QUERY
    UPDATE scan_jobs
       SET status = 'cancelled',
           completed_at = NOW()
     WHERE id = p_job_id
       AND organization_id = p_organization_id
       AND project_id = p_project_id
       AND type IN ('dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run')
       AND status IN ('queued', 'processing')
     RETURNING *;
END;
$$;

-- Lock down execution to authenticated users + the service role (the worker).
REVOKE ALL ON FUNCTION public.cancel_scan_job(UUID, UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.cancel_scan_job(UUID, UUID, UUID)
  TO authenticated, service_role;

COMMENT ON FUNCTION public.cancel_scan_job IS
  'Phase 34b (v2.1d /criticalreview HEH-1 fix): atomically cancel a queued/processing DAST scan_jobs row scoped to (organization, project). Returns the updated row, or empty set if the job is not in a cancellable state OR the (org, project, type) tuple does not match — route maps empty to 404 vs 409 via a follow-up probe.';

COMMIT;

-- Sanity: exactly one cancel_scan_job overload after this migration,
-- with the 3-arg signature.
DO $$
DECLARE v_count INT;
BEGIN
  SELECT count(*) INTO v_count
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE p.proname = 'cancel_scan_job'
     AND n.nspname = 'public';
  IF v_count <> 1 THEN
    RAISE EXCEPTION 'phase34b: unexpected cancel_scan_job overload count: %', v_count;
  END IF;
END $$;
