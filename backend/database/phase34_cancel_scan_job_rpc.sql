-- Phase 34 (v2.1d): cancel_scan_job RPC.
--
-- Adds a user-initiated cancellation path for queued/processing scan_jobs.
-- The worker's existing isJobCancelled() poll (depscanner/src/dast/pipeline.ts
-- line ~1099) reads the resulting `status='cancelled'` and short-circuits its
-- scan loop on the next heartbeat tick.
--
-- v2.1d UX depends on this: when a Test-login button is blocked by a real
-- scan holding the 1/project concurrency slot, the editor offers a "Cancel
-- running scan" affordance that calls POST /dast/jobs/:jobId/cancel, which
-- delegates to this RPC.
--
-- The p_organization_id parameter defends in depth on top of the route
-- handler's tenant check: the UPDATE only matches rows belonging to the
-- caller's org. Cross-org calls return an empty set (not an error), which
-- the route maps to 404 — same posture as v2.1a's loadTargetOrDeny.
--
-- Self-contained migration: no signature changes to existing RPCs, no CHECK
-- changes, no schema overlap with v2.1c objects.

CREATE OR REPLACE FUNCTION cancel_scan_job(
  p_job_id          UUID,
  p_organization_id UUID
)
RETURNS SETOF scan_jobs
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
  RETURN QUERY
    UPDATE scan_jobs
       SET status = 'cancelled',
           completed_at = NOW()
     WHERE id = p_job_id
       AND organization_id = p_organization_id
       AND status IN ('queued', 'processing')
     RETURNING *;
END;
$$;

-- Lock down execution to authenticated users + the service role (the worker).
-- anon stays off the function — cancellation must require a logged-in user.
REVOKE ALL ON FUNCTION cancel_scan_job(UUID, UUID) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION cancel_scan_job(UUID, UUID) TO authenticated, service_role;

COMMENT ON FUNCTION cancel_scan_job IS
  'Phase 34 (v2.1d): atomically cancel a queued/processing scan_jobs row scoped to the caller org. Returns the updated row, or empty set if the job is not in a cancellable state OR the org id does not match (route maps empty to 404).';

-- Sanity: exactly one cancel_scan_job overload exists after this migration.
DO $$ BEGIN
  IF (SELECT count(*) FROM pg_proc WHERE proname = 'cancel_scan_job') <> 1 THEN
    RAISE EXCEPTION 'phase34: unexpected cancel_scan_job overload count';
  END IF;
END $$;

-- =============================================================================
-- After applying: regenerate schema.sql via `cd depscanner && npm run schema:dump`
-- =============================================================================
