-- Phase 43: fleet fairness — per-org concurrency cap + fewest-in-flight-first claim.
--
-- Replaces the FIFO-only claim_scan_job so one org's bulk import can't starve
-- or monopolize the shared fleet. A queued job is claimable only if its org has
-- fewer than p_max_per_org jobs already processing; among claimable jobs, the
-- org with the fewest in-flight wins, then oldest-first.
--
-- IMPORTANT: we DROP the old 2-arg signature first. CREATE OR REPLACE with a
-- 3rd argument does NOT replace it — it creates a SECOND overload, after which
-- the worker's by-name RPC call ({p_machine_id, p_supported_types}) matches BOTH
-- and PostgREST returns 300 (ambiguous). p_max_per_org keeps a DEFAULT so an
-- old worker still mid-deploy resolves against the new function.
--
-- Rollout order (binding): apply this migration FIRST (3-arg w/ DEFAULT is
-- backward-compatible with the 2-arg caller), verify exactly one function
-- exists, then deploy the worker that passes p_max_per_org.
--
-- The supporting partial index is created CONCURRENTLY in a SEPARATE non-
-- transactional step (cannot run inside this migration's transaction):
--   CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_jobs_inflight_by_org
--     ON scan_jobs (organization_id, type) WHERE status = 'processing';

DROP FUNCTION IF EXISTS public.claim_scan_job(text, text[]);

CREATE OR REPLACE FUNCTION public.claim_scan_job(
  p_machine_id      text,
  p_supported_types text[],
  p_max_per_org     int DEFAULT 5
)
RETURNS SETOF scan_jobs
LANGUAGE sql
AS $function$
  UPDATE scan_jobs
  SET status       = 'processing',
      started_at   = NOW(),
      heartbeat_at = NOW(),
      machine_id   = p_machine_id,
      attempts     = attempts + 1
  WHERE id = (
    SELECT q.id
    FROM scan_jobs q
    WHERE q.status = 'queued'
      AND q.type = ANY(p_supported_types)
      AND (
        SELECT COUNT(*) FROM scan_jobs p
        WHERE p.status = 'processing'
          AND p.type = ANY(p_supported_types)
          AND p.organization_id = q.organization_id
      ) < p_max_per_org
    ORDER BY (
      SELECT COUNT(*) FROM scan_jobs p
      WHERE p.status = 'processing'
        AND p.type = ANY(p_supported_types)
        AND p.organization_id = q.organization_id
    ) ASC, q.created_at ASC
    LIMIT 1
    FOR UPDATE SKIP LOCKED
  )
  RETURNING *;
$function$;

COMMENT ON FUNCTION public.claim_scan_job IS
  'Atomically claim one queued scan job (FOR UPDATE SKIP LOCKED). Enforces a per-org in-flight cap (p_max_per_org) and prefers the org with the fewest in-flight jobs, then oldest-first, for cross-tenant fairness.';

-- ROLLBACK (restore FIFO behavior):
--   DROP FUNCTION IF EXISTS public.claim_scan_job(text, text[], int);
--   CREATE OR REPLACE FUNCTION public.claim_scan_job(p_machine_id text, p_supported_types text[])
--   RETURNS SETOF scan_jobs LANGUAGE sql AS $$
--     UPDATE scan_jobs SET status='processing', started_at=NOW(), heartbeat_at=NOW(),
--       machine_id=p_machine_id, attempts=attempts+1
--     WHERE id = (SELECT id FROM scan_jobs WHERE status='queued' AND type = ANY(p_supported_types)
--       ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING *;
--   $$;
