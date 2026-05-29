-- Phase 42: fleet dispatcher snapshot RPC + queued index.
--
-- Supports the horizontally-scalable extraction autoscaler
-- (backend/src/lib/fleet-dispatcher.ts). fleet_scan_snapshot returns, in ONE
-- round-trip, the running machine ids (for the inflight union) and the per-org
-- {queued, inflight} breakdown (for claimable-aware desired). Reading both in a
-- single STABLE function avoids the TOCTOU skew of separate queries while
-- workers concurrently claim jobs mid-tick.
--
-- NOTE: idx_scan_jobs_queued is created CONCURRENTLY in a SEPARATE non-
-- transactional step (it cannot run inside the migration transaction). See the
-- accompanying execute_sql step / plan.

CREATE OR REPLACE FUNCTION public.fleet_scan_snapshot(p_type text)
RETURNS jsonb
LANGUAGE sql
STABLE
AS $function$
  SELECT jsonb_build_object(
    'running_machine_ids', COALESCE((
      SELECT jsonb_agg(DISTINCT machine_id)
      FROM scan_jobs
      WHERE status = 'processing'
        AND type = p_type
        AND machine_id IS NOT NULL
    ), '[]'::jsonb),
    'per_org', COALESCE((
      SELECT jsonb_agg(jsonb_build_object(
        'organization_id', t.organization_id,
        'queued', t.queued,
        'inflight', t.inflight
      ))
      FROM (
        SELECT organization_id,
          COUNT(*) FILTER (WHERE status = 'queued')     AS queued,
          COUNT(*) FILTER (WHERE status = 'processing') AS inflight
        FROM scan_jobs
        WHERE type = p_type
          AND status IN ('queued', 'processing')
        GROUP BY organization_id
      ) t
    ), '[]'::jsonb)
  );
$function$;

COMMENT ON FUNCTION public.fleet_scan_snapshot IS
  'Fleet dispatcher snapshot: running machine ids + per-org queued/inflight counts for one scan type, in a single round-trip.';

-- Applied separately as a non-transactional step (CONCURRENTLY):
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_scan_jobs_queued
--   ON scan_jobs (type, created_at) WHERE status = 'queued';
