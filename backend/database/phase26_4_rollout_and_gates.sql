-- Phase 6 / M8: per-org rollout override + retirement-gate aggregator RPC.
--
-- Adds:
--   1. taint_engine_settings.rollout_pct_override (NULL = use env var,
--      0..100 = force-enable for this org regardless of fleet rollout).
--      Lets us canary specific orgs (or freeze them off) without a
--      worker redeploy.
--   2. get_taint_engine_recent_runs(p_days) RPC. Returns one row per
--      run in the past N days with the columns the M8 gate evaluator
--      needs. Server-side filtering keeps the payload small even when
--      the table grows over the 30-day shadow window.

ALTER TABLE public.taint_engine_settings
  ADD COLUMN IF NOT EXISTS rollout_pct_override smallint;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'taint_engine_settings_rollout_chk'
  ) THEN
    ALTER TABLE public.taint_engine_settings
      ADD CONSTRAINT taint_engine_settings_rollout_chk
        CHECK (rollout_pct_override IS NULL
               OR (rollout_pct_override >= 0 AND rollout_pct_override <= 100));
  END IF;
END$$;

CREATE OR REPLACE FUNCTION public.get_taint_engine_recent_runs(p_days integer)
RETURNS TABLE (
  status text,
  ai_cost_usd numeric,
  total_ms integer,
  failed_at timestamptz,
  organization_id uuid,
  project_id uuid
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    status,
    ai_cost_usd,
    total_ms,
    completed_at AS failed_at,
    organization_id,
    project_id
  FROM public.taint_engine_runs
  WHERE created_at >= now() - (GREATEST(p_days, 1) || ' days')::interval;
$$;

GRANT EXECUTE ON FUNCTION public.get_taint_engine_recent_runs(integer) TO service_role, authenticated;
