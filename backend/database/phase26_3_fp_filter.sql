-- Phase 6 / M7: per-flow AI false-positive filter.
--
-- Adds two pieces:
--   1. A confidence threshold on taint_engine_settings. The deterministic
--      engine emits a per-flow confidence in [0,1]; flows below this
--      threshold are routed to the LLM filter ("flows the engine is unsure
--      about"). Default 0.7 per the locked decision.
--   2. A server-side aggregator the worker calls before invoking the
--      filter, so we can hard-fail if the next batch of flows would
--      exceed the org's monthly cap. Returning the sum from SQL avoids
--      adding a `gte` operator to the worker's storage abstraction (which
--      would have been a wider refactor than this milestone needs).

ALTER TABLE public.taint_engine_settings
  ADD COLUMN IF NOT EXISTS ai_fp_filter_confidence_threshold numeric(3,2) DEFAULT 0.70;

ALTER TABLE public.taint_engine_settings
  ADD CONSTRAINT taint_engine_settings_threshold_chk
    CHECK (ai_fp_filter_confidence_threshold >= 0 AND ai_fp_filter_confidence_threshold <= 1);

CREATE OR REPLACE FUNCTION public.get_taint_engine_monthly_spend(p_organization_id uuid)
RETURNS numeric
LANGUAGE sql
STABLE
AS $$
  SELECT COALESCE(SUM(estimated_cost), 0)::numeric
  FROM public.ai_usage_logs
  WHERE organization_id = p_organization_id
    AND success = true
    AND feature IN ('taint_engine_spec_inference', 'taint_engine_fp_filter')
    AND created_at >= date_trunc('month', now() AT TIME ZONE 'UTC');
$$;

GRANT EXECUTE ON FUNCTION public.get_taint_engine_monthly_spend(uuid) TO service_role, authenticated;
