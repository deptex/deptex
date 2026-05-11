-- phase33_scan_jobs_ai_telemetry.sql
--
-- Per-scan AI telemetry + per-scan cost cap on `scan_jobs`.
--
-- Why now:
-- - Pre-PR, depscanner wrote `reachability_generation_cost_usd` (rule-gen
--   total only) on the scan row, and `ai_usage_logs` per call. There was no
--   single number for "how much AI did THIS scan burn" that summed
--   rule-gen + fp-filter + EPD-anthropic-fallback. ai_per_model gives the
--   per-model breakdown so the org-admin UI can render "this scan used
--   $0.05 of Sonnet + $0.10 of Qwen + $0.01 of Gemini".
-- - Monthly cap (`organization_reachability_settings.monthly_budget_usd`)
--   gates a whole org over a calendar month. ai_cost_cap_usd lets an
--   operator running a single noisy scan attach an extra per-scan ceiling
--   that the worker honours mid-pipeline.
--
-- Schema-dump intentionally NOT refreshed in this commit. Henry rolls
-- phase30+31+32+33 into a single dump pass when this PR lands.
--
-- All new columns are NULL-safe / default-bearing so the migration is
-- a pure additive — no backfill needed; in-flight scans on old rows
-- read NULL caps (= "no cap") and write NULL telemetry until the worker
-- starts populating it.

ALTER TABLE public.scan_jobs
  ADD COLUMN IF NOT EXISTS ai_total_prompt_tokens BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ai_total_completion_tokens BIGINT NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ai_total_cost_usd NUMERIC(10,4) NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS ai_per_model JSONB NOT NULL DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS ai_cost_cap_usd NUMERIC(10,4);

COMMENT ON COLUMN public.scan_jobs.ai_total_prompt_tokens IS
  'Sum of prompt/input tokens across every AI call attributed to this scan: rule generation (D1-D3), taint fp-filter (D4), EPD Anthropic fallback (D5).';
COMMENT ON COLUMN public.scan_jobs.ai_total_completion_tokens IS
  'Sum of completion/output tokens across every AI call attributed to this scan.';
COMMENT ON COLUMN public.scan_jobs.ai_total_cost_usd IS
  'Sum of estimated USD cost across every AI call attributed to this scan. Replaces (rather than mirrors) reachability_generation_cost_usd at the per-scan level — the older column still gets written for back-compat with the org-admin UI''s historical cost chart, but ai_total_cost_usd is the canonical number.';
COMMENT ON COLUMN public.scan_jobs.ai_per_model IS
  'Array of {model, prompt_tokens, completion_tokens, cost_usd} objects, one per distinct (provider, model) pair the scan touched. Updated incrementally via add_scan_job_ai_usage() so concurrent AI calls from different pipeline steps merge cleanly.';
COMMENT ON COLUMN public.scan_jobs.ai_cost_cap_usd IS
  'Optional per-scan AI cost cap (USD). When set, the worker aborts the next AI call once ai_total_cost_usd + the projected next-call cost would exceed it. NULL means no per-scan cap (org-level monthly cap still applies).';

-- Atomic rollup updater. Lives server-side because we need ai_per_model
-- merged in a single transaction — two concurrent worker calls writing
-- the same scan_job would race a JSONB read-modify-write done from the
-- worker. The function:
--   1. SELECT ... FOR UPDATE to lock the row
--   2. Walks ai_per_model JSONB, finds the existing entry for (model)
--      and updates its tokens + cost; appends a new entry if missing
--   3. Returns the new ai_total_cost_usd (so the worker can decide
--      whether the per-scan cap is now exceeded)
--
-- We don't enforce the cap inside the RPC because the cap is checked
-- BEFORE each call (with a projected cost), not after — by the time the
-- AI call has run, the spend is already incurred. The worker uses
-- check_scan_job_ai_cost_cap() (read-only) for pre-call enforcement and
-- add_scan_job_ai_usage() (mutating) for post-call rollup.
CREATE OR REPLACE FUNCTION public.add_scan_job_ai_usage(
  p_job_id UUID,
  p_organization_id UUID,
  p_provider TEXT,
  p_model TEXT,
  p_prompt_tokens BIGINT,
  p_completion_tokens BIGINT,
  p_cost_usd NUMERIC
)
RETURNS NUMERIC
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  v_existing JSONB;
  v_new JSONB;
  v_idx INT;
  v_found BOOLEAN := FALSE;
  v_new_total NUMERIC(10,4);
BEGIN
  -- Belt-and-braces tenant filter: org id must match the job's org.
  -- The locking SELECT + UPDATE happen in the same transaction.
  PERFORM 1
    FROM public.scan_jobs
   WHERE id = p_job_id
     AND organization_id = p_organization_id
   FOR UPDATE;

  IF NOT FOUND THEN
    RAISE EXCEPTION 'scan_job % not found for organization %', p_job_id, p_organization_id;
  END IF;

  -- Walk the existing array looking for a matching (model) entry.
  -- Provider is stored alongside but model is the dedup key (same model
  -- never appears across providers for our pricing table).
  SELECT ai_per_model INTO v_existing
    FROM public.scan_jobs
   WHERE id = p_job_id;

  v_new := '[]'::jsonb;

  FOR v_idx IN 0 .. (jsonb_array_length(v_existing) - 1) LOOP
    IF (v_existing->v_idx->>'model') = p_model THEN
      v_new := v_new || jsonb_build_object(
        'provider', p_provider,
        'model', p_model,
        'prompt_tokens', COALESCE((v_existing->v_idx->>'prompt_tokens')::bigint, 0) + p_prompt_tokens,
        'completion_tokens', COALESCE((v_existing->v_idx->>'completion_tokens')::bigint, 0) + p_completion_tokens,
        'cost_usd', ROUND(COALESCE((v_existing->v_idx->>'cost_usd')::numeric, 0) + p_cost_usd, 6)
      );
      v_found := TRUE;
    ELSE
      v_new := v_new || (v_existing->v_idx);
    END IF;
  END LOOP;

  IF NOT v_found THEN
    v_new := v_new || jsonb_build_object(
      'provider', p_provider,
      'model', p_model,
      'prompt_tokens', p_prompt_tokens,
      'completion_tokens', p_completion_tokens,
      'cost_usd', ROUND(p_cost_usd, 6)
    );
  END IF;

  UPDATE public.scan_jobs
     SET ai_total_prompt_tokens = ai_total_prompt_tokens + p_prompt_tokens,
         ai_total_completion_tokens = ai_total_completion_tokens + p_completion_tokens,
         ai_total_cost_usd = ai_total_cost_usd + p_cost_usd,
         ai_per_model = v_new
   WHERE id = p_job_id
     AND organization_id = p_organization_id
  RETURNING ai_total_cost_usd INTO v_new_total;

  RETURN v_new_total;
END;
$$;

COMMENT ON FUNCTION public.add_scan_job_ai_usage(UUID, UUID, TEXT, TEXT, BIGINT, BIGINT, NUMERIC) IS
  'Atomically rolls up an AI call into scan_jobs.ai_total_* + ai_per_model. Returns the new ai_total_cost_usd so the caller can decide cost-cap behavior on subsequent calls. Concurrent callers serialise on the FOR UPDATE lock.';
