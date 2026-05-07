-- Phase 24: EPD per-org configuration
--
-- Adds organization-level knobs for the EPD (Exploitable Path Dominance)
-- contextual scoring pass that runs in the extraction worker's pipeline.
-- The scorer is in depscanner/src/epd.ts; both columns
-- are optional and fall back to the EPD_MAX_RUN_COST_USD and
-- EPD_BUDGET_EXCEEDED_BEHAVIOR env vars when NULL so single-tenant
-- self-hosters don't need to touch the database to tune EPD.

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS epd_max_run_cost_usd NUMERIC(6, 2),
  ADD COLUMN IF NOT EXISTS epd_budget_exceeded_behavior TEXT;

-- Enum guard. A NULL means "inherit the env default" (the worker reads
-- EPD_BUDGET_EXCEEDED_BEHAVIOR, which itself defaults to `fail_job`).
-- We don't constrain epd_max_run_cost_usd server-side because the HTTP
-- handler clamps on write; a DB CHECK would fight with future AI
-- pricing changes.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'organizations_epd_budget_exceeded_behavior_check'
  ) THEN
    ALTER TABLE organizations
      ADD CONSTRAINT organizations_epd_budget_exceeded_behavior_check
      CHECK (epd_budget_exceeded_behavior IN ('fail_job', 'continue_with_fallback'));
  END IF;
END $$;

COMMENT ON COLUMN organizations.epd_max_run_cost_usd IS
  'Per-extraction EPD AI spend cap in USD (Anthropic BYOK). NULL falls back to EPD_MAX_RUN_COST_USD env (default $3.00). HTTP handler clamps to 0.10-20.00 on write.';

COMMENT ON COLUMN organizations.epd_budget_exceeded_behavior IS
  'On EPD budget exhaustion mid-extraction: fail_job (throw EpdBudgetExceededError, fail extraction) or continue_with_fallback (heuristic for remaining vulns). NULL falls back to EPD_BUDGET_EXCEEDED_BEHAVIOR env (default fail_job).';
