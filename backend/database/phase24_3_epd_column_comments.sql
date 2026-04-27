-- Phase 24.3: clarify EPD column semantics
--
-- Phase 4 critical review surfaced two ambiguities operators and admins
-- have stumbled on:
--   1. epd_max_run_cost_usd is a PER-EXTRACTION cap, not org-wide. With
--      sync_frequency=on_commit and N concurrent extractions, total org
--      spend per minute can be N * cap. A monthly per-org cap is a
--      Phase 5 follow-up; for now we make the per-run scope explicit in
--      the column comment so DB-level readers don't assume otherwise.
--   2. epd_budget_exceeded_behavior=fail_job kills the ENTIRE
--      extraction run (SBOM, vulns, secrets all discarded), not just
--      the EPD step. continue_with_fallback is the recommended setting
--      for most orgs — the comment now reflects that explicitly.
--
-- Schema-only change (column comments). Backend code is unchanged; the
-- HTTP handler and worker still read these columns the same way.

COMMENT ON COLUMN organizations.epd_max_run_cost_usd IS
  'Per-extraction (not per-org-month) EPD AI spend cap in USD (Anthropic BYOK). Each concurrent extraction gets its own budget — there is no org-wide ceiling. NULL falls back to EPD_MAX_RUN_COST_USD env (default $3.00). HTTP handler clamps to 0.10-20.00 on write.';

COMMENT ON COLUMN organizations.epd_budget_exceeded_behavior IS
  'On EPD AI budget exhaustion mid-extraction: fail_job throws EpdBudgetExceededError which FAILS THE ENTIRE EXTRACTION RUN (SBOM, vulns, secrets, semgrep findings all discarded). continue_with_fallback applies heuristic-only EPD scoring to the remaining vulns and lets the extraction finalize normally. continue_with_fallback is recommended for most orgs. NULL falls back to EPD_BUDGET_EXCEEDED_BEHAVIOR env (default fail_job).';
