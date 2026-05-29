/**
 * Per-extraction rule generation pipeline step.
 *
 * Sits between vuln_scan and reachability_rules in pipeline.ts. Given the
 * scan's vulnerabilities, the org's trigger policy, and a platform AI key
 * (read from the worker environment), this step:
 *
 *   1. Loads organization_reachability_settings; bails fast when generation
 *      is disabled or the row is missing.
 *   2. Filters vulnerabilities against the trigger policy + asset tier rank.
 *   3. Subtracts CVEs already covered by platform-shipped rules and the
 *      org's existing generated rules (any validation_status).
 *   4. Estimates total cost; halts or downgrades to haiku per the org's
 *      `on_budget_exhaustion` setting if the running monthly spend would
 *      exceed `monthly_budget_usd`.
 *   5. In-process Promise.all with p-limit, each generation wrapped in
 *      withTimeout(240s). Failures of one CVE never block the others —
 *      they log to extraction_step_errors at warn and continue.
 *   6. Upserts validated rules into organization_generated_rules so the
 *      downstream reachability_rules step picks them up via
 *      loadOrgGeneratedRules and Semgrep matches them in this same scan.
 *   7. Persists telemetry (rules_matched, total_detectable, generated this
 *      scan, total cost) to scan_jobs.
 *
 * The step is intentionally non-fatal: any error short-circuits to a warn
 * log and the pipeline continues with whatever rules existed before.
 *
 * --- Implementation note (post-refactor #2) ---
 * The orchestration body lives in `cve-generation/coordinator.ts`
 * (`CveGenerationCoordinator`). This file is a thin re-export point so the
 * pipeline step + tests keep importing through the historical path. See
 * `cve-generation/` for the helper modules:
 *   - provider-resolution  — provider concurrency caps + platform-key resolution
 *   - cost-cap             — readRuleGenMonthlySpend / applyBudgetCap / logRuleGenAiUsage
 *   - trigger-filter       — applyTriggerPolicy / loadOrgExistingRuleCves
 *   - generate-with-retry  — per-CVE retry loop + RateLimitGate
 *   - persist              — persistGeneratedRule + persistJobTelemetry
 *   - telemetry            — aggregateBreakdowns
 *   - coordinator          — CveGenerationCoordinator class
 */

export {
  runRuleGenerationStep,
  aggregateBreakdowns,
  makeStepWorkdir,
  CveGenerationCoordinator,
} from './cve-generation';
export type {
  RunRuleGenerationArgs,
  RunRuleGenerationResult,
  PipelineVulnRow,
  AggregatedValidationBreakdown,
} from './cve-generation';
