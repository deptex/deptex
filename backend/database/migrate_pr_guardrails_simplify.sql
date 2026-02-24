-- Migrate project_pr_guardrails: remove reachable/score/unmaintained, add policy + transitive.
-- Run after project_pr_guardrails_schema.sql.

-- Add new columns first (with defaults for existing rows)
ALTER TABLE project_pr_guardrails
  ADD COLUMN IF NOT EXISTS block_policy_violations BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS block_transitive_vulns BOOLEAN DEFAULT false;

-- Drop removed columns
ALTER TABLE project_pr_guardrails DROP COLUMN IF EXISTS vulns_only_if_reachable;
ALTER TABLE project_pr_guardrails DROP COLUMN IF EXISTS score_check_enabled;
ALTER TABLE project_pr_guardrails DROP COLUMN IF EXISTS min_package_score;
ALTER TABLE project_pr_guardrails DROP COLUMN IF EXISTS unmaintained_check_enabled;
ALTER TABLE project_pr_guardrails DROP COLUMN IF EXISTS unmaintained_threshold_days;
