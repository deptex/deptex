-- Add policy_result JSONB to project_dependencies.
-- Stores the output of packagePolicy() for each dep: { allowed: boolean, reasons: string[] }

ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS policy_result JSONB;

COMMENT ON COLUMN project_dependencies.policy_result IS 'Result of packagePolicy() execution: { allowed: boolean, reasons: string[] }. NULL if policy has not been evaluated.';
