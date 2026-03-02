-- Add policy-engine columns to projects.
-- status_id replaces the legacy is_compliant boolean and status text.
-- asset_tier_id replaces the hardcoded asset_tier enum.

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS status_id UUID REFERENCES organization_statuses(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS status_violations TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS policy_evaluated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS asset_tier_id UUID REFERENCES organization_asset_tiers(id) ON DELETE SET NULL;

-- Effective policy override columns (null = inherited from org)
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS effective_package_policy_code TEXT,
  ADD COLUMN IF NOT EXISTS effective_project_status_code TEXT,
  ADD COLUMN IF NOT EXISTS effective_pr_check_code TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_status_id
  ON projects(status_id);

CREATE INDEX IF NOT EXISTS idx_projects_asset_tier_id
  ON projects(asset_tier_id);

COMMENT ON COLUMN projects.status_id IS 'FK to organization_statuses. Set by policy engine after evaluation. Replaces is_compliant.';
COMMENT ON COLUMN projects.status_violations IS 'Array of violation messages from the last policy evaluation.';
COMMENT ON COLUMN projects.policy_evaluated_at IS 'Timestamp of the last policy evaluation run.';
COMMENT ON COLUMN projects.asset_tier_id IS 'FK to organization_asset_tiers. Replaces the hardcoded asset_tier enum.';
COMMENT ON COLUMN projects.effective_package_policy_code IS 'Project-level package policy override. NULL = inherited from org.';
COMMENT ON COLUMN projects.effective_project_status_code IS 'Project-level status code override. NULL = inherited from org.';
COMMENT ON COLUMN projects.effective_pr_check_code IS 'Project-level PR check code override. NULL = inherited from org.';
