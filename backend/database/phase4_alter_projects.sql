-- Phase 4A: Alter projects table for custom statuses, tiers, and policy overrides

-- Add status_id (FK to organization_statuses, replaces is_compliant + status TEXT)
ALTER TABLE projects ADD COLUMN IF NOT EXISTS status_id UUID REFERENCES organization_statuses(id) ON DELETE SET NULL;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS status_violations TEXT[] DEFAULT '{}';
ALTER TABLE projects ADD COLUMN IF NOT EXISTS policy_evaluated_at TIMESTAMPTZ;

-- Add asset_tier_id (FK to organization_asset_tiers, replaces asset_tier enum)
ALTER TABLE projects ADD COLUMN IF NOT EXISTS asset_tier_id UUID REFERENCES organization_asset_tiers(id) ON DELETE SET NULL;

-- Project-level policy overrides (each independently nullable = inherited from org)
ALTER TABLE projects ADD COLUMN IF NOT EXISTS effective_package_policy_code TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS effective_project_status_code TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS effective_pr_check_code TEXT;

-- Add policy_result JSONB to project_dependencies (stores per-dep packagePolicy output)
ALTER TABLE project_dependencies ADD COLUMN IF NOT EXISTS policy_result JSONB;

CREATE INDEX IF NOT EXISTS idx_projects_status_id ON projects(status_id);
CREATE INDEX IF NOT EXISTS idx_projects_asset_tier_id ON projects(asset_tier_id);
CREATE INDEX IF NOT EXISTS idx_project_dependencies_policy_result ON project_dependencies USING gin(policy_result);

COMMENT ON COLUMN projects.status_id IS 'FK to organization_statuses. Set by policy engine after evaluation. Replaces is_compliant.';
COMMENT ON COLUMN projects.status_violations IS 'Array of violation messages from the last policy evaluation.';
COMMENT ON COLUMN projects.policy_evaluated_at IS 'Timestamp of the last policy evaluation run.';
COMMENT ON COLUMN projects.asset_tier_id IS 'FK to organization_asset_tiers. Replaces the hardcoded asset_tier enum.';
COMMENT ON COLUMN projects.effective_package_policy_code IS 'Project-level package policy override. NULL = inherited from org.';
COMMENT ON COLUMN projects.effective_project_status_code IS 'Project-level status code override. NULL = inherited from org.';
COMMENT ON COLUMN projects.effective_pr_check_code IS 'Project-level PR check code override. NULL = inherited from org.';
COMMENT ON COLUMN project_dependencies.policy_result IS 'Result of packagePolicy() execution: { allowed: boolean, reasons: string[] }. NULL if policy has not been evaluated.';
