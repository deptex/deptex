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
