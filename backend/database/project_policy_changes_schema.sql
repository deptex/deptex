-- Project Policy Changes: git-like commit chain for project-level policy overrides.
-- Each code type (package_policy, project_status, pr_check) has its own independent chain per project.

CREATE TABLE IF NOT EXISTS project_policy_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_type TEXT NOT NULL CHECK (code_type IN ('package_policy', 'project_status', 'pr_check')),
  author_id UUID NOT NULL,
  reviewer_id UUID,
  parent_id UUID REFERENCES project_policy_changes(id) ON DELETE SET NULL,
  base_code TEXT NOT NULL,
  proposed_code TEXT NOT NULL,
  message TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  is_ai_generated BOOLEAN NOT NULL DEFAULT false,
  ai_merged_code TEXT,
  has_conflict BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_project_policy_changes_project
  ON project_policy_changes(project_id, code_type);

CREATE INDEX IF NOT EXISTS idx_project_policy_changes_org
  ON project_policy_changes(organization_id);

CREATE INDEX IF NOT EXISTS idx_project_policy_changes_status
  ON project_policy_changes(status);

COMMENT ON TABLE project_policy_changes IS 'Git-like commit chain for project-level policy overrides. Each code_type has its own chain per project.';
COMMENT ON COLUMN project_policy_changes.parent_id IS 'Points to the previously accepted change of the same code_type for the same project.';
COMMENT ON COLUMN project_policy_changes.base_code IS 'Snapshot of the effective code when this change was authored (for conflict detection).';
COMMENT ON COLUMN project_policy_changes.has_conflict IS 'True when base_code does not match current effective code at review time.';
