-- Organization Policy Changes: version history for org-level policy edits.
-- Each code type has its own independent chain per org.
-- Simpler than project-level: no pending/review flow (applied immediately by manage_compliance users).

CREATE TABLE IF NOT EXISTS organization_policy_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_type TEXT NOT NULL CHECK (code_type IN ('package_policy', 'project_status', 'pr_check')),
  author_id UUID NOT NULL,
  parent_id UUID REFERENCES organization_policy_changes(id) ON DELETE SET NULL,
  previous_code TEXT NOT NULL,
  new_code TEXT NOT NULL,
  message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_organization_policy_changes_org
  ON organization_policy_changes(organization_id, code_type);

COMMENT ON TABLE organization_policy_changes IS 'Version history for org-level policy edits. Each save creates a new row for revert capability.';
COMMENT ON COLUMN organization_policy_changes.parent_id IS 'Points to the previous change of the same code_type for the same org.';
