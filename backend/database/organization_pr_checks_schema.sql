-- Organization PR Checks: PR-level policy code that determines pass/fail on pull requests.
-- One row per org. Runs pullRequestCheck(context) with added/updated/removed deps.

CREATE TABLE IF NOT EXISTS organization_pr_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  pr_check_code TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by_id UUID,
  UNIQUE(organization_id)
);

COMMENT ON TABLE organization_pr_checks IS 'Stores the pullRequestCheck() function code. Runs per-PR to return { status, violations }.';
