-- Add policy_type to project_policy_exceptions for per-type pending limits.
-- compliance = projectCompliance function change only
-- pull_request = pullRequestCheck function change only
-- full = both functions changed (backwards compat for existing rows)
ALTER TABLE project_policy_exceptions
  ADD COLUMN IF NOT EXISTS policy_type TEXT DEFAULT 'full' CHECK (policy_type IN ('compliance', 'pull_request', 'full'));

-- Index for one-per-type pending check
CREATE INDEX IF NOT EXISTS idx_project_policy_exceptions_project_pending_type
  ON project_policy_exceptions(organization_id, project_id, status, policy_type)
  WHERE status = 'pending';
