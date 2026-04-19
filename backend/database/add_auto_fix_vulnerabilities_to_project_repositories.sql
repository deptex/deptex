-- Add auto_fix_vulnerabilities_enabled to project_repositories
-- When true, Deptex creates fix PRs for critical security vulnerabilities.

ALTER TABLE project_repositories
  ADD COLUMN IF NOT EXISTS auto_fix_vulnerabilities_enabled BOOLEAN DEFAULT false;

COMMENT ON COLUMN project_repositories.auto_fix_vulnerabilities_enabled IS 'When true, Deptex creates fix PRs for critical security issues.';
