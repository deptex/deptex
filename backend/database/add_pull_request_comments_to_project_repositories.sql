-- Add pull_request_comments_enabled to project_repositories
-- When true, Deptex posts policy check results as comments on pull requests.

ALTER TABLE project_repositories
  ADD COLUMN IF NOT EXISTS pull_request_comments_enabled BOOLEAN DEFAULT true;

COMMENT ON COLUMN project_repositories.pull_request_comments_enabled IS 'When true, Deptex posts policy/vulnerability check results as comments on pull requests.';
