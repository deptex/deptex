-- Add 'revoked' to the status CHECK constraint on project_policy_exceptions
-- This allows org admins to revoke a previously accepted exception,
-- causing the project to fall back to the organization's policy.

ALTER TABLE project_policy_exceptions
  DROP CONSTRAINT IF EXISTS project_policy_exceptions_status_check;

ALTER TABLE project_policy_exceptions
  ADD CONSTRAINT project_policy_exceptions_status_check
  CHECK (status IN ('pending', 'accepted', 'rejected', 'revoked'));

-- Add revoked_by and revoked_at columns for audit trail
ALTER TABLE project_policy_exceptions
  ADD COLUMN IF NOT EXISTS revoked_by UUID,
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
