-- Add policy-as-code fields to project_policy_exceptions.
-- requested_policy_code: the policy code the project is requesting.
-- base_policy_code: snapshot of the policy they are changing from (for diff in review).
ALTER TABLE project_policy_exceptions
  ADD COLUMN IF NOT EXISTS requested_policy_code TEXT,
  ADD COLUMN IF NOT EXISTS base_policy_code TEXT;
