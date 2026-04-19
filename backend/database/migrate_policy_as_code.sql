-- Policy as Code: replace license/SLSA columns with single policy_code blob.
-- Run after organization_policies_schema.sql and project_policy_exceptions_schema.sql.

-- 1. organization_policies: add policy_code, then drop old columns
ALTER TABLE organization_policies
  ADD COLUMN IF NOT EXISTS policy_code TEXT DEFAULT '';

-- Drop old columns (order does not matter)
ALTER TABLE organization_policies DROP COLUMN IF EXISTS accepted_licenses;
ALTER TABLE organization_policies DROP COLUMN IF EXISTS rejected_licenses;
ALTER TABLE organization_policies DROP COLUMN IF EXISTS slsa_enforcement;
ALTER TABLE organization_policies DROP COLUMN IF EXISTS slsa_level;

-- 2. Clear all project policy exception data (table and RLS remain for future use)
TRUNCATE project_policy_exceptions;
