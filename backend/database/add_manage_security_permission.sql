-- Add manage_security permission to organization_roles
-- Sub-permission of view_settings. When enabled, grants access to SSO, MFA, and Legal Documents sections.
-- Run this migration manually when ready.

-- Set manage_security to true for owner, admin, and member roles (backward compatibility)
UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_security}',
  'true'::jsonb,
  true
)
WHERE name IN ('owner', 'admin', 'member')
  AND (NOT (permissions ? 'manage_security') OR permissions->>'manage_security' IS NULL);

-- Set manage_security to false for other custom roles (where not already set)
UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_security}',
  'false'::jsonb,
  true
)
WHERE name NOT IN ('owner', 'admin', 'member')
  AND (NOT (permissions ? 'manage_security') OR permissions->>'manage_security' IS NULL);
