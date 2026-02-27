-- Add manage_notifications permission to organization_roles
-- Allows roles to view and manage notification rules without full manage_integrations
-- Run this migration manually when ready.

-- Set manage_notifications to true for owner and admin roles
UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_notifications}',
  'true'::jsonb,
  true
)
WHERE name IN ('owner', 'admin')
  AND (NOT (permissions ? 'manage_notifications') OR permissions->>'manage_notifications' IS NULL);

-- Set manage_notifications to false for member and other roles (where not already set)
UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_notifications}',
  'false'::jsonb,
  true
)
WHERE name NOT IN ('owner', 'admin')
  AND (NOT (permissions ? 'manage_notifications') OR permissions->>'manage_notifications' IS NULL);
