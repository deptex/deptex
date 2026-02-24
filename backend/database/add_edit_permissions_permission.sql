-- Migration: Add edit_permissions permission to existing roles
-- This adds the edit_permissions field to all existing role permissions
-- edit_permissions depends on view_settings, so it's only true if view_settings is also true

UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{edit_permissions}',
  CASE 
    WHEN name = 'owner' THEN 'true'::jsonb
    WHEN COALESCE(permissions->>'view_settings', 'false') = 'true' AND COALESCE(permissions->>'edit_roles', 'false') = 'true' THEN 'true'::jsonb
    ELSE 'false'::jsonb
  END
),
updated_at = NOW()
WHERE permissions IS NULL OR NOT (permissions ? 'edit_permissions');

