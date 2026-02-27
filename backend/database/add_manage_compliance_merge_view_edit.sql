-- Migration: Merge view_compliance and edit_policies into manage_compliance
-- Run this migration to combine the two permissions into a single manage_compliance permission.
-- manage_compliance = true if either view_compliance OR edit_policies was true (preserves access).

-- Add manage_compliance: true if either view_compliance or edit_policies was true
UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_compliance}',
  to_jsonb(COALESCE((permissions->>'view_compliance')::boolean, false) OR COALESCE((permissions->>'edit_policies')::boolean, false)),
  true
);

-- Remove old keys
UPDATE organization_roles
SET permissions = permissions - 'view_compliance' - 'edit_policies';
