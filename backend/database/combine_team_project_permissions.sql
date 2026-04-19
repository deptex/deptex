-- Migration: Simplify to Single Manage Permission
-- This migration:
-- 1. Adds manage_teams_and_projects (true if either creating/managing teams OR projects was true)
-- 2. Removes view_all_teams_and_projects key if it exists
-- 3. Removes old individual permission keys

-- Update all organization_roles permissions
UPDATE organization_roles
SET permissions = (
  -- Build the new permissions object
  jsonb_build_object(
    'view_settings', COALESCE((permissions->>'view_settings')::boolean, false),
    'manage_billing', COALESCE((permissions->>'manage_billing')::boolean, false),
    'view_activity', COALESCE((permissions->>'view_activity')::boolean, false),
    'edit_policies', COALESCE((permissions->>'edit_policies')::boolean, false),
    'interact_with_security_agent', COALESCE((permissions->>'interact_with_security_agent')::boolean, false),
    'manage_aegis', COALESCE((permissions->>'manage_aegis')::boolean, false),
    'view_members', COALESCE((permissions->>'view_members')::boolean, false),
    'add_members', COALESCE((permissions->>'add_members')::boolean, false),
    'edit_roles', COALESCE((permissions->>'edit_roles')::boolean, false),
    'edit_permissions', COALESCE((permissions->>'edit_permissions')::boolean, false),
    'kick_members', COALESCE((permissions->>'kick_members')::boolean, false),
    'view_overview', COALESCE((permissions->>'view_overview')::boolean, false),
    -- Combined Manage Permission
    'manage_teams_and_projects', (
      COALESCE((permissions->>'can_create_teams')::boolean, false) OR 
      COALESCE((permissions->>'create_projects')::boolean, false) OR
      COALESCE((permissions->>'create_teams')::boolean, false) OR
      COALESCE((permissions->>'create_teams_and_projects')::boolean, false) OR
      COALESCE((permissions->>'manage_teams_and_projects')::boolean, false)
    )
  )
),
updated_at = NOW()
WHERE permissions IS NOT NULL;

-- Verify the migration
SELECT 
  id, 
  name, 
  organization_id,
  permissions->>'manage_teams_and_projects' as manage_teams_and_projects
FROM organization_roles
LIMIT 10;
