-- Migration: Add default roles to existing organizations that don't have them
-- This ensures all organizations have owner and member roles defined

-- Insert owner role for organizations that don't have it
INSERT INTO organization_roles (organization_id, name, display_name, display_order, is_default, permissions)
SELECT 
  o.id,
  'owner',
  'Owner',
  0,
  true,
  jsonb_build_object(
    'view_settings', true,
    'manage_billing', true,
    'view_activity', true,
    'edit_policies', true,
    'interact_with_security_agent', true,
    'manage_aegis', true,
    'view_members', true,
    'add_members', true,
    'edit_roles', true,
    'edit_permissions', true,
    'kick_members', true,
    'can_create_teams', true,
    'view_all_teams', true,
    'create_projects', true,
    'view_all_projects', true,
    'view_overview', true
  )
FROM organizations o
WHERE NOT EXISTS (
  SELECT 1 FROM organization_roles r 
  WHERE r.organization_id = o.id 
  AND r.name = 'owner'
);

-- Insert member role for organizations that don't have it
-- Default: all permissions true, owner can customize as needed
INSERT INTO organization_roles (organization_id, name, display_name, display_order, is_default, permissions)
SELECT 
  o.id,
  'member',
  'Member',
  2,
  true,
  jsonb_build_object(
    'view_settings', true,
    'manage_billing', true,
    'view_activity', true,
    'edit_policies', true,
    'interact_with_security_agent', true,
    'manage_aegis', true,
    'view_members', true,
    'add_members', true,
    'edit_roles', true,
    'edit_permissions', true,
    'kick_members', true,
    'can_create_teams', true,
    'view_all_teams', true,
    'create_projects', true,
    'view_all_projects', true,
    'view_overview', true
  )
FROM organizations o
WHERE NOT EXISTS (
  SELECT 1 FROM organization_roles r 
  WHERE r.organization_id = o.id 
  AND r.name = 'member'
);
