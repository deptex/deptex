-- ===========================================
-- Add manage_notification_settings Permission
-- Adds the new permission to team roles
-- ===========================================

-- Step 1: Update the function that creates default team roles
CREATE OR REPLACE FUNCTION create_default_team_roles()
RETURNS TRIGGER AS $$
BEGIN
  -- Create admin role with all permissions
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'admin', 'Admin', true, 0, '{
    "view_overview": true,
    "resolve_alerts": true,
    "manage_projects": true,
    "view_settings": true,
    "view_members": true,
    "add_members": true,
    "kick_members": true,
    "view_roles": true,
    "edit_roles": true,
    "manage_notification_settings": false
  }'::jsonb);
  
  -- Create member role with minimal permissions (can always view overview)
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'member', 'Member', true, 1, '{
    "view_overview": true,
    "resolve_alerts": false,
    "manage_projects": false,
    "view_settings": false,
    "view_members": false,
    "add_members": false,
    "kick_members": false,
    "view_roles": false,
    "edit_roles": false,
    "manage_notification_settings": false
  }'::jsonb);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Step 2: Add manage_notification_settings to all existing team roles
-- This ensures existing roles have the permission set to false by default
UPDATE team_roles
SET permissions = jsonb_set(
  permissions,
  '{manage_notification_settings}',
  'false'::jsonb,
  true
)
WHERE NOT (permissions ? 'manage_notification_settings');
