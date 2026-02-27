-- ===========================================
-- Remove resolve_alerts Permission
-- Removes the resolve_alerts permission from team roles
-- Run this migration manually when ready.
-- ===========================================

-- Step 1: Remove resolve_alerts from all existing team roles
UPDATE team_roles
SET permissions = permissions - 'resolve_alerts'
WHERE permissions ? 'resolve_alerts';

-- Step 2: Update the function that creates default team roles (remove resolve_alerts)
CREATE OR REPLACE FUNCTION create_default_team_roles()
RETURNS TRIGGER AS $$
BEGIN
  -- Create admin role with all permissions
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'admin', 'Admin', true, 0, '{
    "view_overview": true,
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
