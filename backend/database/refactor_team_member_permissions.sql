-- ============================================================
-- Refactor Team Member Permissions
-- - Add manage_members as top-level permission (add + remove people)
-- - manage_members replaces view_members for the "manage" aspect
-- - Viewing members tab requires no permission (unchanged)
-- ============================================================

-- Step 1: Add manage_members to all existing team roles
-- Map: manage_members = true if add_members OR kick_members was true
UPDATE team_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_members}',
  to_jsonb(
    COALESCE((permissions->>'add_members')::boolean, false) OR
    COALESCE((permissions->>'kick_members')::boolean, false)
  ),
  true
)
WHERE NOT (permissions ? 'manage_members');

-- Step 2: For roles that already have manage_members, ensure it's set correctly
UPDATE team_roles
SET permissions = jsonb_set(
  permissions,
  '{manage_members}',
  to_jsonb(
    COALESCE((permissions->>'manage_members')::boolean, false) OR
    COALESCE((permissions->>'add_members')::boolean, false) OR
    COALESCE((permissions->>'kick_members')::boolean, false)
  ),
  true
)
WHERE permissions ? 'manage_members';

-- Step 3: Update create_default_team_roles for new teams
-- Admin: manage_members, view_settings, edit_roles (keep add_members/kick_members for backend compat)
-- Member: all false
CREATE OR REPLACE FUNCTION create_default_team_roles()
RETURNS TRIGGER AS $$
BEGIN
  -- Create admin role with all permissions
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'admin', 'Admin', true, 0, '{
    "view_overview": true,
    "manage_projects": true,
    "manage_members": true,
    "view_settings": true,
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
    "manage_members": false,
    "view_settings": false,
    "add_members": false,
    "kick_members": false,
    "view_roles": false,
    "edit_roles": false,
    "manage_notification_settings": false
  }'::jsonb);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
