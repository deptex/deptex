-- ============================================================
-- Add manage_members permission to team roles
-- Consolidates view_members, add_members, and kick_members
-- ============================================================

-- Step 1: Add manage_members column to team_roles
ALTER TABLE team_roles ADD COLUMN IF NOT EXISTS manage_members_temp BOOLEAN;

-- Step 2: Set manage_members based on existing permissions
-- If a role has add_members OR kick_members, they get manage_members
UPDATE team_roles
SET manage_members_temp = (
  (permissions->>'add_members')::boolean = true OR
  (permissions->>'kick_members')::boolean = true
);

-- Step 3: Update permissions JSON to include manage_members and remove old permissions
UPDATE team_roles
SET permissions = permissions 
  - 'view_members' 
  - 'add_members' 
  - 'kick_members'
  || jsonb_build_object('manage_members', COALESCE(manage_members_temp, false));

-- Step 4: Drop the temporary column
ALTER TABLE team_roles DROP COLUMN IF EXISTS manage_members_temp;

-- Step 5: Update the create_default_team_roles function
CREATE OR REPLACE FUNCTION create_default_team_roles()
RETURNS TRIGGER AS $$
BEGIN
  -- Create admin role with all permissions
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'admin', 'Admin', true, 0, '{
    "view_overview": true,
    "resolve_alerts": true,
    "manage_projects": true,
    "manage_members": true,
    "view_settings": true,
    "view_roles": true,
    "edit_roles": true
  }'::jsonb);
  
  -- Create member role with minimal permissions (can always view overview)
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'member', 'Member', true, 1, '{
    "view_overview": true,
    "resolve_alerts": false,
    "manage_projects": false,
    "manage_members": false,
    "view_settings": false,
    "view_roles": false,
    "edit_roles": false
  }'::jsonb);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
