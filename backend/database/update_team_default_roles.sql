-- ===========================================
-- Update Team Default Roles
-- Changes default team roles from "owner/member" to "admin/member"
-- Admin gets all permissions, member gets none
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
    "edit_roles": true
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
    "edit_roles": false
  }'::jsonb);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Step 2: Remove the auto-add team creator trigger
-- Team creators should NOT be automatically added as team members
-- They have org-level access and can add themselves manually if needed
DROP TRIGGER IF EXISTS add_team_creator_trigger ON teams;
DROP FUNCTION IF EXISTS add_team_creator_as_owner();

-- Step 3: Update RLS policies to check for 'admin' instead of 'owner'
-- (Or check for both during transition)

-- Update policy for creating team roles
DROP POLICY IF EXISTS "Admins can create team roles" ON team_roles;
CREATE POLICY "Admins can create team roles"
  ON team_roles FOR INSERT
  WITH CHECK (
    -- User is org admin/owner
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    -- User is team admin (changed from owner)
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      JOIN team_roles tr ON tr.id = tm.role_id
      WHERE tm.user_id = auth.uid()
      AND tr.name IN ('owner', 'admin')
    )
  );

-- Update policy for updating team roles
DROP POLICY IF EXISTS "Admins can update team roles" ON team_roles;
CREATE POLICY "Admins can update team roles"
  ON team_roles FOR UPDATE
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      JOIN team_roles tr ON tr.id = tm.role_id
      WHERE tm.user_id = auth.uid()
      AND tr.name IN ('owner', 'admin')
    )
  );

-- Update policy for deleting team roles
DROP POLICY IF EXISTS "Admins can delete team roles" ON team_roles;
CREATE POLICY "Admins can delete team roles"
  ON team_roles FOR DELETE
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      JOIN team_roles tr ON tr.id = tm.role_id
      WHERE tm.user_id = auth.uid()
      AND tr.name IN ('owner', 'admin')
    )
  );

-- Step 4: Migrate existing teams - rename 'owner' role to 'admin' and update permissions
UPDATE team_roles 
SET 
  name = 'admin',
  display_name = 'Admin',
  permissions = '{
    "view_overview": true,
    "resolve_alerts": true,
    "manage_projects": true,
    "view_settings": true,
    "view_members": true,
    "add_members": true,
    "kick_members": true,
    "view_roles": true,
    "edit_roles": true
  }'::jsonb
WHERE name = 'owner';

-- Step 5: Update existing member roles to have minimal permissions (can always view overview)
UPDATE team_roles 
SET 
  permissions = '{
    "view_overview": true,
    "resolve_alerts": false,
    "manage_projects": false,
    "view_settings": false,
    "view_members": false,
    "add_members": false,
    "kick_members": false,
    "view_roles": false,
    "edit_roles": false
  }'::jsonb
WHERE name = 'member';
