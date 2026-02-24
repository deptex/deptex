-- ===========================================
-- Team Roles Schema
-- This file creates team roles and updates team_members with role support
-- ===========================================

-- Step 1: Add avatar_url column to teams table if it doesn't exist
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'teams' AND column_name = 'avatar_url'
  ) THEN
    ALTER TABLE teams ADD COLUMN avatar_url TEXT;
  END IF;
END $$;

-- Step 2: Create team_roles table (without RLS policies that reference team_members.role_id)
CREATE TABLE IF NOT EXISTS team_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  display_name TEXT,
  is_default BOOLEAN DEFAULT false,
  display_order INTEGER DEFAULT 0,
  permissions JSONB DEFAULT '{
    "view_overview": true,
    "manage_projects": false,
    "manage_members": false,
    "view_settings": false,
    "view_alerts": true
  }'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(team_id, name)
);

-- Enable RLS on team_roles
ALTER TABLE team_roles ENABLE ROW LEVEL SECURITY;

-- Basic RLS policy for team_roles - users can view roles for teams in their organizations
-- (This policy doesn't reference team_members.role_id)
DROP POLICY IF EXISTS "Users can view team roles" ON team_roles;
CREATE POLICY "Users can view team roles"
  ON team_roles FOR SELECT
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

-- Indexes for team_roles
CREATE INDEX IF NOT EXISTS idx_team_roles_team_id ON team_roles(team_id);
CREATE INDEX IF NOT EXISTS idx_team_roles_display_order ON team_roles(team_id, display_order);

-- Step 3: Add role_id column to team_members if it doesn't exist
-- (Must be done BEFORE creating policies that reference it)
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'team_members' AND column_name = 'role_id'
  ) THEN
    ALTER TABLE team_members ADD COLUMN role_id UUID REFERENCES team_roles(id) ON DELETE SET NULL;
  END IF;
END $$;

-- Index for team_members role_id
CREATE INDEX IF NOT EXISTS idx_team_members_role_id ON team_members(role_id);

-- Step 4: Now create the RLS policies that reference team_members.role_id
-- Only org admins/owners or team owners can create roles
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
    -- User is team owner
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      JOIN team_roles tr ON tr.id = tm.role_id
      WHERE tm.user_id = auth.uid()
      AND tr.name = 'owner'
    )
  );

-- Only org admins/owners or team owners can update roles
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
      AND tr.name = 'owner'
    )
  );

-- Only org admins/owners or team owners can delete roles
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
      AND tr.name = 'owner'
    )
  );

-- Step 5: Create function to auto-create default team roles
CREATE OR REPLACE FUNCTION create_default_team_roles()
RETURNS TRIGGER AS $$
BEGIN
  -- Create owner role with all permissions
  INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'owner', 'Owner', true, 0, '{
    "view_overview": true,
    "manage_projects": true,
    "manage_members": true,
    "view_settings": true,
    "view_alerts": true
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

-- Trigger to auto-create default roles when a team is created
DROP TRIGGER IF EXISTS create_team_roles_trigger ON teams;
CREATE TRIGGER create_team_roles_trigger
  AFTER INSERT ON teams
  FOR EACH ROW
  EXECUTE FUNCTION create_default_team_roles();

-- Step 6: Create function to add team creator as owner
CREATE OR REPLACE FUNCTION add_team_creator_as_owner()
RETURNS TRIGGER AS $$
DECLARE
  owner_role_id UUID;
  creator_id UUID;
BEGIN
  -- Get the owner role for this team
  SELECT id INTO owner_role_id FROM team_roles 
  WHERE team_id = NEW.id AND name = 'owner';
  
  -- Get the user who created the team (current authenticated user)
  creator_id := auth.uid();
  
  -- Add the creator as team owner if we have both IDs
  IF owner_role_id IS NOT NULL AND creator_id IS NOT NULL THEN
    -- Check if the user is already a member (from invitation or other means)
    UPDATE team_members 
    SET role_id = owner_role_id
    WHERE team_id = NEW.id AND user_id = creator_id;
    
    -- If no row was updated, insert a new membership
    IF NOT FOUND THEN
      INSERT INTO team_members (team_id, user_id, role_id)
      VALUES (NEW.id, creator_id, owner_role_id)
      ON CONFLICT (team_id, user_id) DO UPDATE SET role_id = owner_role_id;
    END IF;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to auto-add creator as owner (runs after roles are created)
DROP TRIGGER IF EXISTS add_team_creator_trigger ON teams;
CREATE TRIGGER add_team_creator_trigger
  AFTER INSERT ON teams
  FOR EACH ROW
  EXECUTE FUNCTION add_team_creator_as_owner();

-- Step 7: Create default roles for existing teams that don't have roles
DO $$
DECLARE
  team_record RECORD;
  owner_role_id UUID;
  member_role_id UUID;
BEGIN
  FOR team_record IN SELECT id FROM teams WHERE id NOT IN (SELECT DISTINCT team_id FROM team_roles) LOOP
    -- Create owner role
    INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
    VALUES (team_record.id, 'owner', 'Owner', true, 0, '{
      "view_overview": true,
      "manage_projects": true,
      "manage_members": true,
      "view_settings": true,
      "view_alerts": true
    }'::jsonb)
    RETURNING id INTO owner_role_id;
    
    -- Create member role with minimal permissions (can always view overview)
    INSERT INTO team_roles (team_id, name, display_name, is_default, display_order, permissions)
    VALUES (team_record.id, 'member', 'Member', true, 1, '{
      "view_overview": true,
      "resolve_alerts": false,
      "manage_projects": false,
      "view_settings": false,
      "view_members": false,
      "add_members": false,
      "kick_members": false,
      "view_roles": false,
      "edit_roles": false
    }'::jsonb)
    RETURNING id INTO member_role_id;
    
    -- Assign member role to existing team members without a role
    UPDATE team_members 
    SET role_id = member_role_id
    WHERE team_id = team_record.id AND role_id IS NULL;
  END LOOP;
END $$;
