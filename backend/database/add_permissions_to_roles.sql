-- Migration: Add permissions and display_name to organization_roles
-- This migration adds permissions support and display names for roles,
-- and initializes default roles (owner, admin, member) for all existing organizations

-- Add permissions column (JSONB to store role permissions)
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'organization_roles' AND column_name = 'permissions'
  ) THEN
    ALTER TABLE organization_roles ADD COLUMN permissions JSONB DEFAULT '{}'::jsonb;
  END IF;
END $$;

-- Add display_name column for editable role display names
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'organization_roles' AND column_name = 'display_name'
  ) THEN
    ALTER TABLE organization_roles ADD COLUMN display_name TEXT;
  END IF;
END $$;

-- Initialize default roles for all existing organizations
-- Owner: all permissions true
-- Admin: all permissions true
-- Member: all permissions false
DO $$
DECLARE
  org_record RECORD;
  owner_permissions JSONB;
  admin_permissions JSONB;
  member_permissions JSONB;
BEGIN
  -- Define default permissions
  owner_permissions := '{
    "view_settings": true,
    "view_activity": true,
    "edit_policies": true,
    "interact_with_security_agent": true,
    "view_members": true,
    "add_members": true,
    "edit_roles": true,
    "edit_permissions": true,
    "kick_members": true,
    "view_all_teams": true,
    "view_all_projects": true,
    "view_overview": true,
    "can_create_teams": true
  }'::jsonb;

  member_permissions := '{
    "view_settings": false,
    "view_activity": false,
    "edit_policies": false,
    "interact_with_security_agent": false,
    "view_members": false,
    "add_members": false,
    "edit_roles": false,
    "edit_permissions": false,
    "kick_members": false,
    "view_all_teams": false,
    "view_all_projects": false,
    "view_overview": false,
    "can_create_teams": false
  }'::jsonb;

  -- Loop through all organizations
  FOR org_record IN SELECT id FROM organizations
  LOOP
    -- Insert owner role if it doesn't exist
    INSERT INTO organization_roles (organization_id, name, display_name, is_default, display_order, permissions)
    SELECT org_record.id, 'owner', 'Owner', true, 0, owner_permissions
    WHERE NOT EXISTS (
      SELECT 1 FROM organization_roles 
      WHERE organization_id = org_record.id AND name = 'owner'
    );

    -- Insert member role if it doesn't exist
    INSERT INTO organization_roles (organization_id, name, display_name, is_default, display_order, permissions)
    SELECT org_record.id, 'member', 'Member', true, 1, member_permissions
    WHERE NOT EXISTS (
      SELECT 1 FROM organization_roles 
      WHERE organization_id = org_record.id AND name = 'member'
    );
  END LOOP;
END $$;

