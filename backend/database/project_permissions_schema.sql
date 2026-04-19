-- ===========================================
-- Project Permissions Schema
-- This file creates project roles and members tables with proper ordering
-- Run this INSTEAD of project_roles_schema.sql and project_members_schema.sql
-- ===========================================

-- Step 1: Create project_roles table (without RLS policies that reference project_members)
CREATE TABLE IF NOT EXISTS project_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  display_name TEXT,
  is_default BOOLEAN DEFAULT false,
  display_order INTEGER DEFAULT 0,
  permissions JSONB DEFAULT '{
    "view_overview": true,
    "view_dependencies": true,
    "view_watchlist": true,
    "view_members": false,
    "manage_members": false,
    "view_settings": false,
    "edit_settings": false
  }'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, name)
);

-- Enable RLS on project_roles
ALTER TABLE project_roles ENABLE ROW LEVEL SECURITY;

-- Basic RLS policy for project_roles (doesn't reference project_members)
CREATE POLICY "Users can view project roles"
  ON project_roles FOR SELECT
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

-- Indexes for project_roles
CREATE INDEX IF NOT EXISTS idx_project_roles_project_id ON project_roles(project_id);
CREATE INDEX IF NOT EXISTS idx_project_roles_display_order ON project_roles(project_id, display_order);

-- Step 2: Create project_members table (now project_roles exists)
CREATE TABLE IF NOT EXISTS project_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role_id UUID NOT NULL REFERENCES project_roles(id) ON DELETE RESTRICT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, user_id)
);

-- Enable RLS on project_members
ALTER TABLE project_members ENABLE ROW LEVEL SECURITY;

-- RLS Policies for project_members
CREATE POLICY "Users can view project members"
  ON project_members FOR SELECT
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Users with manage_members can add members"
  ON project_members FOR INSERT
  WITH CHECK (
    -- User is org admin/owner
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    -- User has manage_members permission on this project
    project_id IN (
      SELECT pm.project_id FROM project_members pm
      JOIN project_roles pr ON pr.id = pm.role_id
      WHERE pm.user_id = auth.uid()
      AND (pr.permissions->>'manage_members')::boolean = true
    )
  );

CREATE POLICY "Users with manage_members can update members"
  ON project_members FOR UPDATE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    project_id IN (
      SELECT pm.project_id FROM project_members pm
      JOIN project_roles pr ON pr.id = pm.role_id
      WHERE pm.user_id = auth.uid()
      AND (pr.permissions->>'manage_members')::boolean = true
    )
  );

CREATE POLICY "Users with manage_members can remove members"
  ON project_members FOR DELETE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    project_id IN (
      SELECT pm.project_id FROM project_members pm
      JOIN project_roles pr ON pr.id = pm.role_id
      WHERE pm.user_id = auth.uid()
      AND (pr.permissions->>'manage_members')::boolean = true
    )
  );

-- Indexes for project_members
CREATE INDEX IF NOT EXISTS idx_project_members_project_id ON project_members(project_id);
CREATE INDEX IF NOT EXISTS idx_project_members_user_id ON project_members(user_id);
CREATE INDEX IF NOT EXISTS idx_project_members_role_id ON project_members(role_id);

-- Step 3: Now add the remaining RLS policies for project_roles (that reference project_members)
CREATE POLICY "Project owners can create roles"
  ON project_roles FOR INSERT
  WITH CHECK (
    -- User is org admin/owner
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    -- User is project owner
    project_id IN (
      SELECT pm.project_id FROM project_members pm
      JOIN project_roles pr ON pr.id = pm.role_id
      WHERE pm.user_id = auth.uid()
      AND pr.name = 'owner'
    )
  );

CREATE POLICY "Project owners can update roles"
  ON project_roles FOR UPDATE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    project_id IN (
      SELECT pm.project_id FROM project_members pm
      JOIN project_roles pr ON pr.id = pm.role_id
      WHERE pm.user_id = auth.uid()
      AND pr.name = 'owner'
    )
  );

CREATE POLICY "Project owners can delete roles"
  ON project_roles FOR DELETE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
    OR
    project_id IN (
      SELECT pm.project_id FROM project_members pm
      JOIN project_roles pr ON pr.id = pm.role_id
      WHERE pm.user_id = auth.uid()
      AND pr.name = 'owner'
    )
  );

-- Step 4: Create function to auto-create default project roles
CREATE OR REPLACE FUNCTION create_default_project_roles()
RETURNS TRIGGER AS $$
BEGIN
  -- Create owner role with all permissions
  INSERT INTO project_roles (project_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'owner', 'Owner', true, 0, '{
    "view_overview": true,
    "view_dependencies": true,
    "view_watchlist": true,
    "view_members": true,
    "manage_members": true,
    "view_settings": true,
    "edit_settings": true
  }'::jsonb);
  
  -- Create editor role
  INSERT INTO project_roles (project_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'editor', 'Editor', true, 1, '{
    "view_overview": true,
    "view_dependencies": true,
    "view_watchlist": true,
    "view_members": true,
    "manage_members": false,
    "view_settings": true,
    "edit_settings": false
  }'::jsonb);
  
  -- Create viewer role
  INSERT INTO project_roles (project_id, name, display_name, is_default, display_order, permissions)
  VALUES (NEW.id, 'viewer', 'Viewer', true, 2, '{
    "view_overview": true,
    "view_dependencies": true,
    "view_watchlist": true,
    "view_members": false,
    "manage_members": false,
    "view_settings": false,
    "edit_settings": false
  }'::jsonb);
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to auto-create default roles when a project is created
DROP TRIGGER IF EXISTS create_project_roles_trigger ON projects;
CREATE TRIGGER create_project_roles_trigger
  AFTER INSERT ON projects
  FOR EACH ROW
  EXECUTE FUNCTION create_default_project_roles();

-- Step 5: Create function to add project creator as owner
CREATE OR REPLACE FUNCTION add_project_creator_as_owner()
RETURNS TRIGGER AS $$
DECLARE
  owner_role_id UUID;
  creator_id UUID;
BEGIN
  -- Get the owner role for this project
  SELECT id INTO owner_role_id FROM project_roles 
  WHERE project_id = NEW.id AND name = 'owner';
  
  -- Get the user who created the project (current authenticated user)
  creator_id := auth.uid();
  
  -- Add the creator as project owner if we have both IDs
  IF owner_role_id IS NOT NULL AND creator_id IS NOT NULL THEN
    INSERT INTO project_members (project_id, user_id, role_id)
    VALUES (NEW.id, creator_id, owner_role_id)
    ON CONFLICT (project_id, user_id) DO NOTHING;
  END IF;
  
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- Trigger to auto-add creator as owner (runs after roles are created)
DROP TRIGGER IF EXISTS add_project_creator_trigger ON projects;
CREATE TRIGGER add_project_creator_trigger
  AFTER INSERT ON projects
  FOR EACH ROW
  EXECUTE FUNCTION add_project_creator_as_owner();
