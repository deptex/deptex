-- Organization Custom Roles Table
-- This allows organizations to define custom role names beyond the default owner/admin/member
CREATE TABLE IF NOT EXISTS organization_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  is_default BOOLEAN DEFAULT false, -- true for built-in roles (owner, admin, member)
  display_order INTEGER DEFAULT 0, -- Order in which roles appear
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, name)
);

-- Create default roles for existing organizations (owner, admin, member are built-in and don't need to be stored)
-- But we'll allow custom roles to be added

-- Enable Row Level Security
ALTER TABLE organization_roles ENABLE ROW LEVEL SECURITY;

-- RLS Policies for organization_roles
-- Users can view roles for organizations they are members of
CREATE POLICY "Users can view roles for their orgs"
  ON organization_roles FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only owners and admins can create custom roles
CREATE POLICY "Admins can create custom roles"
  ON organization_roles FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Only owners and admins can update custom roles
CREATE POLICY "Admins can update custom roles"
  ON organization_roles FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Only owners and admins can delete custom roles
CREATE POLICY "Admins can delete custom roles"
  ON organization_roles FOR DELETE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_organization_roles_org_id ON organization_roles(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_roles_display_order ON organization_roles(organization_id, display_order);

-- Add avatar_url column to organizations table if it doesn't exist
DO $$ 
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns 
    WHERE table_name = 'organizations' AND column_name = 'avatar_url'
  ) THEN
    ALTER TABLE organizations ADD COLUMN avatar_url TEXT;
  END IF;
END $$;

