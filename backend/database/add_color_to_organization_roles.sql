-- Add color column to organization_roles
ALTER TABLE organization_roles ADD COLUMN IF NOT EXISTS color TEXT;
