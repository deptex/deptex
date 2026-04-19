-- Add manage_integrations permission to organization_roles table
-- This migration adds a new boolean column for managing integrations

-- Step 1: Add the manage_integrations column to organization_roles table
ALTER TABLE organization_roles
ADD COLUMN IF NOT EXISTS manage_integrations BOOLEAN DEFAULT false;

-- Step 2: Update existing 'owner' roles to have manage_integrations = true
UPDATE organization_roles
SET manage_integrations = true
WHERE name = 'owner';

-- Step 3: Update existing 'member' roles to have manage_integrations = true
UPDATE organization_roles
SET manage_integrations = true
WHERE name = 'member';

-- Verify the changes
-- SELECT organization_id, name, manage_integrations FROM organization_roles ORDER BY organization_id, display_order;
