-- Add github_installation_id column to organizations table
-- This provides quick access to GitHub App installation ID without joining tables
-- The organization_integrations table stores the full integration details

ALTER TABLE organizations
ADD COLUMN IF NOT EXISTS github_installation_id TEXT;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_organizations_github_installation_id 
  ON organizations(github_installation_id) 
  WHERE github_installation_id IS NOT NULL;

-- Add comment for documentation
COMMENT ON COLUMN organizations.github_installation_id IS 
  'GitHub App installation ID for this organization. Provides quick access to check if GitHub is connected.';
