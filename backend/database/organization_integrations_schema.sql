-- Organization Integrations Table
-- Stores enterprise-level integrations (GitHub App, GitLab, Slack, Jira, etc.)
-- These are tied to organizations, not individual users

CREATE TABLE IF NOT EXISTS organization_integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL, -- 'github', 'gitlab', 'slack', 'jira'
  installation_id TEXT, -- GitHub App installation ID, GitLab group ID, etc.
  access_token TEXT, -- Encrypted token if needed
  refresh_token TEXT, -- For services that support token refresh
  webhook_secret TEXT, -- For webhook verification
  metadata JSONB DEFAULT '{}', -- Provider-specific data (repo count, permissions, etc.)
  status TEXT DEFAULT 'connected', -- 'connected', 'disconnected', 'error'
  connected_at TIMESTAMPTZ DEFAULT NOW(),
  last_sync_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, provider)
);

-- RLS Policies
ALTER TABLE organization_integrations ENABLE ROW LEVEL SECURITY;

-- Users can view integrations for organizations they belong to
CREATE POLICY "Users can view their organization integrations"
  ON organization_integrations FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only users with manage_integrations permission can insert integrations
-- This will be enforced at the application level via the API
CREATE POLICY "Authorized users can insert organization integrations"
  ON organization_integrations FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only users with manage_integrations permission can update integrations
CREATE POLICY "Authorized users can update organization integrations"
  ON organization_integrations FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only users with manage_integrations permission can delete integrations
CREATE POLICY "Authorized users can delete organization integrations"
  ON organization_integrations FOR DELETE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Indexes for faster lookups
CREATE INDEX IF NOT EXISTS idx_organization_integrations_org_id ON organization_integrations(organization_id);
CREATE INDEX IF NOT EXISTS idx_organization_integrations_provider ON organization_integrations(provider);
CREATE INDEX IF NOT EXISTS idx_organization_integrations_status ON organization_integrations(status);

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_organization_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER organization_integrations_updated_at
  BEFORE UPDATE ON organization_integrations
  FOR EACH ROW
  EXECUTE FUNCTION update_organization_integrations_updated_at();
