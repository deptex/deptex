-- Organization Policies table (policy as code)
-- Stores policy as a single code blob per organization
CREATE TABLE IF NOT EXISTS organization_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  policy_code TEXT DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id)
);

-- Enable Row Level Security
ALTER TABLE organization_policies ENABLE ROW LEVEL SECURITY;

-- RLS Policies for organization_policies
-- Users can view policies for organizations they are members of
CREATE POLICY "Users can view policies for their orgs"
  ON organization_policies FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only admins and owners can create/update policies
CREATE POLICY "Admins can create policies"
  ON organization_policies FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can update policies"
  ON organization_policies FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Create index for better query performance
CREATE INDEX IF NOT EXISTS idx_organization_policies_org_id ON organization_policies(organization_id);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_organization_policies_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
CREATE TRIGGER update_organization_policies_updated_at
  BEFORE UPDATE ON organization_policies
  FOR EACH ROW
  EXECUTE FUNCTION update_organization_policies_updated_at();
