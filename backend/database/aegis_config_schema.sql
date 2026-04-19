-- Aegis configuration table
CREATE TABLE IF NOT EXISTS aegis_config (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  enabled BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE aegis_config ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_config
-- Users can view config for organizations they are members of
CREATE POLICY "Users can view aegis config for their orgs"
  ON aegis_config FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Users can create config for organizations they are admins/owners of
CREATE POLICY "Admins can create aegis config"
  ON aegis_config FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Users can update config for organizations they are admins/owners of
CREATE POLICY "Admins can update aegis config"
  ON aegis_config FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Create index for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_config_organization_id ON aegis_config(organization_id);

