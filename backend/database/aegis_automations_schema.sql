-- Aegis automations table
CREATE TABLE IF NOT EXISTS aegis_automations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT,
  schedule TEXT NOT NULL,
  enabled BOOLEAN DEFAULT true,
  last_run_at TIMESTAMPTZ,
  next_run_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE aegis_automations ENABLE ROW LEVEL SECURITY;

-- RLS Policies for aegis_automations
-- Users can view automations for organizations they are members of
CREATE POLICY "Users can view aegis automations for their orgs"
  ON aegis_automations FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Users can create automations for organizations they are admins/owners of
CREATE POLICY "Admins can create aegis automations"
  ON aegis_automations FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Users can update automations for organizations they are admins/owners of
CREATE POLICY "Admins can update aegis automations"
  ON aegis_automations FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Users can delete automations for organizations they are admins/owners of
CREATE POLICY "Admins can delete aegis automations"
  ON aegis_automations FOR DELETE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_aegis_automations_organization_id ON aegis_automations(organization_id);
CREATE INDEX IF NOT EXISTS idx_aegis_automations_enabled ON aegis_automations(enabled);
CREATE INDEX IF NOT EXISTS idx_aegis_automations_next_run_at ON aegis_automations(next_run_at) WHERE enabled = true;

