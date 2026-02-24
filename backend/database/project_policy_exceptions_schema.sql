-- Project Policy Exceptions table
-- Stores exception requests from projects for additional licenses or different SLSA requirements
CREATE TABLE IF NOT EXISTS project_policy_exceptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  requested_by UUID NOT NULL,
  status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  reason TEXT NOT NULL,
  additional_licenses TEXT[] DEFAULT '{}',
  slsa_enforcement TEXT CHECK (slsa_enforcement IS NULL OR slsa_enforcement IN ('none', 'recommended', 'require_provenance', 'require_attestations', 'require_signed')),
  slsa_level INTEGER CHECK (slsa_level IS NULL OR (slsa_level >= 1 AND slsa_level <= 4)),
  reviewed_by UUID,
  reviewed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE project_policy_exceptions ENABLE ROW LEVEL SECURITY;

-- RLS Policies for project_policy_exceptions
-- Users can view exceptions for organizations they are members of
CREATE POLICY "Users can view exceptions for their orgs"
  ON project_policy_exceptions FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Users can create exception requests for projects in their organizations
CREATE POLICY "Members can create exception requests"
  ON project_policy_exceptions FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only admins and owners can update exceptions (accept/reject)
CREATE POLICY "Admins can update exceptions"
  ON project_policy_exceptions FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Only admins and owners can delete exceptions
CREATE POLICY "Admins can delete exceptions"
  ON project_policy_exceptions FOR DELETE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_project_policy_exceptions_project_id ON project_policy_exceptions(project_id);
CREATE INDEX IF NOT EXISTS idx_project_policy_exceptions_org_id ON project_policy_exceptions(organization_id);
CREATE INDEX IF NOT EXISTS idx_project_policy_exceptions_status ON project_policy_exceptions(status);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_project_policy_exceptions_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to automatically update updated_at
DROP TRIGGER IF EXISTS update_project_policy_exceptions_updated_at ON project_policy_exceptions;
CREATE TRIGGER update_project_policy_exceptions_updated_at
  BEFORE UPDATE ON project_policy_exceptions
  FOR EACH ROW
  EXECUTE FUNCTION update_project_policy_exceptions_updated_at();
