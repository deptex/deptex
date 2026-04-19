-- PR Guardrails table for project-level merge blocking rules
CREATE TABLE project_pr_guardrails (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE UNIQUE,
  -- Vulnerability blocking
  block_critical_vulns BOOLEAN DEFAULT false,
  block_high_vulns BOOLEAN DEFAULT false,
  block_medium_vulns BOOLEAN DEFAULT false,
  block_low_vulns BOOLEAN DEFAULT false,
  vulns_only_if_reachable BOOLEAN DEFAULT false,
  -- Package score blocking
  score_check_enabled BOOLEAN DEFAULT false,
  min_package_score INTEGER DEFAULT 50 CHECK (min_package_score >= 0 AND min_package_score <= 100),
  -- Unmaintained package blocking
  unmaintained_check_enabled BOOLEAN DEFAULT false,
  unmaintained_threshold_days INTEGER DEFAULT 365,
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Enable Row Level Security
ALTER TABLE project_pr_guardrails ENABLE ROW LEVEL SECURITY;

-- RLS Policies for project_pr_guardrails
-- Users can view guardrails for projects in their organizations
CREATE POLICY "Users can view guardrails for projects in their orgs"
  ON project_pr_guardrails FOR SELECT
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      WHERE p.organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
      )
    )
  );

-- Users can insert guardrails for projects in their organizations (admins/owners)
CREATE POLICY "Admins can create guardrails"
  ON project_pr_guardrails FOR INSERT
  WITH CHECK (
    project_id IN (
      SELECT p.id FROM projects p
      WHERE p.organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
        AND role IN ('owner', 'admin')
      )
    )
  );

-- Users can update guardrails for projects in their organizations (admins/owners)
CREATE POLICY "Admins can update guardrails"
  ON project_pr_guardrails FOR UPDATE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      WHERE p.organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
        AND role IN ('owner', 'admin')
      )
    )
  );

-- Users can delete guardrails for projects in their organizations (admins/owners)
CREATE POLICY "Admins can delete guardrails"
  ON project_pr_guardrails FOR DELETE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      WHERE p.organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
        AND role IN ('owner', 'admin')
      )
    )
  );

-- Create index for better query performance
CREATE INDEX idx_project_pr_guardrails_project_id ON project_pr_guardrails(project_id);

-- Function to update the updated_at timestamp
CREATE OR REPLACE FUNCTION update_pr_guardrails_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-update updated_at
CREATE TRIGGER trigger_update_pr_guardrails_updated_at
  BEFORE UPDATE ON project_pr_guardrails
  FOR EACH ROW
  EXECUTE FUNCTION update_pr_guardrails_updated_at();
