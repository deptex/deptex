-- Project Integrations Table (EE)
-- Project-scoped integrations for notifications and ticketing (Slack, Discord, Jira, etc.)
-- Organization integrations are inherited; these are project-specific overrides/additions

CREATE TABLE IF NOT EXISTS project_integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  provider TEXT NOT NULL,
  installation_id TEXT,
  access_token TEXT,
  refresh_token TEXT,
  webhook_secret TEXT,
  metadata JSONB DEFAULT '{}',
  display_name TEXT,
  status TEXT DEFAULT 'connected',
  connected_at TIMESTAMPTZ DEFAULT NOW(),
  last_sync_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- RLS
ALTER TABLE project_integrations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view project integrations for projects they can access"
  ON project_integrations FOR SELECT
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Authorized users can insert project integrations"
  ON project_integrations FOR INSERT
  WITH CHECK (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Authorized users can update project integrations"
  ON project_integrations FOR UPDATE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Authorized users can delete project integrations"
  ON project_integrations FOR DELETE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE INDEX IF NOT EXISTS idx_project_integrations_project_id ON project_integrations(project_id);
CREATE INDEX IF NOT EXISTS idx_project_integrations_provider ON project_integrations(provider);
CREATE INDEX IF NOT EXISTS idx_project_integrations_status ON project_integrations(status);

CREATE OR REPLACE FUNCTION update_project_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS project_integrations_updated_at ON project_integrations;
CREATE TRIGGER project_integrations_updated_at
  BEFORE UPDATE ON project_integrations
  FOR EACH ROW
  EXECUTE FUNCTION update_project_integrations_updated_at();
