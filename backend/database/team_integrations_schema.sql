-- Team Integrations Table (EE)
-- Team-scoped integrations for notifications and ticketing (Slack, Discord, Jira, etc.)
-- Organization integrations are inherited; these are team-specific additions

CREATE TABLE IF NOT EXISTS team_integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
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

ALTER TABLE team_integrations ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view team integrations for teams they belong to"
  ON team_integrations FOR SELECT
  USING (
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid()
    )
  );

CREATE POLICY "Authorized users can insert team integrations"
  ON team_integrations FOR INSERT
  WITH CHECK (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Authorized users can update team integrations"
  ON team_integrations FOR UPDATE
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Authorized users can delete team integrations"
  ON team_integrations FOR DELETE
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE INDEX IF NOT EXISTS idx_team_integrations_team_id ON team_integrations(team_id);
CREATE INDEX IF NOT EXISTS idx_team_integrations_provider ON team_integrations(provider);
CREATE INDEX IF NOT EXISTS idx_team_integrations_status ON team_integrations(status);

CREATE OR REPLACE FUNCTION update_team_integrations_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS team_integrations_updated_at ON team_integrations;
CREATE TRIGGER team_integrations_updated_at
  BEFORE UPDATE ON team_integrations
  FOR EACH ROW
  EXECUTE FUNCTION update_team_integrations_updated_at();
