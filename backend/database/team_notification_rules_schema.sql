-- Team Notification Rules (EE)
-- Team-scoped notification rules; mirrors project_notification_rules / organization_notification_rules

CREATE TABLE IF NOT EXISTS team_notification_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  trigger_type TEXT NOT NULL CHECK (trigger_type IN ('weekly_digest', 'vulnerability_discovered', 'custom_code_pipeline')),
  min_depscore_threshold INTEGER,
  custom_code TEXT,
  destinations JSONB NOT NULL DEFAULT '[]',
  active BOOLEAN NOT NULL DEFAULT true,
  created_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  created_by_name TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE team_notification_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view team notification rules"
  ON team_notification_rules FOR SELECT
  USING (
    team_id IN (
      SELECT tm.team_id FROM team_members tm
      WHERE tm.user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can create team notification rules"
  ON team_notification_rules FOR INSERT
  WITH CHECK (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can update team notification rules"
  ON team_notification_rules FOR UPDATE
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can delete team notification rules"
  ON team_notification_rules FOR DELETE
  USING (
    team_id IN (
      SELECT t.id FROM teams t
      JOIN organization_members om ON om.organization_id = t.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
  );

CREATE INDEX IF NOT EXISTS idx_team_notification_rules_team_id
  ON team_notification_rules(team_id);

CREATE OR REPLACE FUNCTION update_team_notification_rules_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_team_notification_rules_updated_at ON team_notification_rules;
CREATE TRIGGER update_team_notification_rules_updated_at
  BEFORE UPDATE ON team_notification_rules
  FOR EACH ROW
  EXECUTE FUNCTION update_team_notification_rules_updated_at();
