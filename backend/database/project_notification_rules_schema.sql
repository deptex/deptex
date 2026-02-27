-- Project Notification Rules (EE)
-- Project-scoped notification rules; mirrors organization_notification_rules

CREATE TABLE IF NOT EXISTS project_notification_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
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

ALTER TABLE project_notification_rules ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view project notification rules"
  ON project_notification_rules FOR SELECT
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can create project notification rules"
  ON project_notification_rules FOR INSERT
  WITH CHECK (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can update project notification rules"
  ON project_notification_rules FOR UPDATE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can delete project notification rules"
  ON project_notification_rules FOR DELETE
  USING (
    project_id IN (
      SELECT p.id FROM projects p
      JOIN organization_members om ON om.organization_id = p.organization_id
      WHERE om.user_id = auth.uid()
      AND om.role IN ('owner', 'admin')
    )
  );

CREATE INDEX IF NOT EXISTS idx_project_notification_rules_project_id
  ON project_notification_rules(project_id);

CREATE OR REPLACE FUNCTION update_project_notification_rules_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_project_notification_rules_updated_at ON project_notification_rules;
CREATE TRIGGER update_project_notification_rules_updated_at
  BEFORE UPDATE ON project_notification_rules
  FOR EACH ROW
  EXECUTE FUNCTION update_project_notification_rules_updated_at();
