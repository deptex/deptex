-- Organization Notification Rules (EE)
-- Stores rules that define when and where to send notifications (vulnerability alerts, digests, custom pipelines)
CREATE TABLE IF NOT EXISTS organization_notification_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
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

-- destinations format: [{"integrationType": "slack"|"jira"|"linear"|"asana"|"email", "targetId": "..."}, ...]

-- Enable Row Level Security
ALTER TABLE organization_notification_rules ENABLE ROW LEVEL SECURITY;

-- RLS Policies
CREATE POLICY "Users can view notification rules for their orgs"
  ON organization_notification_rules FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can create notification rules"
  ON organization_notification_rules FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can update notification rules"
  ON organization_notification_rules FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Admins can delete notification rules"
  ON organization_notification_rules FOR DELETE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
      AND role IN ('owner', 'admin')
    )
  );

CREATE INDEX IF NOT EXISTS idx_organization_notification_rules_org_id
  ON organization_notification_rules(organization_id);

-- Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_organization_notification_rules_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS update_organization_notification_rules_updated_at ON organization_notification_rules;
CREATE TRIGGER update_organization_notification_rules_updated_at
  BEFORE UPDATE ON organization_notification_rules
  FOR EACH ROW
  EXECUTE FUNCTION update_organization_notification_rules_updated_at();
