-- Phase 9: Notifications & Integrations
-- Run in order. All tables use service_role for writes, RLS for reads.

-- 9N.0: Prerequisites
ALTER TABLE organization_integrations ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
ALTER TABLE team_integrations ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;
ALTER TABLE project_integrations ADD COLUMN IF NOT EXISTS token_expires_at TIMESTAMPTZ;

ALTER TABLE organizations ADD COLUMN IF NOT EXISTS timezone TEXT DEFAULT 'UTC';
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS notifications_paused_until TIMESTAMPTZ;

ALTER TABLE organization_notification_rules ADD COLUMN IF NOT EXISTS schedule_config JSONB;
ALTER TABLE team_notification_rules ADD COLUMN IF NOT EXISTS schedule_config JSONB;
ALTER TABLE project_notification_rules ADD COLUMN IF NOT EXISTS schedule_config JSONB;

ALTER TABLE organization_notification_rules ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;
ALTER TABLE team_notification_rules ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;
ALTER TABLE project_notification_rules ADD COLUMN IF NOT EXISTS snoozed_until TIMESTAMPTZ;

ALTER TABLE organization_notification_rules ADD COLUMN IF NOT EXISTS dry_run BOOLEAN DEFAULT false;
ALTER TABLE team_notification_rules ADD COLUMN IF NOT EXISTS dry_run BOOLEAN DEFAULT false;
ALTER TABLE project_notification_rules ADD COLUMN IF NOT EXISTS dry_run BOOLEAN DEFAULT false;

ALTER TABLE organization_integrations ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER DEFAULT 0;
ALTER TABLE organization_integrations ADD COLUMN IF NOT EXISTS last_failure_at TIMESTAMPTZ;

-- 9B: Event persistence
CREATE TABLE IF NOT EXISTS notification_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_type TEXT NOT NULL,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  team_id UUID REFERENCES teams(id) ON DELETE SET NULL,
  payload JSONB NOT NULL DEFAULT '{}',
  source TEXT NOT NULL,
  priority TEXT NOT NULL DEFAULT 'normal'
    CHECK (priority IN ('critical', 'high', 'normal', 'low')),
  batch_id UUID,
  deduplication_key TEXT,
  dispatch_attempts INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'dispatching', 'dispatched', 'failed')),
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notif_events_org ON notification_events(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_events_project ON notification_events(project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_events_batch ON notification_events(batch_id) WHERE batch_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notif_events_status ON notification_events(status) WHERE status = 'pending';
CREATE UNIQUE INDEX IF NOT EXISTS idx_notif_events_dedup_unique
  ON notification_events(deduplication_key)
  WHERE deduplication_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notif_events_dedup ON notification_events(deduplication_key, created_at DESC)
  WHERE deduplication_key IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_notif_events_stuck ON notification_events(created_at, dispatch_attempts)
  WHERE status = 'pending';

-- 9J: Delivery tracking
CREATE TABLE IF NOT EXISTS notification_deliveries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID NOT NULL REFERENCES notification_events(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  rule_id UUID NOT NULL,
  rule_scope TEXT NOT NULL CHECK (rule_scope IN ('organization', 'team', 'project')),
  rule_name TEXT,
  destination_type TEXT NOT NULL,
  destination_id UUID NOT NULL,
  destination_name TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN ('pending', 'sending', 'delivered', 'failed', 'rate_limited', 'skipped', 'dry_run')),
  is_test BOOLEAN NOT NULL DEFAULT false,
  message_title TEXT,
  message_body TEXT,
  message_payload JSONB,
  response JSONB,
  external_id TEXT,
  error_message TEXT,
  attempts INTEGER DEFAULT 0,
  last_attempt_at TIMESTAMPTZ,
  delivered_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_notif_deliveries_event ON notification_deliveries(event_id);
CREATE INDEX IF NOT EXISTS idx_notif_deliveries_org_time ON notification_deliveries(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_notif_deliveries_status ON notification_deliveries(status)
  WHERE status IN ('pending', 'failed');

-- 9R: User notification preferences
CREATE TABLE IF NOT EXISTS user_notification_preferences (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  email_opted_out BOOLEAN NOT NULL DEFAULT false,
  muted_event_types TEXT[] DEFAULT '{}',
  muted_project_ids UUID[] DEFAULT '{}',
  dnd_start_hour INTEGER,
  dnd_end_hour INTEGER,
  digest_preference TEXT DEFAULT 'instant'
    CHECK (digest_preference IN ('instant', 'daily_digest', 'weekly_digest', 'off')),
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now(),
  UNIQUE(user_id, organization_id)
);

-- 9S: In-app notification inbox
CREATE TABLE IF NOT EXISTS user_notifications (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  event_id UUID REFERENCES notification_events(id) ON DELETE SET NULL,
  title TEXT NOT NULL,
  body TEXT,
  severity TEXT DEFAULT 'info',
  event_type TEXT,
  project_id UUID REFERENCES projects(id) ON DELETE SET NULL,
  deptex_url TEXT,
  read_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_user_notifs_user ON user_notifications(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_notifs_unread ON user_notifications(user_id, read_at)
  WHERE read_at IS NULL;

-- 9U: Notification rule change history
CREATE TABLE IF NOT EXISTS notification_rule_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  rule_id UUID NOT NULL,
  rule_scope TEXT NOT NULL CHECK (rule_scope IN ('organization', 'team', 'project')),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  previous_code TEXT,
  new_code TEXT,
  previous_destinations JSONB,
  new_destinations JSONB,
  changed_by_user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  changed_by_name TEXT,
  message TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rule_changes_rule ON notification_rule_changes(rule_id, created_at DESC);

-- Migrate existing vulnerability_discovered rules to custom_code_pipeline
UPDATE organization_notification_rules
  SET trigger_type = 'custom_code_pipeline',
      custom_code = COALESCE(custom_code,
        'if (context.event.type !== ''vulnerability_discovered'') return false;' || chr(10) ||
        'if (!context.vulnerability) return false;' || chr(10) ||
        'return true;')
  WHERE trigger_type = 'vulnerability_discovered';

UPDATE team_notification_rules
  SET trigger_type = 'custom_code_pipeline',
      custom_code = COALESCE(custom_code,
        'if (context.event.type !== ''vulnerability_discovered'') return false;' || chr(10) ||
        'if (!context.vulnerability) return false;' || chr(10) ||
        'return true;')
  WHERE trigger_type = 'vulnerability_discovered';

UPDATE project_notification_rules
  SET trigger_type = 'custom_code_pipeline',
      custom_code = COALESCE(custom_code,
        'if (context.event.type !== ''vulnerability_discovered'') return false;' || chr(10) ||
        'if (!context.vulnerability) return false;' || chr(10) ||
        'return true;')
  WHERE trigger_type = 'vulnerability_discovered';

-- Update CHECK constraints to 2-value enum
ALTER TABLE organization_notification_rules DROP CONSTRAINT IF EXISTS organization_notification_rules_trigger_type_check;
ALTER TABLE organization_notification_rules ADD CONSTRAINT organization_notification_rules_trigger_type_check
  CHECK (trigger_type IN ('weekly_digest', 'custom_code_pipeline'));

ALTER TABLE team_notification_rules DROP CONSTRAINT IF EXISTS team_notification_rules_trigger_type_check;
ALTER TABLE team_notification_rules ADD CONSTRAINT team_notification_rules_trigger_type_check
  CHECK (trigger_type IN ('weekly_digest', 'custom_code_pipeline'));

ALTER TABLE project_notification_rules DROP CONSTRAINT IF EXISTS project_notification_rules_trigger_type_check;
ALTER TABLE project_notification_rules ADD CONSTRAINT project_notification_rules_trigger_type_check
  CHECK (trigger_type IN ('weekly_digest', 'custom_code_pipeline'));

-- RLS policies
ALTER TABLE notification_events ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Org members can view their org notification events"
  ON notification_events FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Service role full access to notification events"
  ON notification_events FOR ALL
  USING (auth.role() = 'service_role');

ALTER TABLE notification_deliveries ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Org admins can view their org notification deliveries"
  ON notification_deliveries FOR SELECT
  USING (
    organization_id IN (
      SELECT om.organization_id FROM organization_members om
      WHERE om.user_id = auth.uid()
        AND om.role IN ('owner', 'admin')
    )
  );

CREATE POLICY "Service role full access to notification deliveries"
  ON notification_deliveries FOR ALL
  USING (auth.role() = 'service_role');

ALTER TABLE user_notification_preferences ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage their own preferences"
  ON user_notification_preferences FOR ALL
  USING (user_id = auth.uid());

CREATE POLICY "Service role full access to notification preferences"
  ON user_notification_preferences FOR ALL
  USING (auth.role() = 'service_role');

ALTER TABLE user_notifications ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view their own notifications"
  ON user_notifications FOR SELECT
  USING (user_id = auth.uid());

CREATE POLICY "Users can update their own notifications"
  ON user_notifications FOR UPDATE
  USING (user_id = auth.uid());

CREATE POLICY "Service role full access to user notifications"
  ON user_notifications FOR ALL
  USING (auth.role() = 'service_role');
