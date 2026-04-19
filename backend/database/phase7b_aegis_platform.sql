-- Phase 7B: Aegis Autonomous Security Platform
-- 10 new tables + ALTER existing tables
--
-- RUN THESE FIRST (in order):
--   1. aegis_chat_threads_schema.sql    (creates aegis_chat_threads)
--   2. aegis_chat_messages_schema.sql   (creates aegis_chat_messages; requires aegis_chat_threads)
--   3. aegis_automations_schema.sql     (creates aegis_automations; required for aegis_event_triggers)
--   4. phase6c_ai_infrastructure.sql    (organization_ai_providers, ai_usage_logs; alters aegis_chat_threads)
-- Then run this file: phase7b_aegis_platform.sql

-- Enable pgvector extension for memory embeddings
CREATE EXTENSION IF NOT EXISTS vector;

-- ============================================================
-- 1. aegis_org_settings - Per-org Aegis configuration
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_org_settings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  operating_mode TEXT NOT NULL DEFAULT 'propose',
  role_mode_overrides JSONB DEFAULT '{}',
  monthly_budget NUMERIC(10, 2),
  daily_budget NUMERIC(10, 2),
  per_task_budget NUMERIC(10, 2) DEFAULT 25.00,
  alert_thresholds JSONB DEFAULT '[50, 80, 100]',
  tool_permissions JSONB DEFAULT '{}',
  default_delivery_channel TEXT,
  preferred_provider TEXT,
  preferred_model TEXT,
  pr_review_mode TEXT DEFAULT 'advisory',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_org_settings_org ON aegis_org_settings(organization_id);

-- ============================================================
-- 2. aegis_tool_executions - Audit trail for all tool calls
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_tool_executions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  thread_id UUID REFERENCES aegis_chat_threads(id),
  task_id UUID,
  tool_name TEXT NOT NULL,
  tool_category TEXT NOT NULL,
  parameters JSONB NOT NULL,
  result JSONB,
  success BOOLEAN,
  permission_level TEXT NOT NULL,
  approval_status TEXT,
  duration_ms INTEGER,
  tokens_used INTEGER,
  estimated_cost NUMERIC(8, 4),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_tool_exec_org ON aegis_tool_executions(organization_id);
CREATE INDEX idx_aegis_tool_exec_user ON aegis_tool_executions(user_id);
CREATE INDEX idx_aegis_tool_exec_thread ON aegis_tool_executions(thread_id);
CREATE INDEX idx_aegis_tool_exec_created ON aegis_tool_executions(created_at DESC);
CREATE INDEX idx_aegis_tool_exec_tool ON aegis_tool_executions(tool_name);

-- ============================================================
-- 3. aegis_approval_requests - Approval workflow for dangerous tools
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_approval_requests (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  requested_by UUID NOT NULL REFERENCES auth.users(id),
  thread_id UUID REFERENCES aegis_chat_threads(id),
  task_id UUID,
  task_step_id UUID,
  tool_name TEXT NOT NULL,
  parameters JSONB NOT NULL,
  justification TEXT,
  status TEXT NOT NULL DEFAULT 'pending',
  reviewed_by UUID REFERENCES auth.users(id),
  reviewed_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '24 hours'),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_approvals_org ON aegis_approval_requests(organization_id);
CREATE INDEX idx_aegis_approvals_status ON aegis_approval_requests(status) WHERE status = 'pending';

-- ============================================================
-- 4. aegis_tasks - Long-running background work
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_tasks (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id),
  thread_id UUID REFERENCES aegis_chat_threads(id),
  title TEXT NOT NULL,
  description TEXT,
  mode TEXT NOT NULL DEFAULT 'plan',
  status TEXT NOT NULL DEFAULT 'planning',
  plan_json JSONB,
  total_steps INTEGER DEFAULT 0,
  completed_steps INTEGER DEFAULT 0,
  failed_steps INTEGER DEFAULT 0,
  total_cost NUMERIC(8, 4) DEFAULT 0,
  summary TEXT,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_tasks_org ON aegis_tasks(organization_id);
CREATE INDEX idx_aegis_tasks_status ON aegis_tasks(status);
CREATE INDEX idx_aegis_tasks_user ON aegis_tasks(user_id);

-- ============================================================
-- 5. aegis_task_steps - Individual steps within a task
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_task_steps (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  task_id UUID NOT NULL REFERENCES aegis_tasks(id) ON DELETE CASCADE,
  step_number INTEGER NOT NULL,
  title TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  tool_params JSONB NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  result_json JSONB,
  error_message TEXT,
  cost NUMERIC(8, 4) DEFAULT 0,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_task_steps_task ON aegis_task_steps(task_id);
CREATE INDEX idx_aegis_task_steps_status ON aegis_task_steps(status);

-- ============================================================
-- 6. aegis_memory - pgvector-backed organizational memory
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_memory (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  category TEXT NOT NULL,
  key TEXT NOT NULL,
  content TEXT NOT NULL,
  embedding vector(768),
  source_thread_id UUID REFERENCES aegis_chat_threads(id),
  created_by UUID REFERENCES auth.users(id),
  metadata JSONB DEFAULT '{}',
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_memory_org ON aegis_memory(organization_id);
CREATE INDEX idx_aegis_memory_category ON aegis_memory(organization_id, category);
CREATE INDEX ON aegis_memory USING hnsw (embedding vector_cosine_ops);

-- ============================================================
-- 7. aegis_event_triggers - Event-driven automation triggers
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_event_triggers (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  automation_id UUID NOT NULL REFERENCES aegis_automations(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  filter_criteria JSONB,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_aegis_event_triggers_org ON aegis_event_triggers(organization_id);
CREATE INDEX idx_aegis_event_triggers_event ON aegis_event_triggers(event_type) WHERE enabled = TRUE;

-- ============================================================
-- 8. aegis_slack_config - Per-org Slack bot configuration
-- ============================================================
CREATE TABLE IF NOT EXISTS aegis_slack_config (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL UNIQUE REFERENCES organizations(id) ON DELETE CASCADE,
  slack_team_id TEXT,
  slack_bot_token TEXT NOT NULL,
  slack_signing_secret TEXT NOT NULL,
  encryption_key_version INTEGER DEFAULT 1,
  default_channel_id TEXT,
  enabled BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- ============================================================
-- 9. security_debt_snapshots - Daily security debt tracking
-- ============================================================
CREATE TABLE IF NOT EXISTS security_debt_snapshots (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  score NUMERIC(10, 2) NOT NULL,
  breakdown JSONB NOT NULL,
  snapshot_date DATE NOT NULL DEFAULT CURRENT_DATE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, project_id, snapshot_date)
);

CREATE INDEX idx_debt_snapshots_org_date ON security_debt_snapshots(organization_id, snapshot_date DESC);
CREATE INDEX idx_debt_snapshots_project ON security_debt_snapshots(project_id, snapshot_date DESC);

-- ============================================================
-- 10. package_reputation_scores - Composite reputation scores
-- ============================================================
CREATE TABLE IF NOT EXISTS package_reputation_scores (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  score NUMERIC(5, 2) NOT NULL,
  breakdown JSONB NOT NULL,
  signals_available INTEGER NOT NULL DEFAULT 0,
  calculated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(dependency_id)
);

CREATE INDEX idx_reputation_scores_dep ON package_reputation_scores(dependency_id);
CREATE INDEX idx_reputation_scores_score ON package_reputation_scores(score);

-- ============================================================
-- ALTER existing tables
-- ============================================================

-- Slack config: slack_team_id for multi-workspace lookup, encryption_key_version for token decryption
ALTER TABLE aegis_slack_config
  ADD COLUMN IF NOT EXISTS slack_team_id TEXT,
  ADD COLUMN IF NOT EXISTS encryption_key_version INTEGER DEFAULT 1;

-- Expand aegis_automations with cron, delivery, template support (only if table exists)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'aegis_automations') THEN
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS cron_expression TEXT;
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS timezone TEXT DEFAULT 'UTC';
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS automation_type TEXT DEFAULT 'custom';
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS delivery_config JSONB DEFAULT '{}';
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS template_config JSONB DEFAULT '{}';
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS qstash_schedule_id TEXT;
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS last_run_status TEXT;
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS last_run_output TEXT;
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS last_run_at TIMESTAMPTZ;
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS run_count INTEGER DEFAULT 0;
    ALTER TABLE aegis_automations ADD COLUMN IF NOT EXISTS consecutive_failures INTEGER DEFAULT 0;
  END IF;
END $$;

-- Add metadata to aegis_chat_messages for tool execution refs (only if table exists)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'aegis_chat_messages') THEN
    ALTER TABLE aegis_chat_messages ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';
  END IF;
END $$;

-- ============================================================
-- Permission migration: interact_with_security_agent -> interact_with_aegis
-- ============================================================
UPDATE organization_roles
SET permissions = jsonb_set(
  permissions - 'interact_with_security_agent',
  '{interact_with_aegis}',
  COALESCE(permissions->'interact_with_security_agent', 'true'::jsonb)
)
WHERE permissions ? 'interact_with_security_agent';

-- Add new permissions to all existing owner roles
UPDATE organization_roles
SET permissions = permissions
  || '{"trigger_fix": true, "view_ai_spending": true, "manage_incidents": true}'::jsonb
WHERE name = 'owner' OR (permissions->>'manage_aegis')::boolean = true;

-- Add trigger_fix and view_ai_spending to admin roles
UPDATE organization_roles
SET permissions = permissions
  || '{"trigger_fix": true, "view_ai_spending": true}'::jsonb
WHERE name = 'admin';

-- ============================================================
-- RLS Policies
-- ============================================================
ALTER TABLE aegis_org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_tool_executions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_task_steps ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_event_triggers ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_slack_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_debt_snapshots ENABLE ROW LEVEL SECURITY;
ALTER TABLE package_reputation_scores ENABLE ROW LEVEL SECURITY;

-- Service role bypass for all new tables
CREATE POLICY "Service role full access" ON aegis_org_settings FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_tool_executions FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_approval_requests FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_tasks FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_task_steps FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_memory FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_event_triggers FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON aegis_slack_config FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON security_debt_snapshots FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON package_reputation_scores FOR ALL USING (true) WITH CHECK (true);
