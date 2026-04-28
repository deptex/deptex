-- ai_usage_logs and aegis_tool_executions were defined in
-- phase6c_aegis_infrastructure.sql and phase7b_aegis_platform.sql but
-- never applied to this DB. Token logging from Aegis chat has been
-- silently failing (the writers are wrapped in try/catch); the new
-- AI page surfaces the missing tables explicitly.

CREATE TABLE IF NOT EXISTS ai_usage_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL,
  feature TEXT NOT NULL,
  tier TEXT NOT NULL CHECK (tier IN ('platform', 'byok')),
  provider TEXT NOT NULL,
  model TEXT NOT NULL,
  input_tokens INTEGER NOT NULL,
  output_tokens INTEGER NOT NULL,
  estimated_cost NUMERIC(10, 8),
  context_type TEXT,
  context_id TEXT,
  duration_ms INTEGER,
  success BOOLEAN DEFAULT true,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_aul_org_created ON ai_usage_logs(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aul_user_feature ON ai_usage_logs(user_id, feature, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aul_org_month ON ai_usage_logs(organization_id, created_at) WHERE success = true;

CREATE TABLE IF NOT EXISTS aegis_tool_executions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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

CREATE INDEX IF NOT EXISTS idx_aegis_tool_exec_org ON aegis_tool_executions(organization_id);
CREATE INDEX IF NOT EXISTS idx_aegis_tool_exec_user ON aegis_tool_executions(user_id);
CREATE INDEX IF NOT EXISTS idx_aegis_tool_exec_thread ON aegis_tool_executions(thread_id);
CREATE INDEX IF NOT EXISTS idx_aegis_tool_exec_created ON aegis_tool_executions(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_aegis_tool_exec_tool ON aegis_tool_executions(tool_name);
