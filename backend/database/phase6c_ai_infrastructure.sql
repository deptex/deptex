-- Phase 6C: AI Infrastructure and Aegis Security Copilot
-- organization_ai_providers, ai_usage_logs, aegis_chat_threads additions, projects vuln check columns, permission migration
--
-- Prerequisite: aegis_chat_threads must exist (run aegis_chat_threads_schema.sql first).
-- If it doesn't exist, the aegis_chat_threads ALTER block is skipped; run it again after creating the table.

-- BYOK AI provider configuration per organization
CREATE TABLE IF NOT EXISTS organization_ai_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider TEXT NOT NULL CHECK (provider IN ('openai', 'anthropic', 'google')),
  encrypted_api_key TEXT NOT NULL,
  encryption_key_version INTEGER DEFAULT 1,
  model_preference TEXT,
  is_default BOOLEAN DEFAULT false,
  monthly_cost_cap NUMERIC(8, 2) DEFAULT 100.00,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_oap_org ON organization_ai_providers(organization_id);

-- AI usage logging for cost tracking and audit
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

-- Aegis chat threads: add project context and token tracking
-- (Only runs if aegis_chat_threads exists; run aegis_chat_threads_schema.sql first if it doesn't)
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = 'aegis_chat_threads') THEN
    ALTER TABLE aegis_chat_threads ADD COLUMN IF NOT EXISTS project_id UUID REFERENCES projects(id) ON DELETE SET NULL;
    ALTER TABLE aegis_chat_threads ADD COLUMN IF NOT EXISTS context_type TEXT;
    ALTER TABLE aegis_chat_threads ADD COLUMN IF NOT EXISTS context_id TEXT;
    ALTER TABLE aegis_chat_threads ADD COLUMN IF NOT EXISTS total_tokens_used INTEGER DEFAULT 0;
  END IF;
END $$;

-- Projects: background vulnerability monitoring columns
ALTER TABLE projects ADD COLUMN IF NOT EXISTS last_vuln_check_at TIMESTAMPTZ;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS vuln_check_frequency TEXT DEFAULT '24h';

-- Permission migration: grant interact_with_security_agent to existing Owner/Admin roles
UPDATE organization_roles
SET permissions = permissions || '{"interact_with_security_agent": true}'::jsonb
WHERE name IN ('owner', 'admin')
  AND NOT (permissions ? 'interact_with_security_agent');
