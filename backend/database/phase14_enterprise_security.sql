-- Phase 14: Enterprise Security
-- Prerequisite migrations: schema.sql, organization_roles_schema.sql, add_permissions_to_roles.sql,
--   add_manage_security_permission.sql
-- Run this migration to add MFA enforcement, SSO/SAML, session management,
-- IP allowlisting, API tokens, security audit logging, and SCIM provisioning tables.

-- ============================================================
-- 14A: Security Audit Log
-- ============================================================

CREATE TABLE IF NOT EXISTS security_audit_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  actor_id UUID REFERENCES auth.users(id),
  action TEXT NOT NULL,
  target_type TEXT,
  target_id TEXT,
  ip_address TEXT,
  user_agent TEXT,
  metadata JSONB DEFAULT '{}',
  severity TEXT DEFAULT 'info',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sal_org_created ON security_audit_logs(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sal_action ON security_audit_logs(organization_id, action);
CREATE INDEX IF NOT EXISTS idx_sal_actor ON security_audit_logs(actor_id);

-- ============================================================
-- 14B: MFA Enforcement
-- ============================================================

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'mfa_enforced') THEN
    ALTER TABLE organizations ADD COLUMN mfa_enforced BOOLEAN DEFAULT false;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'mfa_grace_period_days') THEN
    ALTER TABLE organizations ADD COLUMN mfa_grace_period_days INTEGER DEFAULT 7;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'mfa_enforcement_started_at') THEN
    ALTER TABLE organizations ADD COLUMN mfa_enforcement_started_at TIMESTAMPTZ;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS organization_mfa_exemptions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  exempted_by UUID NOT NULL REFERENCES auth.users(id),
  reason TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, user_id)
);

-- ============================================================
-- 14C: Session Management
-- ============================================================

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'max_session_duration_hours') THEN
    ALTER TABLE organizations ADD COLUMN max_session_duration_hours INTEGER DEFAULT 168;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'require_reauth_for_sensitive') THEN
    ALTER TABLE organizations ADD COLUMN require_reauth_for_sensitive BOOLEAN DEFAULT false;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS user_sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  session_id TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  device_info JSONB,
  last_active_at TIMESTAMPTZ DEFAULT NOW(),
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(session_id)
);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON user_sessions(last_active_at DESC);

-- ============================================================
-- 14D: SSO via SAML
-- ============================================================

CREATE TABLE IF NOT EXISTS organization_sso_providers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  provider_type TEXT NOT NULL,
  display_name TEXT,
  metadata_url TEXT,
  metadata_xml TEXT,
  entity_id TEXT NOT NULL,
  sso_url TEXT NOT NULL,
  certificate TEXT NOT NULL,
  domain TEXT NOT NULL,
  domain_verified BOOLEAN DEFAULT false,
  domain_verification_token TEXT,
  enforce_sso BOOLEAN DEFAULT false,
  allow_oauth_fallback BOOLEAN DEFAULT true,
  default_role_id UUID REFERENCES organization_roles(id),
  group_role_mapping JSONB DEFAULT '{}',
  jit_provisioning BOOLEAN DEFAULT true,
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id),
  UNIQUE(domain)
);

CREATE TABLE IF NOT EXISTS organization_sso_bypass_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL,
  created_by UUID NOT NULL REFERENCES auth.users(id),
  used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_sso_bypass_org ON organization_sso_bypass_tokens(organization_id)
  WHERE used_at IS NULL;

-- ============================================================
-- 14E: IP Allowlisting
-- ============================================================

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'organizations' AND column_name = 'ip_allowlist_enabled') THEN
    ALTER TABLE organizations ADD COLUMN ip_allowlist_enabled BOOLEAN DEFAULT false;
  END IF;
END $$;

CREATE TABLE IF NOT EXISTS organization_ip_allowlist (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cidr TEXT NOT NULL,
  label TEXT,
  created_by UUID NOT NULL REFERENCES auth.users(id),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_allowlist_org ON organization_ip_allowlist(organization_id);

-- ============================================================
-- 14F: API Tokens
-- ============================================================

CREATE TABLE IF NOT EXISTS api_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  token_prefix TEXT NOT NULL,
  token_hash TEXT NOT NULL,
  scopes JSONB DEFAULT '["read"]',
  last_used_at TIMESTAMPTZ,
  last_used_ip TEXT,
  expires_at TIMESTAMPTZ,
  revoked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(token_hash)
);

CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_tokens_org ON api_tokens(organization_id) WHERE revoked_at IS NULL;

-- ============================================================
-- 14G: SCIM Provisioning
-- ============================================================

CREATE TABLE IF NOT EXISTS organization_scim_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scim_token_hash TEXT NOT NULL,
  scim_token_prefix TEXT NOT NULL,
  is_active BOOLEAN DEFAULT true,
  last_sync_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id)
);

CREATE TABLE IF NOT EXISTS scim_user_mappings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  scim_external_id TEXT NOT NULL,
  user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  email TEXT NOT NULL,
  display_name TEXT,
  is_active BOOLEAN DEFAULT true,
  provisioned_at TIMESTAMPTZ DEFAULT NOW(),
  deprovisioned_at TIMESTAMPTZ,
  UNIQUE(organization_id, scim_external_id)
);

CREATE INDEX IF NOT EXISTS idx_scim_mappings_org ON scim_user_mappings(organization_id);

-- ============================================================
-- 14I: Permission Model Fix
-- manage_security should NOT be on member role
-- ============================================================

UPDATE organization_roles
SET permissions = jsonb_set(permissions, '{manage_security}', 'false'::jsonb)
WHERE name = 'member'
  AND permissions IS NOT NULL
  AND (permissions->>'manage_security')::boolean = true;

-- ============================================================
-- Row Level Security
-- ============================================================

ALTER TABLE security_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_mfa_exemptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_sso_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_sso_bypass_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_ip_allowlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_scim_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE scim_user_mappings ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on security_audit_logs" ON security_audit_logs
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on organization_mfa_exemptions" ON organization_mfa_exemptions
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on user_sessions" ON user_sessions
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on organization_sso_providers" ON organization_sso_providers
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on organization_sso_bypass_tokens" ON organization_sso_bypass_tokens
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on organization_ip_allowlist" ON organization_ip_allowlist
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on api_tokens" ON api_tokens
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on organization_scim_configs" ON organization_scim_configs
  FOR ALL USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on scim_user_mappings" ON scim_user_mappings
  FOR ALL USING (true) WITH CHECK (true);
