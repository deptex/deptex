-- Custom AI provider: allow provider = 'custom' with display_name and api_base_url.
-- Multiple custom providers per org; built-in providers remain one per org (openai, anthropic, google).

-- Add columns for custom provider
ALTER TABLE organization_ai_providers ADD COLUMN IF NOT EXISTS display_name TEXT;
ALTER TABLE organization_ai_providers ADD COLUMN IF NOT EXISTS api_base_url TEXT;

-- Allow 'custom' in provider check
ALTER TABLE organization_ai_providers DROP CONSTRAINT IF EXISTS organization_ai_providers_provider_check;
ALTER TABLE organization_ai_providers ADD CONSTRAINT organization_ai_providers_provider_check
  CHECK (provider IN ('openai', 'anthropic', 'google', 'custom'));

-- Replace global unique with partial unique: only one row per (org, provider) for built-in providers
ALTER TABLE organization_ai_providers DROP CONSTRAINT IF EXISTS organization_ai_providers_organization_id_provider_key;
CREATE UNIQUE INDEX IF NOT EXISTS idx_oap_org_provider_builtin
  ON organization_ai_providers(organization_id, provider)
  WHERE provider IN ('openai', 'anthropic', 'google');
