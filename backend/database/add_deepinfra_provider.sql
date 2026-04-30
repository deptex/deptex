-- Allow 'deepinfra' as an AI provider option. DeepInfra hosts open-weight
-- models (Qwen, DeepSeek, Llama) at low per-token pricing and exposes an
-- OpenAI-API-compatible endpoint, so the existing OpenAI provider path
-- carries it with just a custom baseURL.

ALTER TABLE organizations DROP CONSTRAINT IF EXISTS organizations_default_ai_provider_check;
ALTER TABLE organizations ADD CONSTRAINT organizations_default_ai_provider_check
  CHECK (default_ai_provider IN ('openai', 'anthropic', 'google', 'deepinfra'));
