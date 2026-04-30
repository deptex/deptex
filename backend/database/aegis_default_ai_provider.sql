-- Adds platform-default AI provider selection to organizations.
-- Each org picks one of openai/anthropic/google; the backend resolves
-- to a Deptex-paid API key via OPENAI_API_KEY / ANTHROPIC_API_KEY /
-- GOOGLE_AI_API_KEY env vars. BYOK on organization_ai_providers stays
-- available as a future override.

ALTER TABLE organizations
  ADD COLUMN default_ai_provider TEXT NOT NULL DEFAULT 'anthropic'
    CHECK (default_ai_provider IN ('openai', 'anthropic', 'google'));

COMMENT ON COLUMN organizations.default_ai_provider IS
  'Platform-default AI provider for Aegis and other AI features. Resolves to a Deptex-paid API key via env vars (OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_AI_API_KEY).';
