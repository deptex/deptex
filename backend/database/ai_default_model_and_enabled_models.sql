-- Adds per-org AI model selection on top of provider selection.
--
-- `default_model` -- the specific model Aegis should use for this org. NULL
-- means "use DEFAULT_MODELS[default_ai_provider]" (backwards-compat).
--
-- `enabled_models` -- which models are available to pick in the org settings
-- model picker. NULL means "all models for the configured provider are
-- enabled" (backwards-compat). Stored as a JSONB array of model id strings,
-- e.g. ["claude-sonnet-4-6", "gpt-4o", "gemini-2.5-flash"].

ALTER TABLE organizations
  ADD COLUMN IF NOT EXISTS default_model TEXT,
  ADD COLUMN IF NOT EXISTS enabled_models JSONB;

COMMENT ON COLUMN organizations.default_model IS
  'Specific AI model Aegis uses for this org. NULL falls back to DEFAULT_MODELS[default_ai_provider].';

COMMENT ON COLUMN organizations.enabled_models IS
  'JSONB array of model ids enabled in the org AI model picker. NULL means all models are enabled.';
