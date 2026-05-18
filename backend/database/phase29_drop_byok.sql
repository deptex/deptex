-- Phase 29: Drop BYOK (Bring Your Own Key) infrastructure.
-- All AI calls now route through the platform key path
-- (getPlatformProvider() / getPlatformKeyForProvider() backed by
-- OPENAI_API_KEY / ANTHROPIC_API_KEY / GOOGLE_AI_API_KEY).
--
-- The encryption helpers in backend/src/lib/ai/encryption.ts are kept
-- because they're shared with organization_registry_credentials (IaC v2
-- Phase 1). AI_ENCRYPTION_KEY env var stays.
--
-- ai_usage_logs.tier CHECK is left as-is (still allows 'platform' | 'byok')
-- so historical rows tagged 'byok' (e.g. taint_engine_anthropic_fallback)
-- remain queryable. New writes only emit 'platform'.

DROP TABLE IF EXISTS organization_ai_providers CASCADE;
