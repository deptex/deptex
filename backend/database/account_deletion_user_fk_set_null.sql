-- Fix account deletion: all FKs to auth.users that had no ON DELETE clause
-- defaulted to RESTRICT, which blocked auth.admin.deleteUser entirely.
-- Attribution/audit columns become NULL when the user is deleted; records survive.
-- Columns that were NOT NULL are also relaxed since a deleted user is a valid
-- null attribution (same semantics as "unknown author").

BEGIN;

-- ── 1. Nullable columns: drop + re-add FK with ON DELETE SET NULL ─────────────

ALTER TABLE public.aegis_chat_messages
  DROP CONSTRAINT aegis_chat_messages_user_id_fkey,
  ADD CONSTRAINT aegis_chat_messages_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.organization_deprecations
  DROP CONSTRAINT organization_deprecations_deprecated_by_fkey,
  ADD CONSTRAINT organization_deprecations_deprecated_by_fkey
    FOREIGN KEY (deprecated_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.organization_reachability_settings
  DROP CONSTRAINT organization_reachability_settings_updated_by_fkey,
  ADD CONSTRAINT organization_reachability_settings_updated_by_fkey
    FOREIGN KEY (updated_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.project_dast_findings
  DROP CONSTRAINT project_dast_findings_risk_accepted_by_fkey,
  ADD CONSTRAINT project_dast_findings_risk_accepted_by_fkey
    FOREIGN KEY (risk_accepted_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.project_malicious_findings
  DROP CONSTRAINT project_malicious_findings_risk_accepted_by_fkey,
  ADD CONSTRAINT project_malicious_findings_risk_accepted_by_fkey
    FOREIGN KEY (risk_accepted_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.project_malicious_findings
  DROP CONSTRAINT project_malicious_findings_suppressed_by_fkey,
  ADD CONSTRAINT project_malicious_findings_suppressed_by_fkey
    FOREIGN KEY (suppressed_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.project_security_fixes
  DROP CONSTRAINT project_security_fixes_approved_by_user_id_fkey,
  ADD CONSTRAINT project_security_fixes_approved_by_user_id_fkey
    FOREIGN KEY (approved_by_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.project_security_fixes
  DROP CONSTRAINT project_security_fixes_rejected_by_user_id_fkey,
  ADD CONSTRAINT project_security_fixes_rejected_by_user_id_fkey
    FOREIGN KEY (rejected_by_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.security_audit_logs
  DROP CONSTRAINT security_audit_logs_actor_id_fkey,
  ADD CONSTRAINT security_audit_logs_actor_id_fkey
    FOREIGN KEY (actor_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.taint_engine_framework_models
  DROP CONSTRAINT taint_engine_framework_models_edited_by_user_id_fkey,
  ADD CONSTRAINT taint_engine_framework_models_edited_by_user_id_fkey
    FOREIGN KEY (edited_by_user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.team_deprecations
  DROP CONSTRAINT team_deprecations_deprecated_by_fkey,
  ADD CONSTRAINT team_deprecations_deprecated_by_fkey
    FOREIGN KEY (deprecated_by) REFERENCES auth.users(id) ON DELETE SET NULL;

-- ── 2. NOT NULL columns: drop constraint, relax nullability, re-add FK ────────

ALTER TABLE public.aegis_chat_invite_codes
  ALTER COLUMN created_by DROP NOT NULL,
  DROP CONSTRAINT aegis_chat_invite_codes_created_by_fkey,
  ADD CONSTRAINT aegis_chat_invite_codes_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.aegis_chat_threads
  ALTER COLUMN created_by DROP NOT NULL,
  DROP CONSTRAINT aegis_chat_threads_created_by_fkey,
  ADD CONSTRAINT aegis_chat_threads_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.aegis_tool_executions
  ALTER COLUMN user_id DROP NOT NULL,
  DROP CONSTRAINT aegis_tool_executions_user_id_fkey,
  ADD CONSTRAINT aegis_tool_executions_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.organization_ip_allowlist
  ALTER COLUMN created_by DROP NOT NULL,
  DROP CONSTRAINT organization_ip_allowlist_created_by_fkey,
  ADD CONSTRAINT organization_ip_allowlist_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.organization_mfa_exemptions
  ALTER COLUMN exempted_by DROP NOT NULL,
  DROP CONSTRAINT organization_mfa_exemptions_exempted_by_fkey,
  ADD CONSTRAINT organization_mfa_exemptions_exempted_by_fkey
    FOREIGN KEY (exempted_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.organization_sso_bypass_tokens
  ALTER COLUMN created_by DROP NOT NULL,
  DROP CONSTRAINT organization_sso_bypass_tokens_created_by_fkey,
  ADD CONSTRAINT organization_sso_bypass_tokens_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES auth.users(id) ON DELETE SET NULL;

ALTER TABLE public.project_security_fixes
  ALTER COLUMN triggered_by DROP NOT NULL,
  DROP CONSTRAINT project_security_fixes_triggered_by_fkey,
  ADD CONSTRAINT project_security_fixes_triggered_by_fkey
    FOREIGN KEY (triggered_by) REFERENCES auth.users(id) ON DELETE SET NULL;

COMMIT;
