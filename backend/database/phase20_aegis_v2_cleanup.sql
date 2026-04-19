-- Phase 20: Aegis v2 cleanup.
-- Drops every Aegis v1 table and helper except aegis_chat_threads + aegis_chat_messages,
-- which the v2 rebuild will reuse as-is. Safe to run multiple times (IF EXISTS on every drop).

-- Chat surface (v1): automations, activity, inbox, config — all replaced by v2's lean chat flow.
DROP TABLE IF EXISTS aegis_activity_logs CASCADE;
DROP TABLE IF EXISTS aegis_automation_jobs CASCADE;
DROP TABLE IF EXISTS aegis_automations CASCADE;
DROP TABLE IF EXISTS aegis_config CASCADE;
DROP TABLE IF EXISTS aegis_inbox CASCADE;
DROP TABLE IF EXISTS aegis_org_settings CASCADE;

-- Task/approval engine (v1): plan-then-execute with QStash step execution. Out of scope for v2.
DROP TABLE IF EXISTS aegis_tool_executions CASCADE;
DROP TABLE IF EXISTS aegis_approval_requests CASCADE;
DROP TABLE IF EXISTS aegis_task_steps CASCADE;
DROP TABLE IF EXISTS aegis_tasks CASCADE;

-- Memory / pgvector: v2 MVP is stateless per-thread.
DROP TABLE IF EXISTS aegis_memory_embeddings CASCADE;
DROP TABLE IF EXISTS aegis_memory CASCADE;

-- Incident response (Phase 17): out of scope for v2 MVP.
DROP TABLE IF EXISTS aegis_incident_notes CASCADE;
DROP TABLE IF EXISTS aegis_incident_timeline CASCADE;
DROP TABLE IF EXISTS aegis_incidents CASCADE;
DROP TABLE IF EXISTS incident_timeline CASCADE;
DROP TABLE IF EXISTS incident_notes CASCADE;
DROP TABLE IF EXISTS incident_playbooks CASCADE;
DROP TABLE IF EXISTS security_incidents CASCADE;

-- Aider / AI fix pipeline (Phase 7): out of scope for v2 MVP (chat-only).
DROP TABLE IF EXISTS ai_fix_artifacts CASCADE;
DROP TABLE IF EXISTS ai_fix_jobs CASCADE;

-- Learning system (Phase 16): fix_outcomes + strategy_patterns.
DROP TABLE IF EXISTS fix_outcomes CASCADE;
DROP TABLE IF EXISTS strategy_patterns CASCADE;

-- Usage logs + BYOK: MVP uses the platform Gemini key, no BYOK, no per-call logging.
DROP TABLE IF EXISTS ai_usage_logs CASCADE;
DROP TABLE IF EXISTS organization_ai_providers CASCADE;

-- Helpers defined alongside the dropped tables.
DROP FUNCTION IF EXISTS compute_strategy_patterns() CASCADE;
DROP FUNCTION IF EXISTS query_aegis_memory(uuid, text, int) CASCADE;
