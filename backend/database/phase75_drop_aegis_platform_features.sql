-- Phase 75: Drop the retired Aegis platform-feature tables.
--
-- The open-source cleanup removed five Aegis v2 platform features from the
-- codebase: scheduled automations (cron), the Slack bot, sprint orchestration,
-- security-debt snapshots, and the Aegis incident-playbook chat tools.
-- This migration drops the tables that belonged exclusively to those features.
--
-- Explicitly KEPT (still used by the live chat, the Task agent, or the broader
-- incident-response feature): aegis_chat_* (threads, messages, participants,
-- user_state, invite_codes), aegis_tool_executions, aegis_tasks,
-- aegis_task_steps, aegis_memory, aegis_org_settings, aegis_approval_requests,
-- aegis_activity_logs, aegis_inbox, aegis_config, security_incidents,
-- incident_playbooks, incident_timeline.
--
-- Note: aegis_automations and aegis_automation_jobs are NOT dropped here —
-- they were already dropped in drop_aegis_tables.sql / phase20_aegis_v2_cleanup.sql
-- and no longer exist. Safe to re-run (IF EXISTS on every drop).

-- Automations event triggers (only reader was lib/aegis/automations-engine.ts).
DROP TABLE IF EXISTS aegis_event_triggers CASCADE;

-- Slack bot per-org config (only reader was lib/aegis/slack-bot.ts).
DROP TABLE IF EXISTS aegis_slack_config CASCADE;

-- Security-debt daily snapshots (only reader/writer was lib/aegis/security-debt.ts).
DROP TABLE IF EXISTS security_debt_snapshots CASCADE;
