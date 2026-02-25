-- Drop Aegis tables (chat, config, automations, activity, inbox).
-- Run this migration to remove Aegis feature tables. The feature will be reworked later.
-- Order matters: drop tables that reference others first.
--
-- After running: Comment out or remove the aegis route in backend/load-ee-routes.js
-- (app.use('/api/aegis', ...)) to avoid 500 errors when those endpoints are hit.

-- Chat (messages reference threads)
DROP TABLE IF EXISTS aegis_chat_messages;

-- Chat threads (drop trigger first)
DROP TRIGGER IF EXISTS update_aegis_chat_threads_updated_at ON aegis_chat_threads;
DROP FUNCTION IF EXISTS update_aegis_chat_threads_updated_at();
DROP TABLE IF EXISTS aegis_chat_threads;

-- Automation jobs (reference automations)
DROP TABLE IF EXISTS aegis_automation_jobs;

-- Automations
DROP TABLE IF EXISTS aegis_automations;

-- Activity logs
DROP TABLE IF EXISTS aegis_activity_logs;

-- Inbox
DROP TABLE IF EXISTS aegis_inbox;

-- Config
DROP TABLE IF EXISTS aegis_config;
