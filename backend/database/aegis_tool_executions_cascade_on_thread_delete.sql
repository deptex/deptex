-- Add ON DELETE CASCADE to aegis_tool_executions.thread_id so deleting a chat
-- thread also drops its tool execution audit rows. Without this, the FK
-- (originally created without an ON DELETE clause in
-- create_ai_usage_logs_and_aegis_tool_executions.sql) blocked thread deletion
-- with: "update or delete on table aegis_chat_threads violates foreign key
-- constraint aegis_tool_executions_thread_id_fkey".
--
-- Matches the cascade behavior of the other thread_id FKs (aegis_chat_messages,
-- aegis_chat_participants, aegis_chat_invite_codes, aegis_chat_user_state).

ALTER TABLE public.aegis_tool_executions
  DROP CONSTRAINT IF EXISTS aegis_tool_executions_thread_id_fkey;

ALTER TABLE public.aegis_tool_executions
  ADD CONSTRAINT aegis_tool_executions_thread_id_fkey
  FOREIGN KEY (thread_id) REFERENCES public.aegis_chat_threads(id) ON DELETE CASCADE;
