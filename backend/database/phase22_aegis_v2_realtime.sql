-- Phase 22: Aegis v2 Realtime fixes.
--
-- Two fixes needed to make Supabase Realtime deliver aegis_chat_messages
-- events to the client:
--
-- (1) Add aegis_chat_messages to the `supabase_realtime` publication. The
--     original schema (aegis_chat_messages_schema.sql) created the table and
--     RLS but never added it to the publication, so `postgres_changes` events
--     never fired at all.
--
-- (2) Break the infinite recursion in the aegis_chat_participants SELECT
--     policy. The old policy said "you can see participant rows whose
--     thread_id is in the set of threads you're a participant of" — which
--     self-references. When Postgres evaluates the aegis_chat_messages SELECT
--     policy (which also subqueries aegis_chat_participants), the inner table
--     applies its own policy, which recurses. Realtime's walrus_rls then
--     errors with `infinite recursion detected`, and NO events are delivered.
--
--     New policy: users can only see their own participant rows via direct
--     RLS. That's enough for the aegis_chat_messages policy's subquery to
--     return the correct set of thread_ids. The frontend already goes through
--     the service-role backend endpoint to list *other* participants of a
--     thread, so this doesn't reduce user-visible functionality.
--
-- Idempotent.

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_publication_tables
    WHERE pubname = 'supabase_realtime' AND tablename = 'aegis_chat_messages'
  ) THEN
    ALTER PUBLICATION supabase_realtime ADD TABLE aegis_chat_messages;
  END IF;
END $$;

DROP POLICY IF EXISTS "Participants can view participant rows" ON aegis_chat_participants;

CREATE POLICY "Users can view their own participant rows"
  ON aegis_chat_participants FOR SELECT
  USING (user_id = auth.uid());
