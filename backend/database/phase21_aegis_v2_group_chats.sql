-- Aegis v2 group chats: participants, per-user pin/archive, author column,
-- creator audit, active-stream guard. Replaces the earlier thread-level
-- pin/archive migration (pin + archive are now per-user).

CREATE TABLE aegis_chat_participants (
  thread_id UUID NOT NULL REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (thread_id, user_id)
);
CREATE INDEX idx_aegis_chat_participants_user_id ON aegis_chat_participants(user_id);

CREATE TABLE aegis_chat_user_state (
  thread_id UUID NOT NULL REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  pinned_at TIMESTAMPTZ,
  archived_at TIMESTAMPTZ,
  PRIMARY KEY (thread_id, user_id)
);
CREATE INDEX idx_aegis_chat_user_state_user_id ON aegis_chat_user_state(user_id);

ALTER TABLE aegis_chat_threads
  ADD COLUMN created_by UUID REFERENCES auth.users(id),
  ADD COLUMN active_stream_until TIMESTAMPTZ;
UPDATE aegis_chat_threads SET created_by = user_id WHERE created_by IS NULL;
ALTER TABLE aegis_chat_threads ALTER COLUMN created_by SET NOT NULL;

ALTER TABLE aegis_chat_messages
  ADD COLUMN user_id UUID REFERENCES auth.users(id);

INSERT INTO aegis_chat_participants (thread_id, user_id, joined_at)
SELECT id, user_id, COALESCE(created_at, NOW()) FROM aegis_chat_threads
ON CONFLICT DO NOTHING;

INSERT INTO aegis_chat_user_state (thread_id, user_id, pinned_at, archived_at)
SELECT id, user_id, pinned_at, archived_at FROM aegis_chat_threads
WHERE pinned_at IS NOT NULL OR archived_at IS NOT NULL
ON CONFLICT DO NOTHING;

UPDATE aegis_chat_messages m
SET user_id = t.user_id
FROM aegis_chat_threads t
WHERE m.thread_id = t.id AND m.role = 'user' AND m.user_id IS NULL;

DROP INDEX IF EXISTS idx_aegis_chat_threads_pinned_at;
DROP INDEX IF EXISTS idx_aegis_chat_threads_archived_at;
ALTER TABLE aegis_chat_threads
  DROP COLUMN pinned_at,
  DROP COLUMN archived_at;

ALTER TABLE aegis_chat_participants ENABLE ROW LEVEL SECURITY;
ALTER TABLE aegis_chat_user_state ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Users can view aegis threads for their orgs" ON aegis_chat_threads;
DROP POLICY IF EXISTS "Users can create aegis threads" ON aegis_chat_threads;
DROP POLICY IF EXISTS "Users can update their own aegis threads" ON aegis_chat_threads;
DROP POLICY IF EXISTS "Users can delete their own aegis threads" ON aegis_chat_threads;

CREATE POLICY "Participants can view aegis threads"
  ON aegis_chat_threads FOR SELECT
  USING (id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));
CREATE POLICY "Org members can create aegis threads"
  ON aegis_chat_threads FOR INSERT
  WITH CHECK (
    organization_id IN (SELECT organization_id FROM organization_members WHERE user_id = auth.uid())
    AND user_id = auth.uid()
    AND created_by = auth.uid()
  );
CREATE POLICY "Participants can update aegis threads"
  ON aegis_chat_threads FOR UPDATE
  USING (id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));
CREATE POLICY "Creator can delete aegis threads"
  ON aegis_chat_threads FOR DELETE
  USING (user_id = auth.uid());

DROP POLICY IF EXISTS "Users can view aegis messages for their orgs" ON aegis_chat_messages;
DROP POLICY IF EXISTS "Users can create aegis messages" ON aegis_chat_messages;

CREATE POLICY "Participants can view aegis messages"
  ON aegis_chat_messages FOR SELECT
  USING (thread_id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));
CREATE POLICY "Participants can create aegis messages"
  ON aegis_chat_messages FOR INSERT
  WITH CHECK (thread_id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));

CREATE POLICY "Participants can view participant rows"
  ON aegis_chat_participants FOR SELECT
  USING (thread_id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));

CREATE POLICY "Users manage their own aegis user_state"
  ON aegis_chat_user_state FOR ALL
  USING (user_id = auth.uid())
  WITH CHECK (user_id = auth.uid());
