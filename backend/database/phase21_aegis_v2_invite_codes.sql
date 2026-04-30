-- Invite codes for joining an Aegis chat thread by code (fallback when the
-- inviter cannot see the target user under existing RBAC).

CREATE TABLE aegis_chat_invite_codes (
  thread_id UUID PRIMARY KEY REFERENCES aegis_chat_threads(id) ON DELETE CASCADE,
  code TEXT NOT NULL UNIQUE,
  created_by UUID NOT NULL REFERENCES auth.users(id),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  revoked_at TIMESTAMPTZ
);
CREATE INDEX idx_aegis_chat_invite_codes_active_code
  ON aegis_chat_invite_codes(code) WHERE revoked_at IS NULL;

ALTER TABLE aegis_chat_invite_codes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Participants can view invite codes"
  ON aegis_chat_invite_codes FOR SELECT
  USING (thread_id IN (SELECT thread_id FROM aegis_chat_participants WHERE user_id = auth.uid()));
