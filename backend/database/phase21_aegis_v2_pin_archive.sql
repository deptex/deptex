-- Phase 21 — Aegis v2 pin + archive
ALTER TABLE aegis_chat_threads
  ADD COLUMN IF NOT EXISTS pinned_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_aegis_chat_threads_pinned
  ON aegis_chat_threads(user_id, pinned_at DESC)
  WHERE pinned_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_aegis_chat_threads_archived
  ON aegis_chat_threads(user_id, archived_at)
  WHERE archived_at IS NOT NULL;
