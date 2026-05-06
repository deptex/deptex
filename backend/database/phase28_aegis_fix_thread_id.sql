-- Phase 28: link Aegis fixes to chat threads.
--
-- Until now, project_security_fixes only knew its origin via the FixPanel
-- context's in-memory shadow list (frontend-only) — reload nuked the list,
-- and the historical "what fixes did I propose in this thread" view was
-- inaccessible. Adding thread_id makes the relationship durable so the
-- panel can query `SELECT * FROM project_security_fixes WHERE thread_id = ?`
-- and see every plan ever generated in that thread.
--
-- Backfill is intentionally NULL for old rows; pre-Phase-28 fixes have no
-- thread association we can recover post-hoc. The frontend treats NULL
-- thread_id as "not associated with any thread".

ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS thread_id uuid;

ALTER TABLE public.project_security_fixes
  ADD CONSTRAINT project_security_fixes_thread_id_fkey
  FOREIGN KEY (thread_id)
  REFERENCES public.aegis_chat_threads(id)
  ON DELETE SET NULL;

-- Index supports the panel's "fixes for this thread" query, ordered by
-- most-recent-first.
CREATE INDEX IF NOT EXISTS idx_project_security_fixes_thread_id
  ON public.project_security_fixes (thread_id, created_at DESC)
  WHERE thread_id IS NOT NULL;
