-- Phase 53: split sync_frequency into two independent controls.
--
-- BEFORE: project_repositories.sync_frequency was a single enum
--   ('manual' | 'on_commit' | 'daily' | 'weekly') and mutually exclusive —
--   'on_commit' repos scanned on push (webhook handlers) and never on a
--   schedule; 'daily'/'weekly' scanned only via the scheduled cron; 'manual'
--   never auto-scanned.
--
-- AFTER: two independent fields.
--   scan_on_commit (boolean)            = re-extract on every push (the
--                                          real-time, event-driven trigger).
--   sync_frequency  ('daily'|'weekly')  = the periodic floor that ALWAYS runs,
--                                          catching newly-published advisories
--                                          on dependencies that haven't changed.
--   Both run independently: a repo can scan on commit AND on a daily floor.
--
-- New connections default to scan_on_commit=false + sync_frequency='daily'
-- (no per-commit credit burn; never more than a day stale). 'on_commit' and
-- 'manual' are retired as sync_frequency values; the backend now only writes
-- 'daily'/'weekly' to this column.

ALTER TABLE project_repositories
  ADD COLUMN IF NOT EXISTS scan_on_commit BOOLEAN NOT NULL DEFAULT false;

-- Migrate existing rows onto the two-field model.
UPDATE project_repositories
  SET scan_on_commit = true, sync_frequency = 'daily'
  WHERE sync_frequency = 'on_commit';

UPDATE project_repositories
  SET scan_on_commit = false, sync_frequency = 'weekly'
  WHERE sync_frequency = 'manual';

-- 'daily' / 'weekly' rows keep their floor; scan_on_commit stays false
-- (the column default), so they are unchanged.

-- New connections re-check daily by default (was 'on_commit').
ALTER TABLE project_repositories
  ALTER COLUMN sync_frequency SET DEFAULT 'daily';
