-- Team-level notification pause (optional). When set, team notification rules are skipped until this time.
-- Org-level pause (organizations.notifications_paused_until) still applies to all events.
ALTER TABLE teams ADD COLUMN IF NOT EXISTS notifications_paused_until TIMESTAMPTZ;
