-- Project-level notification pause. When set, project notification rules are skipped until this time.
-- Org- and team-level pause still apply to their respective scopes.
ALTER TABLE projects ADD COLUMN IF NOT EXISTS notifications_paused_until TIMESTAMPTZ;
