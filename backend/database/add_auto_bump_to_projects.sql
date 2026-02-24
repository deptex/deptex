-- Per-project Auto Bump toggle for Watchtower (default on).
-- When true, auto-bump PRs are created for new versions of direct dependencies (subject to watchlist/quarantine).

ALTER TABLE projects
ADD COLUMN IF NOT EXISTS auto_bump BOOLEAN NOT NULL DEFAULT true;

COMMENT ON COLUMN projects.auto_bump IS 'When true, automatically create bump PRs for new versions of direct dependencies (subject to org watchlist and quarantine).';
