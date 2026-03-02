-- Phase 8G: PR Tracking Table
-- Tracks PR lifecycle so the compliance tab shows real PR data.

CREATE TABLE IF NOT EXISTS project_pull_requests (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  pr_number INTEGER NOT NULL,
  title TEXT,
  author_login TEXT,
  author_avatar_url TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  check_result TEXT,
  check_summary TEXT,
  deps_added INTEGER DEFAULT 0,
  deps_updated INTEGER DEFAULT 0,
  deps_removed INTEGER DEFAULT 0,
  transitive_changes INTEGER DEFAULT 0,
  blocked_by JSONB,
  provider TEXT NOT NULL DEFAULT 'github',
  provider_url TEXT,
  base_branch TEXT,
  head_branch TEXT,
  head_sha TEXT,
  opened_at TIMESTAMPTZ,
  merged_at TIMESTAMPTZ,
  closed_at TIMESTAMPTZ,
  last_checked_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_project_prs_project_id ON project_pull_requests(project_id);
CREATE INDEX IF NOT EXISTS idx_project_prs_status ON project_pull_requests(status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_prs_project_pr ON project_pull_requests(project_id, pr_number, provider);
