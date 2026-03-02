-- Phase 8C: Project Commits Tracking
-- Tracks every commit that hits the default branch for each project.

CREATE TABLE IF NOT EXISTS project_commits (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  sha TEXT NOT NULL,
  message TEXT,
  author_name TEXT,
  author_email TEXT,
  author_avatar_url TEXT,
  committed_at TIMESTAMPTZ,
  manifest_changed BOOLEAN NOT NULL DEFAULT false,
  extraction_triggered BOOLEAN NOT NULL DEFAULT false,
  extraction_status TEXT,
  files_changed INTEGER,
  compliance_status TEXT DEFAULT 'UNKNOWN',
  dependencies_added INTEGER DEFAULT 0,
  dependencies_removed INTEGER DEFAULT 0,
  dependencies_updated INTEGER DEFAULT 0,
  provider TEXT NOT NULL DEFAULT 'github',
  provider_url TEXT,
  created_at TIMESTAMPTZ DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_project_commits_project_id ON project_commits(project_id);
CREATE INDEX IF NOT EXISTS idx_project_commits_sha ON project_commits(sha);
CREATE UNIQUE INDEX IF NOT EXISTS idx_project_commits_project_sha ON project_commits(project_id, sha);
