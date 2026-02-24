-- Package Commits Table
-- Stores recent commits for watched packages to enable commit-level analysis
-- Used by the Watchtower worker to track repository activity

CREATE TABLE IF NOT EXISTS package_commits (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  watched_package_id UUID NOT NULL REFERENCES watched_packages(id) ON DELETE CASCADE,
  sha TEXT NOT NULL,
  author TEXT NOT NULL,
  author_email TEXT NOT NULL,
  message TEXT NOT NULL,
  timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
  lines_added INT DEFAULT 0,
  lines_deleted INT DEFAULT 0,
  files_changed INT DEFAULT 0,
  diff_data JSONB, -- Stores detailed diff information per file
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Ensure no duplicate commits per package
  UNIQUE(watched_package_id, sha)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_package_commits_watched_package_id 
  ON package_commits(watched_package_id);

CREATE INDEX IF NOT EXISTS idx_package_commits_timestamp 
  ON package_commits(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_package_commits_author_email 
  ON package_commits(author_email);

-- Enable RLS
ALTER TABLE package_commits ENABLE ROW LEVEL SECURITY;

-- Allow service role full access
CREATE POLICY "Service role can manage package_commits" ON package_commits
  FOR ALL
  USING (true)
  WITH CHECK (true);
