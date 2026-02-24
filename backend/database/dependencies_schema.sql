-- Dependencies table - stores unique package-level data (one row per package name)
-- This enables deduplication across projects

CREATE TABLE IF NOT EXISTS dependencies (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL UNIQUE,
  license TEXT,
  -- Reputation score + status
  status TEXT NOT NULL DEFAULT 'pending', -- pending, analyzing, ready, error
  score INTEGER, -- reputation score (0-100)
  -- OpenSSF Scorecard (package-level)
  openssf_score DECIMAL(3,1),
  openssf_data JSONB,
  -- npm stats
  weekly_downloads INTEGER,
  last_published_at TIMESTAMP WITH TIME ZONE,
  -- Maintenance
  releases_last_12_months INTEGER,
  -- Score breakdown penalties
  openssf_penalty INTEGER DEFAULT 0,
  popularity_penalty INTEGER DEFAULT 0,
  maintenance_penalty INTEGER DEFAULT 0,
  -- Package metadata
  github_url TEXT,
  description TEXT,
  latest_version TEXT,
  latest_release_date TIMESTAMP WITH TIME ZONE,
  -- Analysis metadata
  analyzed_at TIMESTAMP WITH TIME ZONE,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_dependencies_name ON dependencies(name);
CREATE INDEX IF NOT EXISTS idx_dependencies_status ON dependencies(status);
CREATE INDEX IF NOT EXISTS idx_dependencies_github_url ON dependencies(github_url);
