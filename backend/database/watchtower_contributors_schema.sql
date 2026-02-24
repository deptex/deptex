-- Package Contributors Table
-- Stores contributor profiles with behavioral statistics for anomaly detection
-- Used by the Watchtower worker to build baseline behavior patterns

CREATE TABLE IF NOT EXISTS package_contributors (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  watched_package_id UUID NOT NULL REFERENCES watched_packages(id) ON DELETE CASCADE,
  author_email TEXT NOT NULL,
  author_name TEXT,
  
  -- Commit statistics
  total_commits INT NOT NULL DEFAULT 0,
  
  -- Lines changed statistics
  avg_lines_added FLOAT DEFAULT 0,
  avg_lines_deleted FLOAT DEFAULT 0,
  stddev_lines_added FLOAT DEFAULT 0,
  stddev_lines_deleted FLOAT DEFAULT 0,
  
  -- Files changed statistics
  avg_files_changed FLOAT DEFAULT 0,
  stddev_files_changed FLOAT DEFAULT 0,
  
  -- Commit message statistics
  avg_commit_message_length FLOAT DEFAULT 0,
  stddev_commit_message_length FLOAT DEFAULT 0,
  
  -- Ratio metrics
  insert_to_delete_ratio FLOAT DEFAULT 0,
  
  -- Time-based behavior patterns (for anomaly detection)
  commit_time_histogram JSONB DEFAULT '{}', -- Hours: {"0:00": count, "1:00": count, ...}
  typical_days_active JSONB DEFAULT '{}', -- Days: {"Monday": count, "Tuesday": count, ...}
  commit_time_heatmap JSONB DEFAULT '[]', -- 7x24 grid: [day][hour] = commit count
  
  -- Files the contributor typically works on
  files_worked_on JSONB DEFAULT '{}', -- {"path/to/file": count, ...}
  
  -- Activity window
  first_commit_date TIMESTAMP WITH TIME ZONE,
  last_commit_date TIMESTAMP WITH TIME ZONE,
  
  -- Timestamps
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Ensure no duplicate contributors per package
  UNIQUE(watched_package_id, author_email)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_package_contributors_watched_package_id 
  ON package_contributors(watched_package_id);

CREATE INDEX IF NOT EXISTS idx_package_contributors_author_email 
  ON package_contributors(author_email);

CREATE INDEX IF NOT EXISTS idx_package_contributors_total_commits 
  ON package_contributors(total_commits DESC);

-- Enable RLS
ALTER TABLE package_contributors ENABLE ROW LEVEL SECURITY;

-- Allow service role full access
CREATE POLICY "Service role can manage package_contributors" ON package_contributors
  FOR ALL
  USING (true)
  WITH CHECK (true);
