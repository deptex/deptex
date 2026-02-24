-- Global watched packages table
-- Tracks all packages being monitored by the Watchtower system
-- This enables centralized tracking, deduplication of analysis work, and batch processing

CREATE TABLE IF NOT EXISTS watched_packages (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL UNIQUE,
  -- Analysis status
  status TEXT NOT NULL DEFAULT 'pending', -- pending, analyzing, ready, error
  -- Watchtower analysis results (to be populated by worker)
  registry_integrity_status TEXT, -- pass, warning, fail
  install_scripts_status TEXT,
  entropy_analysis_status TEXT,
  maintainer_analysis_status TEXT,
  -- Latest release quarantine info
  latest_version TEXT,
  latest_release_date TIMESTAMP WITH TIME ZONE,
  quarantine_expires_at TIMESTAMP WITH TIME ZONE,
  -- Metadata
  analysis_data JSONB,
  error_message TEXT,
  analyzed_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_watched_packages_name ON watched_packages(name);
CREATE INDEX IF NOT EXISTS idx_watched_packages_status ON watched_packages(status);

-- Index for finding packages in quarantine
CREATE INDEX IF NOT EXISTS idx_watched_packages_quarantine
  ON watched_packages(quarantine_expires_at)
  WHERE quarantine_expires_at IS NOT NULL;
