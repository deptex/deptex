-- Dependency Versions table - stores version-specific data
-- Each dependency (package) can have multiple versions
-- Vulnerability counts and security analysis results are stored per-version

CREATE TABLE IF NOT EXISTS dependency_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  version TEXT NOT NULL,
  
  -- Vulnerability counts (version-specific)
  critical_vulns INTEGER DEFAULT 0,
  high_vulns INTEGER DEFAULT 0,
  medium_vulns INTEGER DEFAULT 0,
  low_vulns INTEGER DEFAULT 0,
  
  -- Watchtower security analysis (nullable until analyzed)
  registry_integrity_status TEXT,  -- pass, warning, fail
  registry_integrity_reason TEXT,  -- reason for warning/fail status
  install_scripts_status TEXT,     -- pass, warning, fail
  install_scripts_reason TEXT,     -- reason for warning/fail status
  entropy_analysis_status TEXT,    -- pass, warning, fail
  entropy_analysis_reason TEXT,    -- reason for warning/fail status
  
  -- Detailed analysis data
  analysis_data JSONB,
  
  -- Timestamps
  analyzed_at TIMESTAMP WITH TIME ZONE,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Unique constraint: one entry per version per dependency
  UNIQUE(dependency_id, version)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_dependency_versions_dependency_id 
  ON dependency_versions(dependency_id);
CREATE INDEX IF NOT EXISTS idx_dependency_versions_version 
  ON dependency_versions(version);

-- Enable RLS
ALTER TABLE dependency_versions ENABLE ROW LEVEL SECURITY;

-- Allow service role full access
CREATE POLICY "Service role can manage dependency_versions" ON dependency_versions
  FOR ALL
  USING (true)
  WITH CHECK (true);
