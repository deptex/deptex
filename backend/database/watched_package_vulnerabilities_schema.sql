-- Watched Package Vulnerabilities Table
-- Stores OSV vulnerabilities discovered for watched packages
-- Used by the watchtower-poller to track newly disclosed CVEs/advisories

CREATE TABLE IF NOT EXISTS watched_package_vulnerabilities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  watched_package_id UUID NOT NULL REFERENCES watched_packages(id) ON DELETE CASCADE,
  osv_id TEXT NOT NULL,
  severity TEXT, -- critical, high, medium, low
  summary TEXT,
  details TEXT,
  aliases TEXT[], -- CVE IDs and other aliases
  affected_versions JSONB,
  fixed_versions TEXT[],
  published_at TIMESTAMP WITH TIME ZONE,
  modified_at TIMESTAMP WITH TIME ZONE,
  first_detected_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(), -- When we first discovered it
  
  -- Ensure no duplicate vulnerabilities per package
  UNIQUE(watched_package_id, osv_id)
);

-- Indexes for efficient querying
CREATE INDEX IF NOT EXISTS idx_watched_package_vulnerabilities_watched_package_id 
  ON watched_package_vulnerabilities(watched_package_id);

CREATE INDEX IF NOT EXISTS idx_watched_package_vulnerabilities_severity 
  ON watched_package_vulnerabilities(severity);

CREATE INDEX IF NOT EXISTS idx_watched_package_vulnerabilities_osv_id 
  ON watched_package_vulnerabilities(osv_id);

CREATE INDEX IF NOT EXISTS idx_watched_package_vulnerabilities_first_detected_at 
  ON watched_package_vulnerabilities(first_detected_at DESC);

-- Enable RLS
ALTER TABLE watched_package_vulnerabilities ENABLE ROW LEVEL SECURITY;

-- Allow service role full access
CREATE POLICY "Service role can manage watched_package_vulnerabilities" ON watched_package_vulnerabilities
  FOR ALL
  USING (true)
  WITH CHECK (true);
