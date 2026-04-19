-- Dependency vulnerabilities table - stores vulnerability details from OSV.dev
-- We store vulnerabilities for the current version and up to 5 previous versions
-- to avoid re-polling when another project uses an older version

CREATE TABLE IF NOT EXISTS dependency_vulnerabilities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  dependency_id UUID NOT NULL REFERENCES dependencies(id) ON DELETE CASCADE,
  osv_id TEXT NOT NULL,
  severity TEXT, -- critical, high, medium, low
  summary TEXT,
  details TEXT,
  aliases TEXT[], -- CVE IDs and other aliases
  affected_versions JSONB, -- Array of affected version ranges
  fixed_versions TEXT[], -- Versions where the vulnerability is fixed
  published_at TIMESTAMP WITH TIME ZONE,
  modified_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(dependency_id, osv_id)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_dependency_vulnerabilities_dependency_id 
  ON dependency_vulnerabilities(dependency_id);
CREATE INDEX IF NOT EXISTS idx_dependency_vulnerabilities_severity 
  ON dependency_vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_dependency_vulnerabilities_osv_id 
  ON dependency_vulnerabilities(osv_id);
