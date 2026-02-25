-- Project-specific vulnerabilities (reachable vulns from dep-scan with EPSS).
-- Replaces dependency_vulnerabilities for project-level vulnerability views.
-- Stores per-project, per-dependency-version reachable vulns + EPSS.

CREATE TABLE IF NOT EXISTS project_dependency_vulnerabilities (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  project_dependency_id UUID NOT NULL REFERENCES project_dependencies(id) ON DELETE CASCADE,
  osv_id TEXT NOT NULL,
  severity TEXT, -- critical, high, medium, low
  summary TEXT,
  aliases TEXT[], -- CVE IDs and other aliases
  fixed_versions TEXT[],
  is_reachable BOOLEAN NOT NULL DEFAULT true,
  epss_score NUMERIC(5, 4), -- e.g. 0.0001 to 1.0000
  cvss_score NUMERIC(3, 1), -- 0.0 to 10.0
  cisa_kev BOOLEAN NOT NULL DEFAULT false,
  depscore INTEGER, -- 0-100 composite risk score (4-tier asset_tier: CROWN_JEWELS, EXTERNAL, INTERNAL, NON_PRODUCTION)
  published_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, project_dependency_id, osv_id)
);

ALTER TABLE project_dependency_vulnerabilities ENABLE ROW LEVEL SECURITY;

CREATE INDEX IF NOT EXISTS idx_project_dependency_vulnerabilities_project_id
  ON project_dependency_vulnerabilities(project_id);
CREATE INDEX IF NOT EXISTS idx_project_dependency_vulnerabilities_project_dependency_id
  ON project_dependency_vulnerabilities(project_dependency_id);
CREATE INDEX IF NOT EXISTS idx_project_dependency_vulnerabilities_osv_id
  ON project_dependency_vulnerabilities(osv_id);
CREATE INDEX IF NOT EXISTS idx_project_dependency_vulnerabilities_severity
  ON project_dependency_vulnerabilities(severity);

-- Allow service role full access
CREATE POLICY "Service role can manage project_dependency_vulnerabilities" ON project_dependency_vulnerabilities
  FOR ALL
  USING (true)
  WITH CHECK (true);
