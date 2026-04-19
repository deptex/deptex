-- Phase 6: Security Tab Core - Database migrations
-- Tables: project_semgrep_findings, project_secret_findings, project_vulnerability_events, project_version_candidates
-- Schema additions to project_dependency_vulnerabilities

-- Semgrep code analysis findings
CREATE TABLE IF NOT EXISTS project_semgrep_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER,
  end_line INTEGER,
  severity TEXT,
  message TEXT,
  cwe_ids TEXT[],
  owasp_ids TEXT[],
  category TEXT,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, rule_id, file_path, start_line)
);

CREATE INDEX IF NOT EXISTS idx_psf_project ON project_semgrep_findings(project_id);
CREATE INDEX IF NOT EXISTS idx_psf_run ON project_semgrep_findings(extraction_run_id);

-- TruffleHog secret findings (redacted values only)
CREATE TABLE IF NOT EXISTS project_secret_findings (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  detector_type TEXT NOT NULL,
  file_path TEXT NOT NULL,
  start_line INTEGER,
  is_verified BOOLEAN DEFAULT false,
  is_current BOOLEAN DEFAULT true,
  description TEXT,
  redacted_value TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, detector_type, file_path, start_line)
);

CREATE INDEX IF NOT EXISTS idx_psecf_project ON project_secret_findings(project_id);
CREATE INDEX IF NOT EXISTS idx_psecf_run ON project_secret_findings(extraction_run_id);

-- Vulnerability lifecycle events for timeline + MTTR
CREATE TABLE IF NOT EXISTS project_vulnerability_events (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  osv_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  metadata JSONB,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_pve_project_id ON project_vulnerability_events(project_id);
CREATE INDEX IF NOT EXISTS idx_pve_osv_id ON project_vulnerability_events(osv_id);
CREATE INDEX IF NOT EXISTS idx_pve_event_type ON project_vulnerability_events(event_type);
CREATE INDEX IF NOT EXISTS idx_pve_created_at ON project_vulnerability_events(created_at DESC);

-- Smart version recommendation candidates
CREATE TABLE IF NOT EXISTS project_version_candidates (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  package_name TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  current_version TEXT NOT NULL,
  candidate_type TEXT NOT NULL,
  candidate_version TEXT NOT NULL,
  fixes_cve_count INTEGER NOT NULL DEFAULT 0,
  total_current_cves INTEGER NOT NULL DEFAULT 0,
  fixes_cve_ids TEXT[],
  known_new_cves INTEGER DEFAULT 0,
  known_new_cve_ids TEXT[],
  is_major_bump BOOLEAN DEFAULT false,
  is_org_banned BOOLEAN DEFAULT false,
  release_notes TEXT,
  release_notes_url TEXT,
  published_at TIMESTAMPTZ,
  verified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(project_id, package_name, ecosystem, candidate_type)
);

CREATE INDEX IF NOT EXISTS idx_pvc_project_package ON project_version_candidates(project_id, package_name, ecosystem);

-- Add suppress/accept-risk columns to project_dependency_vulnerabilities
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS suppressed BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS suppressed_by UUID,
  ADD COLUMN IF NOT EXISTS suppressed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS risk_accepted BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS risk_accepted_by UUID,
  ADD COLUMN IF NOT EXISTS risk_accepted_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS risk_accepted_reason TEXT;
