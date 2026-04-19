-- Add status column to all security findings tables
-- Values: 'open' (default), 'ignored'

ALTER TABLE project_dependency_vulnerabilities ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE project_secret_findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE project_semgrep_findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';

CREATE INDEX IF NOT EXISTS idx_pdv_status ON project_dependency_vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_psecf_status ON project_secret_findings(status);
CREATE INDEX IF NOT EXISTS idx_psemf_status ON project_semgrep_findings(status);
