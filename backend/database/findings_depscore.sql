-- Add depscore column to secret and semgrep findings tables
-- Unified 0-100 priority score, same scale as vulnerability depscores

ALTER TABLE project_secret_findings ADD COLUMN IF NOT EXISTS depscore INTEGER;
ALTER TABLE project_semgrep_findings ADD COLUMN IF NOT EXISTS depscore INTEGER;

CREATE INDEX IF NOT EXISTS idx_psecf_depscore ON project_secret_findings(depscore DESC NULLS LAST);
CREATE INDEX IF NOT EXISTS idx_psemf_depscore ON project_semgrep_findings(depscore DESC NULLS LAST);
