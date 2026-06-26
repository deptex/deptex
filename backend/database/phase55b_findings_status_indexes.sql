-- phase55b: findings-status foundation indexes (companion to phase55)
--
-- CREATE INDEX CONCURRENTLY can't run inside a transaction, so the indexes live
-- in their own non-transactional file. `(project_id, finding_key)` backs the
-- status endpoint's (project_id, finding_key) -> active-run-row resolution;
-- `(project_id, status)` backs the Open/Ignored filter reads. DROP IF EXISTS
-- first so a previously-failed CONCURRENTLY build (left INVALID) is replaced.
--
-- Run AFTER phase55. Not wrapped in BEGIN/COMMIT.

DROP INDEX IF EXISTS idx_pdv_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pdv_project_finding_key
  ON project_dependency_vulnerabilities (project_id, finding_key);
DROP INDEX IF EXISTS idx_pdv_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_pdv_project_status
  ON project_dependency_vulnerabilities (project_id, status);

DROP INDEX IF EXISTS idx_secret_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_secret_project_finding_key
  ON project_secret_findings (project_id, finding_key);
DROP INDEX IF EXISTS idx_secret_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_secret_project_status
  ON project_secret_findings (project_id, status);

DROP INDEX IF EXISTS idx_semgrep_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_semgrep_project_finding_key
  ON project_semgrep_findings (project_id, finding_key);
DROP INDEX IF EXISTS idx_semgrep_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_semgrep_project_status
  ON project_semgrep_findings (project_id, status);

DROP INDEX IF EXISTS idx_dast_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dast_project_finding_key
  ON project_dast_findings (project_id, finding_key);
DROP INDEX IF EXISTS idx_dast_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_dast_project_status
  ON project_dast_findings (project_id, status);

DROP INDEX IF EXISTS idx_iac_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iac_project_finding_key
  ON project_iac_findings (project_id, finding_key);
DROP INDEX IF EXISTS idx_iac_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_iac_project_status
  ON project_iac_findings (project_id, status);

DROP INDEX IF EXISTS idx_container_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_container_project_finding_key
  ON project_container_findings (project_id, finding_key);
DROP INDEX IF EXISTS idx_container_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_container_project_status
  ON project_container_findings (project_id, status);

DROP INDEX IF EXISTS idx_malicious_project_finding_key;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_project_finding_key
  ON project_malicious_findings (project_id, finding_key);
DROP INDEX IF EXISTS idx_malicious_project_status;
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_malicious_project_status
  ON project_malicious_findings (project_id, status);
