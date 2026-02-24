-- Remove redundant vuln count columns from dependency_versions.
-- Counts are derived at read time from dependency_vulnerabilities (version vs affected_versions + severity).

ALTER TABLE dependency_versions
  DROP COLUMN IF EXISTS critical_vulns,
  DROP COLUMN IF EXISTS high_vulns,
  DROP COLUMN IF EXISTS medium_vulns,
  DROP COLUMN IF EXISTS low_vulns;
