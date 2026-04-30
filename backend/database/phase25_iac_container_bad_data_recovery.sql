-- Phase 25: IaC + Container scanning — bad-data recovery recipe.
--
-- Run only when a parser bug shipped a corrupted batch of findings under a
-- known scanner_version. The naive `DELETE WHERE scanner_version = ...`
-- would also nuke any user decisions (status='ignored', risk_accepted,
-- suppressed) on those rows. The 3-stage procedure below preserves them.
--
-- Per-incident substitutions:
--   <DATE>            — yyyymmdd suffix for the backup table name
--   <SCANNER>         — 'checkov' or 'trivy'
--   <BAD_VERSION>     — the bad scanner version string, e.g. 'checkov@3.2.5'
--
-- IaC findings: keyed on (project_id, scanner, iac_fingerprint).
-- Container findings: keyed on (project_id, container_fingerprint).
-- Fingerprint-NULL rows lose their decisions in the restore step
-- (intentional — see plan rationale).

-- ============================================================
-- Stage 1 — preservation pass.
-- Snapshot the user-decision columns for any row about to be purged.
-- ============================================================
-- IaC variant:
CREATE TABLE IF NOT EXISTS bad_data_iac_decisions_backup_<DATE> AS
SELECT
  id, project_id, iac_fingerprint, scanner,
  status,
  suppressed, suppressed_by, suppressed_at,
  risk_accepted, risk_accepted_by, risk_accepted_at, risk_accepted_reason
FROM project_iac_findings
WHERE scanner = '<SCANNER>'
  AND scanner_version = '<BAD_VERSION>'
  AND (status = 'ignored' OR suppressed OR risk_accepted);

-- Container variant:
CREATE TABLE IF NOT EXISTS bad_data_container_decisions_backup_<DATE> AS
SELECT
  id, project_id, container_fingerprint,
  status,
  suppressed, suppressed_by, suppressed_at,
  risk_accepted, risk_accepted_by, risk_accepted_at, risk_accepted_reason
FROM project_container_findings
WHERE scanner_version = '<BAD_VERSION>'
  AND (status = 'ignored' OR suppressed OR risk_accepted);


-- ============================================================
-- Stage 2 — surgical purge.
-- Delete the corrupt rows. New extraction will re-emit clean rows.
-- ============================================================
-- IaC:
DELETE FROM project_iac_findings
WHERE scanner = '<SCANNER>'
  AND scanner_version = '<BAD_VERSION>';

-- Container:
DELETE FROM project_container_findings
WHERE scanner_version = '<BAD_VERSION>';


-- ============================================================
-- Stage 3 — restore.
-- After the next extraction completes, run the matching UPDATE to copy the
-- preserved decisions onto the freshly-emitted rows where the fingerprint
-- matches. Fingerprint-NULL backup rows do NOT carry — their fingerprints
-- can't be matched, by design.
-- ============================================================
-- IaC:
UPDATE project_iac_findings new_if
SET
  status = b.status,
  suppressed = b.suppressed,
  suppressed_by = b.suppressed_by,
  suppressed_at = b.suppressed_at,
  risk_accepted = b.risk_accepted,
  risk_accepted_by = b.risk_accepted_by,
  risk_accepted_at = b.risk_accepted_at,
  risk_accepted_reason = b.risk_accepted_reason
FROM bad_data_iac_decisions_backup_<DATE> b
WHERE new_if.project_id = b.project_id
  AND new_if.scanner = b.scanner
  AND new_if.iac_fingerprint IS NOT NULL
  AND b.iac_fingerprint IS NOT NULL
  AND new_if.iac_fingerprint = b.iac_fingerprint;

-- Container:
UPDATE project_container_findings new_cf
SET
  status = b.status,
  suppressed = b.suppressed,
  suppressed_by = b.suppressed_by,
  suppressed_at = b.suppressed_at,
  risk_accepted = b.risk_accepted,
  risk_accepted_by = b.risk_accepted_by,
  risk_accepted_at = b.risk_accepted_at,
  risk_accepted_reason = b.risk_accepted_reason
FROM bad_data_container_decisions_backup_<DATE> b
WHERE new_cf.project_id = b.project_id
  AND new_cf.container_fingerprint IS NOT NULL
  AND b.container_fingerprint IS NOT NULL
  AND new_cf.container_fingerprint = b.container_fingerprint;


-- ============================================================
-- Cleanup (optional — after restore is verified).
-- ============================================================
-- DROP TABLE bad_data_iac_decisions_backup_<DATE>;
-- DROP TABLE bad_data_container_decisions_backup_<DATE>;
