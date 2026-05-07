-- Phase 27a rollback — reverse the framework CHECK widening + drop compliance_refs.
--
-- Populated-table handling: rows with framework values introduced in 27a
-- (helm/cloudformation/arm/bicep/serverless/github_actions) are DELETEd before
-- the narrow CHECK is reapplied. Those rows would violate the v1 CHECK; running
-- this on a populated table without the DELETE would fail with constraint
-- violation 23514.
--
-- Trade-off: rollback discards 27a-era IaC findings for the new framework
-- values. v1 carry-forward of TF/K8s/Dockerfile findings is preserved (those
-- rows pass the narrow CHECK unchanged).

BEGIN;

DELETE FROM project_iac_findings
  WHERE framework NOT IN ('terraform', 'kubernetes', 'dockerfile');

ALTER TABLE project_iac_findings DROP CONSTRAINT IF EXISTS project_iac_findings_framework_check;
ALTER TABLE project_iac_findings ADD CONSTRAINT project_iac_findings_framework_check
  CHECK (framework IN ('terraform', 'kubernetes', 'dockerfile'));

ALTER TABLE project_iac_findings DROP COLUMN IF EXISTS compliance_refs;

COMMIT;
