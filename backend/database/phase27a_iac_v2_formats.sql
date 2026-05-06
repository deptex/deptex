-- Phase 27a: IaC + Container Scanning v2 — Formats
-- Adds:
--   - project_iac_findings.framework CHECK extension (3 → 9 values)
--     New: helm, cloudformation, arm, bicep, serverless, github_actions
--     Kept: terraform, kubernetes, dockerfile
--     Note: kustomization.yaml files surface as 'kubernetes' — no separate value.
--   - project_iac_findings.compliance_refs JSONB (CIS / SOC2 / NIST badge data
--     extracted from Checkov metadata.benchmark; nullable when no refs).
--
-- Independent of phase27b; if 1a stalls, 27a stays in production.
-- Rollback: phase27a_iac_v2_formats_rollback.sql — DELETEs v2-only rows before
-- re-narrowing the CHECK so it runs cleanly on populated tables.

BEGIN;

ALTER TABLE project_iac_findings DROP CONSTRAINT IF EXISTS project_iac_findings_framework_check;
ALTER TABLE project_iac_findings ADD CONSTRAINT project_iac_findings_framework_check
  CHECK (framework IN (
    'terraform', 'kubernetes', 'dockerfile',
    'helm', 'cloudformation', 'arm', 'bicep', 'serverless',
    'github_actions'
  ));
-- 'kustomize' deliberately omitted — kustomization.yaml surfaces as 'kubernetes'.

ALTER TABLE project_iac_findings ADD COLUMN IF NOT EXISTS compliance_refs JSONB;
-- GIN index gated to v3 (project-scoped lists in v2, no cross-org rollups).

COMMIT;
