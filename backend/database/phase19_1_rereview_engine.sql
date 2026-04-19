-- Phase 19.1: Re-review trigger engine + semgrep fingerprint stable ID
--
-- Builds on phase19_atomic_commit.sql. Additive — no data loss.
--
-- Goal:
--   1. Semgrep findings use semgrep's native `extra.fingerprint` as stable ID
--      (survives formatting, line shifts, comment edits). The pipeline step is
--      updated separately to capture this from CLI output.
--   2. PDV findings gain a trigger engine that fires when external threat-intel
--      or project context changes meaningfully: user sees a "re-review needed" /
--      "updated" badge on affected findings, rolled up into one notification per
--      extraction per project.
--   3. Re-review thresholds live per asset tier (Crown Jewels vs Non-Prod get
--      different sensitivities). Project inherits via its asset_tier_id.
--
-- See .cursor/plans/phase1-atomic-commit-design.md for full design rationale.

-- =============================================================================
-- 1. project_semgrep_findings: capture semgrep's native stable fingerprint
--    Existing (project_id, rule_id, file_path, start_line) constraint is kept
--    for backward-compat on rows without fingerprint. Carry-forward logic uses
--    fingerprint when available, falls back to the line-based tuple otherwise.
-- =============================================================================
ALTER TABLE project_semgrep_findings
  ADD COLUMN IF NOT EXISTS semgrep_fingerprint TEXT;

CREATE INDEX IF NOT EXISTS idx_psemf_fingerprint
  ON project_semgrep_findings(project_id, semgrep_fingerprint)
  WHERE semgrep_fingerprint IS NOT NULL;

COMMENT ON COLUMN project_semgrep_findings.semgrep_fingerprint IS
  'Phase 19.1: semgrep CLI extra.fingerprint. Stable across reformatting and line shifts. Preferred stable ID for carry-forward; falls back to (rule_id, file_path, start_line) when NULL (pre-Phase19.1 rows).';

-- =============================================================================
-- 2. project_dependency_vulnerabilities: re-review trigger columns
--    Orthogonal to status — the badge renders whenever re_review_triggered_at
--    is set, regardless of whether status is 'open' or 'ignored'. User action
--    (re-ignore, mark fixed, etc.) clears these columns.
-- =============================================================================
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS re_review_triggered_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS re_review_reasons JSONB;

-- Queries that list re-review items: WHERE re_review_triggered_at IS NOT NULL
CREATE INDEX IF NOT EXISTS idx_pdv_rereview_triggered
  ON project_dependency_vulnerabilities(project_id, re_review_triggered_at DESC)
  WHERE re_review_triggered_at IS NOT NULL;

COMMENT ON COLUMN project_dependency_vulnerabilities.re_review_triggered_at IS
  'Phase 19.1: when the carry-forward engine last flagged this finding for user re-review. NULL = no re-review pending. Cleared when user re-ignores, marks fixed, or otherwise acts on the finding.';
COMMENT ON COLUMN project_dependency_vulnerabilities.re_review_reasons IS
  'Phase 19.1: JSONB array of triggers that fired. Shape: [{"trigger": "depscore_delta", "from": 42, "to": 51, "detected_at": "2026-04-19T..."}, ...]. Accumulates across re-firings until user acts.';

-- =============================================================================
-- 3. organization_asset_tiers: per-tier re-review configuration
--    Every project inherits its tier's settings via projects.asset_tier_id.
--    Default shape tunable via org settings UI (Phase 1.5).
-- =============================================================================
ALTER TABLE organization_asset_tiers
  ADD COLUMN IF NOT EXISTS rereview_settings JSONB NOT NULL DEFAULT jsonb_build_object(
    'enabled', true,
    'triggers', jsonb_build_object(
      'depscore_delta', 5,
      'severity_escalation', true,
      'reachability_upgrade', true,
      'kev_added', true,
      'epss_delta', 0.1,
      'has_exploit_flipped', true,
      'is_malicious_flipped', true,
      'became_direct', true,
      'dev_to_prod', true
    )
  );

-- Tune system-tier defaults: tighter thresholds for more critical tiers.
-- Only touches is_system tiers so we don't stomp on user-customized tiers
-- that may exist from prior Phase 14 migration runs.
UPDATE organization_asset_tiers
SET rereview_settings = jsonb_set(
  rereview_settings,
  '{triggers,depscore_delta}',
  to_jsonb(3)
) || jsonb_build_object(
  'triggers',
  (rereview_settings -> 'triggers') || jsonb_build_object('epss_delta', 0.05)
)
WHERE is_system = true AND rank <= 2;

UPDATE organization_asset_tiers
SET rereview_settings = jsonb_set(
  rereview_settings,
  '{triggers,depscore_delta}',
  to_jsonb(10)
) || jsonb_build_object(
  'triggers',
  (rereview_settings -> 'triggers') || jsonb_build_object('epss_delta', 0.2)
)
WHERE is_system = true AND rank >= 4;

COMMENT ON COLUMN organization_asset_tiers.rereview_settings IS
  'Phase 19.1: per-tier re-review trigger thresholds. Projects inherit via projects.asset_tier_id. Shape: {enabled, triggers: {depscore_delta, severity_escalation, reachability_upgrade, kev_added, epss_delta, has_exploit_flipped, is_malicious_flipped, became_direct, dev_to_prod}}. System tier defaults vary by rank: Crown Jewels (rank<=2) tighter, Non-Prod (rank>=4) looser.';
