-- Phase 25: Per-org AI rule generation pipeline
--
-- Phase 5 of the reachability roadmap stops trying to scale the per-CVE
-- Semgrep rule library by hand and instead generates rules per-org during
-- extraction. Pipeline (in-process within extraction-worker, p-limit 5):
--
--   for each vuln matching org's trigger policy:
--     fetch OSV advisory → fetch fix-commit patch diff → BYOK provider
--     drafts a rule + fixtures → semgrep validates pre-patch matches and
--     post-patch does not → row written to organization_generated_rules.
--
-- Two new tables drive this:
--   organization_reachability_settings — per-org trigger policy + AI model
--     choice + monthly budget cap.
--   organization_generated_rules — owned per-org, RLS-enforced, no cross-org
--     sharing; previous_versions JSONB carries rollback history when a rule
--     is regenerated with a different model.
--
-- Plus four telemetry columns on extraction_jobs so we can answer
-- "rules_matched=42 / total_detectable=68 / generated_this_scan=3 /
-- generation_cost=$0.12" from extraction_jobs alone.

-- =============================================================================
-- 1. organization_reachability_settings
-- =============================================================================

CREATE TABLE IF NOT EXISTS organization_reachability_settings (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  auto_generate_enabled BOOLEAN NOT NULL DEFAULT false,
  -- Trigger policy. Generation only fires when a vuln matches every active
  -- filter (severity AND (kev OR not require-kev) AND tier <= max AND ...).
  trigger_severities TEXT[] NOT NULL DEFAULT ARRAY['critical', 'high'],
  trigger_kev BOOLEAN NOT NULL DEFAULT true,
  trigger_asset_tier_max_rank INT NOT NULL DEFAULT 2,
  trigger_newly_discovered BOOLEAN NOT NULL DEFAULT true,
  trigger_reevaluate_existing BOOLEAN NOT NULL DEFAULT false,
  -- Provider choice — must match a row in organization_ai_providers for the
  -- same org or generation will skip silently with a warn-level step error.
  ai_provider TEXT NOT NULL DEFAULT 'anthropic'
    CHECK (ai_provider IN ('anthropic', 'openai', 'google')),
  ai_model TEXT NOT NULL DEFAULT 'claude-sonnet-4-6',
  -- Hard cost cap. The pipeline checks the running monthly spend before each
  -- batch and either skips or downgrades to haiku per on_budget_exhaustion.
  monthly_budget_usd NUMERIC(10, 2) NOT NULL DEFAULT 10.00,
  on_budget_exhaustion TEXT NOT NULL DEFAULT 'skip'
    CHECK (on_budget_exhaustion IN ('skip', 'fall_back_to_haiku')),
  -- Per-extraction wall-clock cap. After this many seconds of generation the
  -- pipeline bails out with whatever rules it has so far and continues.
  max_wait_seconds INT NOT NULL DEFAULT 300,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID REFERENCES auth.users(id)
);

ALTER TABLE organization_reachability_settings ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS reachability_settings_select ON organization_reachability_settings;
CREATE POLICY reachability_settings_select
  ON organization_reachability_settings
  FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS reachability_settings_modify ON organization_reachability_settings;
CREATE POLICY reachability_settings_modify
  ON organization_reachability_settings
  FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

COMMENT ON TABLE organization_reachability_settings IS
  'Phase 25: per-org policy for AI-driven Semgrep rule generation during extraction. NULL row = auto_generate_enabled=false, generation never fires.';

-- =============================================================================
-- 2. organization_generated_rules
-- =============================================================================

CREATE TABLE IF NOT EXISTS organization_generated_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  cve_id TEXT NOT NULL,
  package_purl TEXT NOT NULL,
  ecosystem TEXT NOT NULL,
  affected_version_range TEXT,
  rule_yaml TEXT NOT NULL,
  vulnerable_fixture TEXT NOT NULL,
  safe_fixture TEXT NOT NULL,
  -- 'confirmed' (taint sink → source flow) or 'function' (call-site only).
  -- Mirrors the existing project_dependency_vulnerabilities.reachability_level
  -- domain so rule matches can upgrade PDV reachability the same way Phase 3
  -- hand-written rules do.
  reachability_level TEXT NOT NULL,
  entry_point_class TEXT,
  generated_with_provider TEXT NOT NULL,
  generated_with_model TEXT NOT NULL,
  generation_cost_usd NUMERIC(10, 4) NOT NULL,
  validation_status TEXT NOT NULL DEFAULT 'pending'
    CHECK (validation_status IN ('pending', 'validated', 'failed_validation', 'manual_override')),
  -- {pre_patch_matches, post_patch_matches, semgrep_stderr, took_ms, ...}
  validation_log JSONB,
  enabled BOOLEAN NOT NULL DEFAULT true,
  -- Rollback history. Each entry: {rule_yaml, vulnerable_fixture, safe_fixture,
  -- generated_with_provider, generated_with_model, generated_at, replaced_at,
  -- replaced_by_user_id, validation_status}. Newest at index 0 (LIFO).
  previous_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
  generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at TIMESTAMPTZ,
  use_count INT NOT NULL DEFAULT 0,
  UNIQUE (organization_id, cve_id, package_purl)
);

ALTER TABLE organization_generated_rules ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS generated_rules_select ON organization_generated_rules;
CREATE POLICY generated_rules_select
  ON organization_generated_rules
  FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

DROP POLICY IF EXISTS generated_rules_modify ON organization_generated_rules;
CREATE POLICY generated_rules_modify
  ON organization_generated_rules
  FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE INDEX IF NOT EXISTS idx_ogr_org_enabled
  ON organization_generated_rules(organization_id, enabled);

CREATE INDEX IF NOT EXISTS idx_ogr_cve
  ON organization_generated_rules(cve_id);

CREATE INDEX IF NOT EXISTS idx_ogr_status
  ON organization_generated_rules(organization_id, validation_status);

COMMENT ON TABLE organization_generated_rules IS
  'Phase 25: AI-generated Semgrep reachability rules, owned per-org. Loaded into the extraction-worker''s rules dir alongside the platform-shipped 20.';

COMMENT ON COLUMN organization_generated_rules.previous_versions IS
  'Phase 25: rollback history for regenerate-with-different-model. Newest at index 0; rolling back swaps current row state with previous_versions[0].';

-- =============================================================================
-- 3. extraction_jobs telemetry columns
-- =============================================================================

ALTER TABLE extraction_jobs
  ADD COLUMN IF NOT EXISTS reachability_rules_matched INT,
  ADD COLUMN IF NOT EXISTS reachability_rules_total_detectable INT,
  ADD COLUMN IF NOT EXISTS reachability_rules_generated_this_scan INT,
  ADD COLUMN IF NOT EXISTS reachability_generation_cost_usd NUMERIC(10, 4);

COMMENT ON COLUMN extraction_jobs.reachability_rules_matched IS
  'Phase 25: count of CVEs in this scan matched by any reachability rule (platform 20 + org generated).';
COMMENT ON COLUMN extraction_jobs.reachability_rules_total_detectable IS
  'Phase 25: count of CVEs that COULD have been detectable if a rule existed (i.e. has OSV patch commit). Drives the autogrep coverage funnel.';
COMMENT ON COLUMN extraction_jobs.reachability_rules_generated_this_scan IS
  'Phase 25: count of new rules successfully validated and persisted during this scan.';
COMMENT ON COLUMN extraction_jobs.reachability_generation_cost_usd IS
  'Phase 25: total AI spend (USD) on rule generation during this scan. Sum of per-CVE generate.ts cost estimates.';
