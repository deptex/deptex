-- Phase 26: Cross-File Taint Engine
--
-- Adds per-extraction telemetry (taint_engine_runs), per-org settings with
-- killswitch, and an org-scoped framework_models cache for AI-inferred
-- specs (M6 will populate). Extends the project_reachable_flows
-- reachability_source CHECK constraint to admit 'taint_engine' so the
-- engine writes flows into the same table atom uses, picked up unchanged
-- by updateReachabilityLevels().
--
-- Numbering: phase26 (Phase 5 has phase23-25 staged on its own worktree;
-- this leaves room for those to merge first).

-- 1. Extend reachability_source CHECK on project_reachable_flows
ALTER TABLE project_reachable_flows
  DROP CONSTRAINT IF EXISTS project_reachable_flows_reachability_source_check;
ALTER TABLE project_reachable_flows
  ADD CONSTRAINT project_reachable_flows_reachability_source_check
  CHECK (reachability_source IN ('atom', 'semgrep_taint', 'taint_engine'));

-- 2. taint_engine_runs — per-extraction telemetry, used by circuit breaker
CREATE TABLE IF NOT EXISTS taint_engine_runs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'aborted', 'skipped')),
  callgraph_build_ms INTEGER,
  taint_propagation_ms INTEGER,
  ai_spec_inference_ms INTEGER,
  ai_fp_filter_ms INTEGER,
  total_ms INTEGER,
  flows_emitted INTEGER DEFAULT 0,
  flows_after_ai_filter INTEGER DEFAULT 0,
  ai_cost_usd NUMERIC(10, 6) DEFAULT 0,
  frameworks_detected TEXT[] DEFAULT '{}',
  framework_models_used JSONB DEFAULT '{}',
  is_typed_js_project BOOLEAN,
  typed_files_pct NUMERIC(5, 2),
  vuln_classes_evaluated TEXT[] DEFAULT '{}',
  error_code TEXT,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  completed_at TIMESTAMPTZ,
  UNIQUE(project_id, extraction_run_id)
);

CREATE INDEX IF NOT EXISTS idx_ter_org_created ON taint_engine_runs(organization_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ter_project_extraction ON taint_engine_runs(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_ter_status_created ON taint_engine_runs(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ter_failed_recent ON taint_engine_runs(created_at DESC)
  WHERE status = 'failed';

-- 3. taint_engine_framework_models — AI-inferred specs cached per (org, framework, version)
CREATE TABLE IF NOT EXISTS taint_engine_framework_models (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  framework_name TEXT NOT NULL,
  framework_version TEXT NOT NULL DEFAULT '*',
  source_type TEXT NOT NULL CHECK (source_type IN ('hand_written', 'ai_inferred', 'user_edited')),
  spec JSONB NOT NULL,
  inferred_at TIMESTAMPTZ DEFAULT NOW(),
  inferred_by_model TEXT,
  inferred_cost_usd NUMERIC(10, 6),
  edited_by_user_id UUID REFERENCES auth.users(id),
  edited_at TIMESTAMPTZ,
  last_validated_at TIMESTAMPTZ,
  validation_score NUMERIC(5, 2),
  is_active BOOLEAN DEFAULT true,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, framework_name, framework_version)
);

CREATE INDEX IF NOT EXISTS idx_temf_org_active ON taint_engine_framework_models(organization_id, is_active);
CREATE INDEX IF NOT EXISTS idx_temf_framework ON taint_engine_framework_models(framework_name);

-- 4. taint_engine_settings — per-org config
CREATE TABLE IF NOT EXISTS taint_engine_settings (
  organization_id UUID PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  enabled BOOLEAN DEFAULT true,
  ai_layer_enabled BOOLEAN DEFAULT true,
  monthly_ai_cost_cap_usd NUMERIC(10, 2) DEFAULT 50.00,
  untyped_js_enabled BOOLEAN DEFAULT true,
  vuln_classes_enabled TEXT[] DEFAULT ARRAY[
    'sql_injection', 'ssrf', 'xss', 'path_traversal', 'command_injection',
    'prototype_pollution', 'deserialization', 'redos', 'file_upload',
    'open_redirect', 'log_injection'
  ],
  killswitch_active BOOLEAN DEFAULT false,
  killswitch_reason TEXT,
  killswitch_activated_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- No RLS — backend service-role mediated, same as project_reachable_flows
-- per phase6b_reachability_tables.sql convention.

-- 5. Helper RPC: check circuit breaker state (called by worker before each run)
CREATE OR REPLACE FUNCTION check_taint_engine_circuit_breaker(
  p_organization_id UUID,
  p_window_minutes INTEGER DEFAULT 60,
  p_failure_threshold_pct NUMERIC DEFAULT 5.0
) RETURNS TABLE(should_run BOOLEAN, recent_runs INT, recent_failures INT, failure_pct NUMERIC, killswitch_active BOOLEAN) AS $$
DECLARE
  v_killswitch BOOLEAN;
  v_recent_runs INT;
  v_recent_failures INT;
  v_failure_pct NUMERIC;
BEGIN
  -- Manual or auto-engaged killswitch
  SELECT s.killswitch_active INTO v_killswitch
  FROM taint_engine_settings s
  WHERE s.organization_id = p_organization_id;
  v_killswitch := COALESCE(v_killswitch, false);

  -- Failure rate over rolling window
  SELECT
    COUNT(*),
    COUNT(*) FILTER (WHERE r.status = 'failed')
  INTO v_recent_runs, v_recent_failures
  FROM taint_engine_runs r
  WHERE r.organization_id = p_organization_id
    AND r.created_at > NOW() - (p_window_minutes || ' minutes')::INTERVAL;

  v_failure_pct := CASE
    WHEN v_recent_runs > 0 THEN (v_recent_failures::NUMERIC / v_recent_runs * 100)
    ELSE 0
  END;

  RETURN QUERY SELECT
    NOT v_killswitch AND (v_recent_runs < 5 OR v_failure_pct < p_failure_threshold_pct),
    v_recent_runs,
    v_recent_failures,
    v_failure_pct,
    v_killswitch;
END;
$$ LANGUAGE plpgsql;

-- 6. Auto-engage killswitch when failure threshold tripped
CREATE OR REPLACE FUNCTION engage_taint_engine_killswitch(
  p_organization_id UUID,
  p_reason TEXT
) RETURNS VOID AS $$
BEGIN
  INSERT INTO taint_engine_settings (organization_id, killswitch_active, killswitch_reason, killswitch_activated_at)
  VALUES (p_organization_id, true, p_reason, NOW())
  ON CONFLICT (organization_id) DO UPDATE
  SET killswitch_active = true,
      killswitch_reason = EXCLUDED.killswitch_reason,
      killswitch_activated_at = NOW();
END;
$$ LANGUAGE plpgsql;
