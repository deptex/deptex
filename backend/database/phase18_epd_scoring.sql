-- Phase 18: Execution Path Dominance (EPD) scoring fields
-- Keeps legacy depscore while introducing contextual scoring primitives.

ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS base_depscore_no_reachability NUMERIC(6,2),
  ADD COLUMN IF NOT EXISTS epd_factor NUMERIC(10,6),
  ADD COLUMN IF NOT EXISTS contextual_depscore NUMERIC(10,4),
  ADD COLUMN IF NOT EXISTS reachability_status TEXT DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS entry_point_classification TEXT,
  ADD COLUMN IF NOT EXISTS entry_point_weight NUMERIC(5,3),
  ADD COLUMN IF NOT EXISTS epd_depth INTEGER,
  ADD COLUMN IF NOT EXISTS epd_alpha NUMERIC(5,3) DEFAULT 0.85,
  ADD COLUMN IF NOT EXISTS sink_precondition TEXT,
  ADD COLUMN IF NOT EXISTS sanitization_postcondition TEXT,
  ADD COLUMN IF NOT EXISTS is_sanitized BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS epd_confidence_tier TEXT,
  ADD COLUMN IF NOT EXISTS epd_model TEXT,
  ADD COLUMN IF NOT EXISTS epd_schema_version TEXT,
  ADD COLUMN IF NOT EXISTS epd_prompt_version TEXT,
  ADD COLUMN IF NOT EXISTS epd_status TEXT DEFAULT 'pending';

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_pdv_reachability_status'
  ) THEN
    ALTER TABLE project_dependency_vulnerabilities
      ADD CONSTRAINT chk_pdv_reachability_status
      CHECK (reachability_status IN ('reachable', 'unreachable', 'unknown'));
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1
    FROM pg_constraint
    WHERE conname = 'chk_pdv_epd_confidence_tier'
  ) THEN
    ALTER TABLE project_dependency_vulnerabilities
      ADD CONSTRAINT chk_pdv_epd_confidence_tier
      CHECK (epd_confidence_tier IS NULL OR epd_confidence_tier IN ('high', 'medium', 'low'));
  END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_pdv_project_reachability_contextual
  ON project_dependency_vulnerabilities(project_id, reachability_status, contextual_depscore DESC);

CREATE INDEX IF NOT EXISTS idx_pdv_project_epd_confidence
  ON project_dependency_vulnerabilities(project_id, epd_confidence_tier);

COMMENT ON COLUMN project_dependency_vulnerabilities.base_depscore_no_reachability IS
  'Base risk score excluding reachability weighting. Keeps CVSS/EPSS/KEV/tier/dependency context.';
COMMENT ON COLUMN project_dependency_vulnerabilities.epd_factor IS
  'Execution Path Dominance factor in [0,1], derived from entry-point weight and attenuation by path depth.';
COMMENT ON COLUMN project_dependency_vulnerabilities.contextual_depscore IS
  'Contextualized vulnerability score calculated as base_depscore_no_reachability * epd_factor.';
COMMENT ON COLUMN project_dependency_vulnerabilities.reachability_status IS
  'Explicit reachability state for triage and reporting: reachable, unreachable, or unknown.';
COMMENT ON COLUMN project_dependency_vulnerabilities.epd_status IS
  'Operational status of EPD scoring for this vulnerability (e.g., pending, fallback_no_ai, byok_missing, budget_exceeded).';
