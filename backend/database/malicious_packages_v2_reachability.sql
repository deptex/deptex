-- =============================================================================
-- Malicious Packages v2: reachability columns on project_malicious_findings
-- =============================================================================
-- Adds the per-finding reachability resolution surface:
--   reachability_level     ∈ {unimported, imported_unused, module, function, NULL}
--   reachability_details   JSONB (entry_points / call_chain / sink_file / sink_line)
--   reachability_computed_at  populated when level is set; NULL if soft-failed.
-- Also relaxes the scanner CHECK to admit 'maintainer' (M1c finding source).
-- The v1 scanner CHECK was declared inline (anonymous); look up the actual
-- name dynamically so DROP CONSTRAINT IF EXISTS isn't a silent no-op when
-- the auto-generated name differs between PGLite and Postgres.
-- =============================================================================

ALTER TABLE public.project_malicious_findings
  ADD COLUMN IF NOT EXISTS reachability_level text,
  ADD COLUMN IF NOT EXISTS reachability_details jsonb,
  ADD COLUMN IF NOT EXISTS reachability_computed_at timestamptz;

DO $$
DECLARE
  v_constraint_name text;
BEGIN
  SELECT conname INTO v_constraint_name
  FROM pg_constraint c
  JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY(c.conkey)
  WHERE c.conrelid = 'public.project_malicious_findings'::regclass
    AND c.contype = 'c'
    AND a.attname = 'scanner'
  LIMIT 1;
  IF v_constraint_name IS NOT NULL THEN
    EXECUTE format('ALTER TABLE public.project_malicious_findings DROP CONSTRAINT %I', v_constraint_name);
  END IF;
END $$;

ALTER TABLE public.project_malicious_findings
  ADD CONSTRAINT project_malicious_findings_scanner_check
  CHECK (scanner IN ('feed','guarddog','maintainer'));

-- Idempotent guard so repeat applies don't error on existing constraint
ALTER TABLE public.project_malicious_findings
  DROP CONSTRAINT IF EXISTS project_malicious_findings_reachability_chk;
ALTER TABLE public.project_malicious_findings
  ADD CONSTRAINT project_malicious_findings_reachability_chk
  CHECK (reachability_level IS NULL OR
         reachability_level IN ('unimported','imported_unused','module','function'));

-- Partial index for the filter-by-reachability hot path (UI filter pill +
-- API ?reachability= query param). Only includes findings the user can act
-- on (not suppressed, not risk-accepted).
CREATE INDEX IF NOT EXISTS idx_pmf_reachability
  ON public.project_malicious_findings (project_id, reachability_level)
  WHERE suppressed = false AND risk_accepted = false;

COMMENT ON COLUMN public.project_malicious_findings.reachability_level IS
  'Malicious v2: lightweight per-package reachability classification computed at scan time. Self-contained — does not depend on Phase 6 taint engine.';
COMMENT ON COLUMN public.project_malicious_findings.reachability_details IS
  'Malicious v2: { entry_points?: string[], call_chain?: string[], sink_file?: string, sink_line?: number, error?: string }';
