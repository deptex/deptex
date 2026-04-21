-- Phase 19: Hybrid Atomic Commit (soft-switch findings + upsert deps)
--
-- Goal: replace the current delete-then-insert commit with a hybrid pattern:
--   - project_dependencies upserted by (project_id, name, version), UUIDs stable across re-extractions
--   - All findings tables soft-switched under extraction_run_id with atomic pointer flip on projects.active_extraction_run_id
--
-- This migration is purely additive — no breaking column changes, no data loss.
-- Existing pipeline.ts continues to function (writes to existing extraction_run_id columns where they exist).
-- Follow-up commits will: write commit_extraction RPC, refactor pipeline.ts to call it,
-- update read query sites to filter by active_extraction_run_id, build admin page.
--
-- See .cursor/plans/phase1-atomic-commit-design.md for full design rationale.
--
-- Note on terminology: keeping `extraction_run_id` (TEXT) to match the existing 4 tables
-- (project_semgrep_findings, project_secret_findings, project_reachable_flows, project_usage_slices)
-- rather than introducing a parallel `extraction_id UUID` concept that would force renames + frontend churn.

-- =============================================================================
-- 1. projects: pointer columns for soft-switch (atomic visibility flip)
-- =============================================================================
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS active_extraction_run_id TEXT,
  ADD COLUMN IF NOT EXISTS previous_extraction_run_id TEXT;

COMMENT ON COLUMN projects.active_extraction_run_id IS
  'Phase 19 soft-switch: which extraction run is currently visible to readers. Findings query WHERE extraction_run_id = projects.active_extraction_run_id. NULL = no completed extraction yet.';
COMMENT ON COLUMN projects.previous_extraction_run_id IS
  'Phase 19 soft-switch: prior visible generation, kept for backend-level rollback (manual SQL pointer flip). Reaper preserves this generation; no admin UI button in Phase 1.';

-- =============================================================================
-- 2. project_dependencies: soft-delete + run tracking
--    UUIDs stay stable across re-extractions (upsert pattern). Notes, watchtower
--    flags, ai_usage_summary all survive naturally because FKs don't change.
-- =============================================================================
ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS removed_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS last_seen_extraction_run_id TEXT;

-- Partial index for the common "current deps" read pattern
CREATE INDEX IF NOT EXISTS idx_project_dependencies_active
  ON project_dependencies(project_id)
  WHERE removed_at IS NULL;

COMMENT ON COLUMN project_dependencies.removed_at IS
  'Phase 19: soft-delete timestamp. NULL = present in latest extraction. Set when an extraction does not see this dep in the SBOM. Notes / fixes / watchtower flags survive removal.';
COMMENT ON COLUMN project_dependencies.last_seen_extraction_run_id IS
  'Phase 19: extraction_run_id that last confirmed this dep exists in the project SBOM. Used by the upsert step to determine which existing rows to mark removed.';

-- =============================================================================
-- 3. Findings tables that don't have extraction_run_id yet — add it
--    (project_semgrep_findings, project_secret_findings, project_reachable_flows,
--     project_usage_slices already have it from phase 6)
-- =============================================================================
ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;
CREATE INDEX IF NOT EXISTS idx_pdv_project_extraction_run
  ON project_dependency_vulnerabilities(project_id, extraction_run_id);

ALTER TABLE project_dependency_files
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;
-- project_dependency_files has no project_id — filter is via project_dependency_id FK
CREATE INDEX IF NOT EXISTS idx_pdf_dep_extraction_run
  ON project_dependency_files(project_dependency_id, extraction_run_id);

ALTER TABLE project_dependency_functions
  ADD COLUMN IF NOT EXISTS extraction_run_id TEXT;
-- project_dependency_functions has no project_id — filter is via project_dependency_id FK
CREATE INDEX IF NOT EXISTS idx_pdfn_dep_extraction_run
  ON project_dependency_functions(project_dependency_id, extraction_run_id);

-- =============================================================================
-- 3a. Update unique constraints to include extraction_run_id
--     Without this, two generations of the same finding (active + previous) would collide
--     during the reap window. NULLs are treated as distinct by default in Postgres UNIQUE,
--     so existing rows (extraction_run_id NULL) remain valid under the new constraint.
-- =============================================================================

-- project_dependency_vulnerabilities: (project_id, project_dependency_id, osv_id) → add extraction_run_id
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'project_dependency_vulnerabilities'::regclass
      AND contype = 'u'
      AND array_length(conkey, 1) = 3
  LOOP
    EXECUTE format('ALTER TABLE project_dependency_vulnerabilities DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE project_dependency_vulnerabilities
  DROP CONSTRAINT IF EXISTS pdv_extraction_run_unique;
ALTER TABLE project_dependency_vulnerabilities
  ADD CONSTRAINT pdv_extraction_run_unique
  UNIQUE (project_id, project_dependency_id, osv_id, extraction_run_id);

-- project_semgrep_findings: (project_id, rule_id, file_path, start_line) → add extraction_run_id
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'project_semgrep_findings'::regclass
      AND contype = 'u'
      AND array_length(conkey, 1) = 4
  LOOP
    EXECUTE format('ALTER TABLE project_semgrep_findings DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE project_semgrep_findings
  DROP CONSTRAINT IF EXISTS psemf_extraction_run_unique;
ALTER TABLE project_semgrep_findings
  ADD CONSTRAINT psemf_extraction_run_unique
  UNIQUE (project_id, rule_id, file_path, start_line, extraction_run_id);

-- project_secret_findings: (project_id, detector_type, file_path, start_line) → add extraction_run_id
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'project_secret_findings'::regclass
      AND contype = 'u'
      AND array_length(conkey, 1) = 4
  LOOP
    EXECUTE format('ALTER TABLE project_secret_findings DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE project_secret_findings
  DROP CONSTRAINT IF EXISTS psecf_extraction_run_unique;
ALTER TABLE project_secret_findings
  ADD CONSTRAINT psecf_extraction_run_unique
  UNIQUE (project_id, detector_type, file_path, start_line, extraction_run_id);

-- project_usage_slices: (project_id, file_path, line_number, target_name) → add extraction_run_id
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'project_usage_slices'::regclass
      AND contype = 'u'
      AND array_length(conkey, 1) = 4
  LOOP
    EXECUTE format('ALTER TABLE project_usage_slices DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE project_usage_slices
  DROP CONSTRAINT IF EXISTS pus_extraction_run_unique;
ALTER TABLE project_usage_slices
  ADD CONSTRAINT pus_extraction_run_unique
  UNIQUE (project_id, file_path, line_number, target_name, extraction_run_id);

-- project_dependency_functions: (project_dependency_id, function_name) → add extraction_run_id
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'project_dependency_functions'::regclass
      AND contype = 'u'
      AND array_length(conkey, 1) = 2
  LOOP
    EXECUTE format('ALTER TABLE project_dependency_functions DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE project_dependency_functions
  DROP CONSTRAINT IF EXISTS pdfn_extraction_run_unique;
ALTER TABLE project_dependency_functions
  ADD CONSTRAINT pdfn_extraction_run_unique
  UNIQUE (project_dependency_id, function_name, extraction_run_id);

-- project_dependency_files: (project_dependency_id, file_path) → add extraction_run_id
DO $$
DECLARE c RECORD;
BEGIN
  FOR c IN
    SELECT conname FROM pg_constraint
    WHERE conrelid = 'project_dependency_files'::regclass
      AND contype = 'u'
      AND array_length(conkey, 1) = 2
  LOOP
    EXECUTE format('ALTER TABLE project_dependency_files DROP CONSTRAINT %I', c.conname);
  END LOOP;
END $$;
ALTER TABLE project_dependency_files
  DROP CONSTRAINT IF EXISTS pdf_extraction_run_unique;
ALTER TABLE project_dependency_files
  ADD CONSTRAINT pdf_extraction_run_unique
  UNIQUE (project_dependency_id, file_path, extraction_run_id);

-- project_reachable_flows already has extraction_run_id in its UNIQUE constraint (from phase6b)

-- =============================================================================
-- 4. Composite indexes on the existing extraction_run_id tables
--    (existing single-column indexes don't help for the (project_id, extraction_run_id) filter pattern)
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_psemf_project_extraction_run
  ON project_semgrep_findings(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_psecf_project_extraction_run
  ON project_secret_findings(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_prf_project_extraction_run
  ON project_reachable_flows(project_id, extraction_run_id);
CREATE INDEX IF NOT EXISTS idx_pus_project_extraction_run
  ON project_usage_slices(project_id, extraction_run_id);

-- =============================================================================
-- 5. extraction_step_errors: structured per-step failure logging
--    severity=warn means pipeline continued (graceful degradation);
--    severity=error means pipeline halted.
-- =============================================================================
CREATE TABLE IF NOT EXISTS extraction_step_errors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  extraction_job_id UUID NOT NULL REFERENCES extraction_jobs(id) ON DELETE CASCADE,
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  step TEXT NOT NULL,
  code TEXT NOT NULL,
  message TEXT NOT NULL,
  stack TEXT,
  machine_id TEXT,
  duration_ms INTEGER,
  severity TEXT NOT NULL DEFAULT 'error',
  created_at TIMESTAMPTZ DEFAULT NOW(),
  CONSTRAINT chk_extraction_step_errors_severity CHECK (severity IN ('warn', 'error'))
);

CREATE INDEX IF NOT EXISTS idx_extraction_step_errors_created
  ON extraction_step_errors(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_extraction_step_errors_step_code
  ON extraction_step_errors(step, code);
CREATE INDEX IF NOT EXISTS idx_extraction_step_errors_project_created
  ON extraction_step_errors(project_id, created_at DESC);

ALTER TABLE extraction_step_errors ENABLE ROW LEVEL SECURITY;

-- Service role only for now — admin page reads via service-role client.
-- Org-scoped read policy can be added later when there's an org-facing surface.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_policies
    WHERE schemaname = 'public'
      AND tablename = 'extraction_step_errors'
      AND policyname = 'Service role manages extraction_step_errors'
  ) THEN
    CREATE POLICY "Service role manages extraction_step_errors"
      ON extraction_step_errors FOR ALL USING (true) WITH CHECK (true);
  END IF;
END $$;

COMMENT ON TABLE extraction_step_errors IS
  'Phase 19: structured per-step extraction failure log. severity=warn means pipeline continued (graceful degradation, e.g. atom OOM); severity=error means pipeline halted. Surfaced in /admin/extraction-failures.';
COMMENT ON COLUMN extraction_step_errors.step IS
  'Pipeline step name: clone | dep_resolution | sbom | tree_sitter | dep_scan | atom | joern | semgrep | trufflehog | iac_container | ai_stitching | epd | commit | ...';
COMMENT ON COLUMN extraction_step_errors.code IS
  'Structured error code: timeout | oom | subprocess_failed | parse_error | fk_violation | network_error | rule_parse_error | unexpected | ...';
