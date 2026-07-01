-- phase69: Aegis Task — support every finding type, not just the first three.
--
-- The Aegis "task" agent (plan-then-execute fix loop) was limited to
-- vulnerability / semgrep / secret findings. This widens the fix ledger to
-- cover the rest of what the scanner surfaces — IaC misconfigs, container
-- OS-CVEs, base-image recommendations, reachable taint flows (dataflow), and
-- DAST findings — and adds a per-type finding-id column for each (mirroring the
-- existing osv_id / semgrep_finding_id / secret_finding_id / malicious_finding_id
-- pattern).
--
-- Strategies added:
--   fix_iac           — minimal edit to the offending IaC block (file:line)
--   bump_base_image   — deterministic FROM-line bump in a Dockerfile
--                       (used by both base_image recommendations and container
--                        OS-CVEs, which are only fixable by moving the image)
--   sanitize_dataflow — insert a sanitizer along a reachable taint path
--   patch_handler     — patch the vulnerable DAST endpoint handler

BEGIN;

-- 1. Allow the five new fix_type values.
ALTER TABLE public.project_security_fixes
  DROP CONSTRAINT IF EXISTS project_security_fixes_fix_type_check;
ALTER TABLE public.project_security_fixes
  ADD CONSTRAINT project_security_fixes_fix_type_check
  CHECK (fix_type = ANY (ARRAY[
    'vulnerability'::text,
    'semgrep'::text,
    'secret'::text,
    'iac'::text,
    'container'::text,
    'base_image'::text,
    'dataflow'::text,
    'dast'::text
  ]));

-- 2. Allow the four new strategy values.
ALTER TABLE public.project_security_fixes
  DROP CONSTRAINT IF EXISTS project_security_fixes_strategy_check;
ALTER TABLE public.project_security_fixes
  ADD CONSTRAINT project_security_fixes_strategy_check
  CHECK (strategy = ANY (ARRAY[
    'bump_version'::text,
    'code_patch'::text,
    'add_wrapper'::text,
    'pin_transitive'::text,
    'remove_unused'::text,
    'fix_semgrep'::text,
    'remediate_secret'::text,
    'fix_iac'::text,
    'bump_base_image'::text,
    'sanitize_dataflow'::text,
    'patch_handler'::text
  ]));

-- 3. Per-type finding-id columns (nullable; exactly one is set per fix row,
--    chosen by fixTypeColumn(findingType) in backend/src/lib/aegis-v3/fix-request.ts).
--    dataflow keys on reachable_flow_id (a project_reachable_flows row) and also
--    carries osv_id for the CVE it neutralises.
ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS iac_finding_id      uuid,
  ADD COLUMN IF NOT EXISTS container_finding_id uuid,
  ADD COLUMN IF NOT EXISTS base_image_rec_id   uuid,
  ADD COLUMN IF NOT EXISTS dast_finding_id     uuid,
  ADD COLUMN IF NOT EXISTS reachable_flow_id   uuid;

COMMIT;

-- Note: finding_tracker_links.finding_type already allows
-- iac / container / dast / taint_flow / malicious, so no change there. The
-- backend maps dataflow -> 'taint_flow' and base_image -> 'container' at the
-- tracker-link upsert boundary (tasks.ts) to satisfy that existing constraint.
