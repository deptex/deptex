-- ============================================================================
-- Rollback for phase28c_container_reachability_advisor.sql
-- ============================================================================

DROP FUNCTION IF EXISTS public.cleanup_dismissed_base_image_recommendations(INTEGER);

DROP INDEX IF EXISTS public.idx_pcf_reachability;

ALTER TABLE public.project_container_findings
  DROP COLUMN IF EXISTS reachability_details,
  DROP COLUMN IF EXISTS reachability_level;

DROP TRIGGER IF EXISTS pbir_set_org_id ON public.project_base_image_recommendations;
DROP FUNCTION IF EXISTS public.enforce_pbir_org_scope();
DROP TABLE IF EXISTS public.project_base_image_recommendations;
