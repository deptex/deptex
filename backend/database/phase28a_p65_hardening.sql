-- Phase 6.5 hardening — fixes P0/P1 issues from /criticalreview 12.

-- 1. Roll back spec_format DEFAULT to 'semgrep_yaml' for cutover safety.
--    Old depscanner machines mid-cutover INSERT rule_yaml without
--    framework_spec; with DEFAULT 'framework_spec', spec_shape_chk rejects
--    every legacy INSERT during the rollover window. Flip back to
--    'framework_spec' in a follow-up migration AFTER old depscanner is
--    provably retired (30d window per OD-2).
ALTER TABLE public.organization_generated_rules
  ALTER COLUMN spec_format SET DEFAULT 'semgrep_yaml';

-- 2. Re-add taint_engine_settings_cost_cap_sane CHECK with NOT VALID + manual
--    VALIDATE so the migration doesn't abort if any prod row already has
--    cap > 1000 (the COST_CAP_MAX_USD clamp was new in this PR; legacy admin
--    settings were uncapped).
ALTER TABLE public.taint_engine_settings
  DROP CONSTRAINT IF EXISTS taint_engine_settings_cost_cap_sane;

UPDATE public.taint_engine_settings
SET monthly_ai_cost_cap_usd = 1000
WHERE monthly_ai_cost_cap_usd > 1000;

ALTER TABLE public.taint_engine_settings
  ADD CONSTRAINT taint_engine_settings_cost_cap_sane
  CHECK (monthly_ai_cost_cap_usd >= 0 AND monthly_ai_cost_cap_usd <= 1000)
  NOT VALID;

ALTER TABLE public.taint_engine_settings
  VALIDATE CONSTRAINT taint_engine_settings_cost_cap_sane;

-- 3. Add Anthropic-fallback feature to get_taint_engine_monthly_spend RPC's
--    accepted feature set so per-PDV cap re-check sees fallback spend.
--    Mirror the existing RPC's column choices: estimated_cost, success=true,
--    UTC date_trunc.
CREATE OR REPLACE FUNCTION public.get_taint_engine_monthly_spend(p_organization_id uuid)
 RETURNS numeric
 LANGUAGE sql
 STABLE
AS $function$
  SELECT COALESCE(SUM(estimated_cost), 0)::numeric
  FROM public.ai_usage_logs
  WHERE organization_id = p_organization_id
    AND success = true
    AND feature IN (
      'taint_engine_spec_inference',
      'taint_engine_fp_filter',
      'taint_engine_anthropic_fallback'
    )
    AND created_at >= date_trunc('month', now() AT TIME ZONE 'UTC');
$function$;

GRANT EXECUTE ON FUNCTION public.get_taint_engine_monthly_spend(uuid) TO service_role;

-- 4. Tenant-integrity trigger on project_reachable_flow_suppressions.
--    Asserts organization_id matches projects.organization_id at INSERT/UPDATE
--    time. Belt-and-braces against route-side bugs (the cross-tenant POST
--    path was the consensus P0 from /criticalreview).
CREATE OR REPLACE FUNCTION public.assert_flow_suppression_tenant()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
  actual_org uuid;
BEGIN
  SELECT organization_id INTO actual_org
  FROM public.projects
  WHERE id = NEW.project_id;

  IF actual_org IS NULL THEN
    RAISE EXCEPTION 'project % does not exist', NEW.project_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;

  IF actual_org <> NEW.organization_id THEN
    RAISE EXCEPTION 'organization_id % does not own project % (actual: %)',
      NEW.organization_id, NEW.project_id, actual_org
      USING ERRCODE = 'check_violation';
  END IF;

  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS project_reachable_flow_suppressions_tenant_check
  ON public.project_reachable_flow_suppressions;

CREATE TRIGGER project_reachable_flow_suppressions_tenant_check
  BEFORE INSERT OR UPDATE ON public.project_reachable_flow_suppressions
  FOR EACH ROW
  EXECUTE FUNCTION public.assert_flow_suppression_tenant();
