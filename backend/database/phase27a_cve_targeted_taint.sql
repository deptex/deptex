-- Phase 6.5 — Cross-file CVE-targeted taint engine.
-- Repurposes organization_generated_rules to carry FrameworkSpec snippets
-- (new per-CVE format) alongside the legacy Semgrep YAML.
-- Adds per-flow suppression columns on project_reachable_flows.
-- Adds taint_engine_settings.cve_targeted_taint_enabled feature flag.
-- Bumps the AI cost cap default from $50 to $75 to accommodate the
-- extended fp-filter (structured triple) and the rewritten generator.
-- Validates osv_id consistency in framework_spec via JSONB CHECK.
--
-- Deployment ordering (mandatory): deploy new depscanner code → wait for ALL
-- Fly machines to roll over → apply phase27a → apply phase27b → deploy
-- frontend. Reverse order on revert.

-- 1. Drop NOT NULL on rule_yaml only (narrowed scope per architect-P1 review).
--    The new framework_spec generator (M2) STILL emits vulnerable_fixture +
--    safe_fixture for Gate 2 round-trip validation, so those columns stay
--    NOT NULL. Only rule_yaml goes nullable since framework_spec rows
--    legitimately have no Semgrep YAML body.
ALTER TABLE public.organization_generated_rules
  ALTER COLUMN rule_yaml DROP NOT NULL;

-- 1b. Pre-VALIDATE empty-string normalization (MSA-P1 review).
--     The Phase 5 generator wrote `rule_yaml: result.rule?.rule_yaml ?? ''`
--     on schema-fail rows. Step 3b's CASE treats empty string as NOT NULL →
--     classifies as 'semgrep_yaml', then VALIDATE on spec_shape_chk fails
--     because the row has empty rule_yaml. NULL out empty strings BEFORE the
--     backfill so they classify as framework_spec (which then fails the
--     CHECK because framework_spec is NULL — surfaces the bad row explicitly
--     instead of silently passing).
UPDATE public.organization_generated_rules
SET rule_yaml = NULL
WHERE rule_yaml = '';

-- 2. Add framework_spec column (nullable; populated by new generator path).
ALTER TABLE public.organization_generated_rules
  ADD COLUMN IF NOT EXISTS framework_spec jsonb;

COMMENT ON COLUMN public.organization_generated_rules.framework_spec IS
  'Phase 6.5 — FrameworkSpec JSON with osv_id-tagged sinks. Replaces rule_yaml for new generations. Old rows keep rule_yaml; new rows write framework_spec.';

-- 3. Add spec_format discriminator using safe three-step pattern (G1 / MSA-R2-1).
--    Step 3a: add nullable, no default, so legacy rows default-backfill correctly.
ALTER TABLE public.organization_generated_rules
  ADD COLUMN IF NOT EXISTS spec_format text;

--    Step 3b: backfill from existing data — semgrep_yaml if rule_yaml present,
--    framework_spec otherwise (covers any rows already pre-populated by tests).
UPDATE public.organization_generated_rules
SET spec_format = CASE
  WHEN rule_yaml IS NOT NULL THEN 'semgrep_yaml'
  ELSE 'framework_spec'
END
WHERE spec_format IS NULL;

--    Step 3c: lock down with default + NOT NULL + enum CHECK.
ALTER TABLE public.organization_generated_rules
  ALTER COLUMN spec_format SET DEFAULT 'framework_spec',
  ALTER COLUMN spec_format SET NOT NULL,
  ADD CONSTRAINT organization_generated_rules_spec_format_check
    CHECK (spec_format = ANY (ARRAY['semgrep_yaml'::text, 'framework_spec'::text]));

COMMENT ON COLUMN public.organization_generated_rules.spec_format IS
  'Either ''semgrep_yaml'' (legacy Phase 5) or ''framework_spec'' (Phase 6.5). New rows default to ''framework_spec''.';

-- 4. Exactly-one-spec-shape CHECK (DM-14). Prevents rows with NEITHER shape and
--    rows with the WRONG shape for their format discriminator. Added NOT VALID
--    so it doesn't have to scan the whole table; VALIDATE separately so any
--    pre-existing inconsistent row surfaces explicitly instead of silently
--    blocking the migration.
ALTER TABLE public.organization_generated_rules
  ADD CONSTRAINT organization_generated_rules_spec_shape_chk CHECK (
    (spec_format = 'semgrep_yaml' AND rule_yaml IS NOT NULL)
    OR (spec_format = 'framework_spec' AND framework_spec IS NOT NULL)
  ) NOT VALID;

ALTER TABLE public.organization_generated_rules
  VALIDATE CONSTRAINT organization_generated_rules_spec_shape_chk;

-- 5. JSONB CHECK enforcing every sink's osv_id matches the row's cve_id (Patch 5,
--    defense-in-depth alongside server-side substitution). Belt + suspenders so
--    a hallucinated osv_id from the model can't slip through the trust boundary.
--    Wrapped in an IMMUTABLE SQL helper because Postgres rejects subqueries
--    directly inside CHECK constraints (`cannot use subquery in check
--    constraint`) and `jsonb_array_elements` is a set-returning function that
--    requires a FROM-clause (i.e., a subquery) to iterate. The helper gets a
--    deterministic IMMUTABLE wrapper that the planner sees as a function call.
--    MSA-P1: the helper also guards `jsonb_array_elements(... -> 'sinks')`
--    against non-array values (JSONB `null`, `false`, `0`, `{}`) — calling
--    jsonb_array_elements on a non-array RAISES, which would block the CHECK
--    on otherwise-valid rows. The `jsonb_typeof(...) = 'array'` guard fires
--    first so we never feed a non-array to the SRF.
CREATE OR REPLACE FUNCTION public.framework_spec_osv_matches_cve(spec jsonb, cve text)
RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
AS $$
  SELECT
    spec IS NULL
    OR NOT (spec ? 'sinks')
    OR jsonb_typeof(spec -> 'sinks') IS DISTINCT FROM 'array'
    OR NOT EXISTS (
      SELECT 1
      FROM jsonb_array_elements(spec -> 'sinks') AS sink
      WHERE sink ? 'osv_id'
        AND (sink ->> 'osv_id') IS DISTINCT FROM cve
    );
$$;

COMMENT ON FUNCTION public.framework_spec_osv_matches_cve(jsonb, text) IS
  'Phase 6.5 helper for organization_generated_rules_framework_spec_osv_match_chk. Returns true when every sink in framework_spec.sinks[] has an osv_id matching the row''s cve_id (or the spec lacks a well-formed sinks array). IMMUTABLE so it can be referenced from a CHECK constraint.';

ALTER TABLE public.organization_generated_rules
  ADD CONSTRAINT organization_generated_rules_framework_spec_osv_match_chk
  CHECK (public.framework_spec_osv_matches_cve(framework_spec, cve_id))
  NOT VALID;

ALTER TABLE public.organization_generated_rules
  VALIDATE CONSTRAINT organization_generated_rules_framework_spec_osv_match_chk;

-- 6. Per-flow suppression — Option B (OD-4): stable-hash keyed in a separate
--    table. project_reachable_flows is fully derived (writeFlows wipe-and-rewrite
--    every extraction); user-state must NOT live on derived rows. Suppression key
--    is sha256(source_file:line || sink_file:line || sink_method || osv_id) so it
--    survives re-extraction across writeFlows churn.
--
--    flow_signature_hash also lives on project_reachable_flows (denormalized) so
--    classifier + EPD aggregator can JOIN cheaply without recomputing hash.
--    Computed at writeFlows time (M3 task 17 update); never trusted from API.
ALTER TABLE public.project_reachable_flows
  ADD COLUMN IF NOT EXISTS flow_signature_hash text;

CREATE TABLE IF NOT EXISTS public.project_reachable_flow_suppressions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  project_id uuid NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  flow_signature_hash text NOT NULL,
  suppressed_by uuid REFERENCES auth.users(id) ON DELETE SET NULL,
  -- ON DELETE SET NULL: a user removed from the org keeps the suppression they
  -- created (auth identity nulled but the suppression itself stays valid).
  -- Frontend M6 must render `suppressed_by IS NULL` as "former member" (NOT
  -- "system" — system-suppressions are a different feature). Mirror existing
  -- UI pattern from PDV suppression display.
  suppressed_at timestamp with time zone NOT NULL DEFAULT now(),
  suppressed_reason text,
  created_at timestamp with time zone NOT NULL DEFAULT now(),

  CONSTRAINT project_reachable_flow_suppressions_unique
    UNIQUE (project_id, flow_signature_hash)
);

ALTER TABLE public.project_reachable_flow_suppressions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "members_view_org_flow_suppressions"
  ON public.project_reachable_flow_suppressions FOR SELECT
  USING (organization_id IN (
    SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
  ));

CREATE POLICY "members_manage_org_flow_suppressions"
  ON public.project_reachable_flow_suppressions FOR ALL
  USING (organization_id IN (
    SELECT organization_id FROM public.organization_members WHERE user_id = auth.uid()
  ));

COMMENT ON TABLE public.project_reachable_flow_suppressions IS
  'Phase 6.5 — per-flow suppressions keyed on flow_signature_hash so user-state survives writeFlows wipe-and-rewrite. Resolution of Cluster D (Option B per OD-4).';

COMMENT ON COLUMN public.project_reachable_flows.flow_signature_hash IS
  'sha256(source_file:line || sink_file:line || sink_method || osv_id). Stable across re-extractions of the same logical flow. Computed at writeFlows time. Joins to project_reachable_flow_suppressions for user-state lookup.';

-- 7. Cost cap default raise: $50 → $75 (taint engine fp-filter triple).
--    Also bump the SEPARATE generator cost cap on organization_reachability_settings
--    (the two caps are independent; raising only one is a silent miscalibration of
--    the M7 acceptance "<$0.50 generator + fp-filter combined").
--    Defensive upper-bound CHECK (DM-R1-10): a fat-fingered admin setting
--    cap=10000 makes the gate effectively a no-op. Pin a sane ceiling.
ALTER TABLE public.taint_engine_settings
  ALTER COLUMN monthly_ai_cost_cap_usd SET DEFAULT 75.00;

ALTER TABLE public.taint_engine_settings
  ADD CONSTRAINT taint_engine_settings_cost_cap_sane
  CHECK (monthly_ai_cost_cap_usd >= 0 AND monthly_ai_cost_cap_usd <= 1000);

ALTER TABLE public.organization_reachability_settings
  ALTER COLUMN monthly_budget_usd SET DEFAULT 30.00;  -- was 10.00; raise to give the
                                                       -- generator headroom for the new
                                                       -- framework_spec output format
                                                       -- which takes longer to converge

-- 8. Per-org feature flag (Patch 9 / RB-1). Default ON preserves the cutover;
--    the lever exists when a customer org needs to opt out without a full
--    git revert. Worker reads at job-claim time (per-job, not per-machine —
--    Fly scale-to-zero means a stale machine boot cache would persist a flip).
--    Co-located on `taint_engine_settings` (existing per-org PK table that
--    already houses `enabled`, `ai_layer_enabled`, `monthly_ai_cost_cap_usd`,
--    `killswitch_active`).
ALTER TABLE public.taint_engine_settings
  ADD COLUMN IF NOT EXISTS cve_targeted_taint_enabled boolean NOT NULL DEFAULT true;

COMMENT ON COLUMN public.taint_engine_settings.cve_targeted_taint_enabled IS
  'Phase 6.5 — per-org kill switch for the cve-targeted taint pipeline (generator + osv-tagged engine + extended fp-filter + EPD aggregation). Default ON. Flip to false to disable for a single tenant without reverting the deploy.';

-- 9. RLS pass-through: project_reachable_flows existing policies cover the
--    new columns. organization_generated_rules existing policies cover
--    the new framework_spec column. taint_engine_settings policies already
--    cover any new boolean (per-org PK; existing RLS already filters by org).

-- 10. Cleanup: do NOT drop legacy spec columns (rule_yaml/vulnerable_fixture/
--     safe_fixture). They keep their data on legacy rows. Removing them is a
--     follow-up migration once we've confirmed every read site has migrated.
