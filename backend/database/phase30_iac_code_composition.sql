-- Phase 30: Composed IaC↔Code Reachability (Item G).
--
-- Pairs container OS-package reachability (PCF, written by doIaCContainer)
-- with code-side call-graph reachability (PDV, written by Phase 6 + EPD)
-- across a shared SONAME bridge. The bridge is computed at scan time by
-- the new native-bindings extractor and persisted in
-- `project_native_bindings`. Confirmed pairs are written to
-- `project_composition_partners`. The per-PDV minimum composition factor
-- is folded back into PDV.contextual_depscore so the existing Security
-- tab ORDER BY contextual_depscore automatically reflects composition
-- without any UI changes.
--
-- Sole-writer invariant inside the depscanner pipeline:
-- after doReachabilityAndEpd, only composition.ts mutates contextual_depscore.
-- See depscanner/src/__tests__/contextual-depscore-writers.test.ts.

-- ============================================================
-- project_native_bindings — SONAME bridge rows
-- ============================================================
-- Two scopes:
--   'language' rows = a language-managed package (Python wheel,
--     Node native module) installed somewhere on disk that ships an ELF
--     whose DT_NEEDED entry names a SONAME.
--   'os' rows = an OS package (currently dpkg-only) that ships an ELF
--     whose DT_SONAME identifies it under that name.
-- Composition pairs them by exact-string soname match.

CREATE TABLE IF NOT EXISTS public.project_native_bindings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,

  scope TEXT NOT NULL CHECK (scope IN ('language', 'os')),
  package_identifier TEXT NOT NULL,
  package_ecosystem TEXT,
  soname TEXT NOT NULL,
  -- Sentinel '' avoids the UNIQUE-with-NULL gotcha (NULL is never equal
  -- to NULL in UNIQUE indexes, so two NULL install_paths would not dedup).
  install_path TEXT NOT NULL DEFAULT '',
  link_method TEXT NOT NULL CHECK (link_method IN (
    'elf_needed',     -- v1 language side
    'dpkg_soname',    -- v1 OS side
    'elf_dlopen',     -- v2 reserved
    'ctypes_grep',    -- v2 reserved
    'apk_provided',   -- v2 reserved
    'rpm_provided'    -- v2 reserved
  )),

  extractor_version TEXT NOT NULL DEFAULT 'v1',
  discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (extraction_run_id, scope, package_identifier, soname, install_path)
);

CREATE INDEX IF NOT EXISTS idx_pnb_run_language_pkg
  ON public.project_native_bindings(extraction_run_id, package_identifier)
  WHERE scope = 'language';
CREATE INDEX IF NOT EXISTS idx_pnb_run_os_pkg
  ON public.project_native_bindings(extraction_run_id, package_identifier)
  WHERE scope = 'os';
CREATE INDEX IF NOT EXISTS idx_pnb_run_soname
  ON public.project_native_bindings(extraction_run_id, soname text_pattern_ops);

DROP TRIGGER IF EXISTS project_native_bindings_enforce_org_id ON public.project_native_bindings;
CREATE TRIGGER project_native_bindings_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON public.project_native_bindings
  FOR EACH ROW EXECUTE FUNCTION public.enforce_finding_org_id();

-- ============================================================
-- project_composition_partners — confirmed PCF×PDV edges
-- ============================================================
-- One row per (container_finding × pdv) edge. PDV.composition_factor is
-- the per-PDV MIN(composition_factor) across this row's edges; the join
-- table keeps every edge for forensics + future UI breakdown.

CREATE TABLE IF NOT EXISTS public.project_composition_partners (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES public.projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  extraction_run_id TEXT NOT NULL,

  container_finding_id UUID NOT NULL REFERENCES public.project_container_findings(id) ON DELETE CASCADE,
  pdv_id UUID NOT NULL REFERENCES public.project_dependency_vulnerabilities(id) ON DELETE CASCADE,

  container_reachability_multiplier NUMERIC(4,3) NOT NULL,
  code_reachability_multiplier NUMERIC(4,3) NOT NULL,
  composition_factor NUMERIC(4,3) NOT NULL,
  -- composed_depscore omitted in v1 (no UI consumer); compute at read
  -- time when frontend follow-up surfaces side-by-side.

  bindings_evidence JSONB NOT NULL,
    -- Locked typed shape (max 20 entries):
    -- [{ soname: string, link_method: 'elf_needed' | 'dpkg_soname',
    --    language_install_path?: string, os_install_path?: string,
    --    extractor_version: string }]
    -- composition.ts emits this contract; frontend follow-up consumes it.

  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  UNIQUE (extraction_run_id, container_finding_id, pdv_id)
);

CREATE INDEX IF NOT EXISTS idx_pcp_run_pcf
  ON public.project_composition_partners(extraction_run_id, container_finding_id);
CREATE INDEX IF NOT EXISTS idx_pcp_run_pdv
  ON public.project_composition_partners(extraction_run_id, pdv_id);
-- Supports the MIN(composition_factor) per-PDV aggregation at compose time.
CREATE INDEX IF NOT EXISTS idx_pcp_pdv_factor
  ON public.project_composition_partners(pdv_id, composition_factor);

DROP TRIGGER IF EXISTS project_composition_partners_enforce_org_id ON public.project_composition_partners;
CREATE TRIGGER project_composition_partners_enforce_org_id
  BEFORE INSERT OR UPDATE OF project_id, organization_id ON public.project_composition_partners
  FOR EACH ROW EXECUTE FUNCTION public.enforce_finding_org_id();

-- Cross-project edge protection: the PCF and PDV referenced by a partner
-- row must both live in the row's project_id. Defends against a caller
-- forging cross-tenant pairs.
CREATE OR REPLACE FUNCTION public.enforce_composition_same_project() RETURNS TRIGGER AS $$
DECLARE
  pcf_project UUID;
  pdv_project UUID;
BEGIN
  SELECT project_id INTO pcf_project FROM public.project_container_findings WHERE id = NEW.container_finding_id;
  SELECT project_id INTO pdv_project FROM public.project_dependency_vulnerabilities WHERE id = NEW.pdv_id;
  IF pcf_project IS NULL OR pdv_project IS NULL THEN
    RAISE EXCEPTION 'composition partner finding not found (pcf=% pdv=%)', NEW.container_finding_id, NEW.pdv_id;
  END IF;
  IF pcf_project != pdv_project OR pcf_project != NEW.project_id THEN
    RAISE EXCEPTION 'composition partner findings must belong to same project';
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;  -- NOT SECURITY DEFINER — runs under caller's role.

DROP TRIGGER IF EXISTS project_composition_partners_enforce_same_project ON public.project_composition_partners;
CREATE TRIGGER project_composition_partners_enforce_same_project
  BEFORE INSERT OR UPDATE OF container_finding_id, pdv_id, project_id ON public.project_composition_partners
  FOR EACH ROW EXECUTE FUNCTION public.enforce_composition_same_project();

-- ============================================================
-- PDV.composition_factor — per-PDV MIN folded multiplier (NULL = unpaired)
-- ============================================================
-- Existing rows stay NULL; composeFindings writes the per-PDV MIN
-- across that PDV's edges. NULL preserves contextual_depscore
-- bit-identically (the RPC does not multiply when factor is NULL — the
-- multiply only happens inside apply_composition_results, which only
-- runs for PDVs that DO have at least one partner).

ALTER TABLE public.project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS composition_factor NUMERIC(4,3);

-- ============================================================
-- apply_composition_results — atomic multi-row UPDATE via JSONB payload
-- ============================================================
-- supabase-js cannot express `UPDATE ... FROM (VALUES ...)` shape, and a
-- per-PDV `.update().eq()` loop would be N round-trips with no
-- atomicity. This RPC accepts a JSONB array of {pdv_id, factor} pairs
-- (JS pre-aggregates MIN per PDV) and applies the UPDATE in one
-- statement, gated on (project_id, extraction_run_id) so a tampered
-- payload cannot touch another tenant or another scan's rows.

CREATE OR REPLACE FUNCTION public.apply_composition_results(
  p_project_id uuid,
  p_run_id text,
  p_updates jsonb
)
RETURNS integer  -- count of PDV rows updated
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  updated_count integer;
BEGIN
  WITH updates AS (
    SELECT (e->>'pdv_id')::uuid  AS pdv_id,
           (e->>'factor')::numeric AS factor
      FROM jsonb_array_elements(p_updates) e
  ),
  result AS (
    UPDATE public.project_dependency_vulnerabilities pdv
       SET composition_factor = u.factor,
           contextual_depscore = ROUND(pdv.contextual_depscore * u.factor, 4)
      FROM updates u
     WHERE pdv.id = u.pdv_id
       AND pdv.project_id = p_project_id
       AND pdv.extraction_run_id = p_run_id
    RETURNING 1
  )
  SELECT count(*) INTO updated_count FROM result;
  RETURN updated_count;
END;
$$;

COMMENT ON FUNCTION public.apply_composition_results(uuid, text, jsonb) IS
  'Phase 30 (Item G): atomic multi-row UPDATE of PDV.composition_factor + PDV.contextual_depscore × factor, gated on (project_id, extraction_run_id) for tenant safety. Called by composition.ts once per scan.';

-- ============================================================
-- Recreate get_project_vulnerabilities_from_pdv RPC with composition_factor
-- ============================================================
-- Appends composition_factor to the 25-column return shape so the
-- frontend follow-up can render the composed multiplier without a
-- second round-trip. Existing 25 projections preserved verbatim from
-- phase24_2:14-69.

DROP FUNCTION IF EXISTS public.get_project_vulnerabilities_from_pdv(uuid);

CREATE FUNCTION public.get_project_vulnerabilities_from_pdv(p_project_id uuid)
RETURNS TABLE(
  id uuid,
  dependency_id uuid,
  osv_id text,
  severity text,
  summary text,
  details text,
  aliases text[],
  fixed_versions text[],
  published_at timestamp with time zone,
  modified_at timestamp with time zone,
  created_at timestamp with time zone,
  dependency_name text,
  dependency_version text,
  is_reachable boolean,
  reachability_level text,
  reachability_details jsonb,
  epss_score numeric,
  cvss_score numeric,
  cisa_kev boolean,
  depscore integer,
  contextual_depscore numeric,
  entry_point_classification text,
  epd_status text,
  sla_status text,
  sla_deadline_at timestamp with time zone,
  composition_factor numeric
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    pdv.id,
    pd.dependency_id,
    pdv.osv_id,
    pdv.severity,
    pdv.summary,
    NULL::TEXT AS details,
    pdv.aliases,
    pdv.fixed_versions,
    pdv.published_at,
    NULL::TIMESTAMPTZ AS modified_at,
    pdv.created_at,
    pd.name AS dependency_name,
    pd.version AS dependency_version,
    pdv.is_reachable,
    pdv.reachability_level,
    pdv.reachability_details,
    pdv.epss_score,
    pdv.cvss_score,
    pdv.cisa_kev,
    pdv.depscore,
    pdv.contextual_depscore,
    pdv.entry_point_classification,
    pdv.epd_status,
    pdv.sla_status,
    pdv.sla_deadline_at,
    pdv.composition_factor
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;

COMMENT ON FUNCTION public.get_project_vulnerabilities_from_pdv(uuid) IS
  'Phase 30 (Item G): appends composition_factor to the return shape so the frontend follow-up can render the composed multiplier alongside contextual_depscore.';

NOTIFY pgrst, 'reload schema';
