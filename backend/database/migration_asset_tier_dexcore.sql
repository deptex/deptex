-- Migration: 4-Tier Asset Criticality and Dexcore
-- Replaces projects.asset_criticality (1-3) with asset_tier enum.
-- Adds dexcore to project_dependency_vulnerabilities and updates PDV RPC.
--
-- Run this file against your Postgres instance, e.g.:
--   psql -f backend/database/migration_asset_tier_dexcore.sql
-- or execute in Supabase SQL editor.

-- ============================================================================
-- STEP 1: Create asset_tier enum and migrate projects
-- ============================================================================

DO $$ BEGIN
  CREATE TYPE asset_tier AS ENUM ('CROWN_JEWELS', 'EXTERNAL', 'INTERNAL', 'NON_PRODUCTION');
EXCEPTION
  WHEN duplicate_object THEN NULL; -- enum already exists
END $$;

ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS asset_tier asset_tier NOT NULL DEFAULT 'EXTERNAL';

-- Backfill from legacy asset_criticality: 1=EXTERNAL, 2=INTERNAL, 3=NON_PRODUCTION
UPDATE projects
SET asset_tier = CASE
  WHEN asset_criticality = 1 THEN 'EXTERNAL'::asset_tier
  WHEN asset_criticality = 2 THEN 'INTERNAL'::asset_tier
  WHEN asset_criticality = 3 THEN 'NON_PRODUCTION'::asset_tier
  ELSE 'EXTERNAL'::asset_tier
END
WHERE asset_criticality IS NOT NULL;

ALTER TABLE projects DROP CONSTRAINT IF EXISTS chk_projects_asset_criticality;
ALTER TABLE projects DROP COLUMN IF EXISTS asset_criticality;

COMMENT ON COLUMN projects.asset_tier IS '4-tier asset criticality: CROWN_JEWELS, EXTERNAL, INTERNAL, NON_PRODUCTION';

-- ============================================================================
-- STEP 2: Add dexcore to project_dependency_vulnerabilities
-- ============================================================================

ALTER TABLE project_dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS dexcore INTEGER;

COMMENT ON COLUMN project_dependency_vulnerabilities.dexcore IS 'Dexcore risk score (0-100): context-aware score using CVSS, EPSS, KEV, reachability, and asset tier';

-- ============================================================================
-- STEP 3: Update get_project_vulnerabilities_from_pdv to return dexcore
-- ============================================================================

DROP FUNCTION IF EXISTS get_project_vulnerabilities_from_pdv(UUID);

CREATE OR REPLACE FUNCTION get_project_vulnerabilities_from_pdv(p_project_id UUID)
RETURNS TABLE (
  id UUID,
  dependency_id UUID,
  osv_id TEXT,
  severity TEXT,
  summary TEXT,
  details TEXT,
  aliases TEXT[],
  fixed_versions TEXT[],
  published_at TIMESTAMPTZ,
  modified_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ,
  dependency_name TEXT,
  dependency_version TEXT,
  is_reachable BOOLEAN,
  epss_score NUMERIC,
  cvss_score NUMERIC,
  cisa_kev BOOLEAN,
  depscore INTEGER,
  dexcore INTEGER
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
    pdv.epss_score,
    pdv.cvss_score,
    pdv.cisa_kev,
    pdv.depscore,
    pdv.dexcore
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;
