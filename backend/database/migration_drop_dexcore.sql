-- Migration: Drop Dexcore, Keep Depscore (4-tier model)
-- Depscore now uses the 4-tier asset_tier model. Dexcore is redundant.
--
-- Run: psql -f backend/database/migration_drop_dexcore.sql

-- STEP 1: Drop dexcore column from project_dependency_vulnerabilities
ALTER TABLE project_dependency_vulnerabilities
  DROP COLUMN IF EXISTS dexcore;

-- STEP 2: Update get_project_vulnerabilities_from_pdv to stop returning dexcore
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
  depscore INTEGER
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
    pdv.depscore
  FROM project_dependency_vulnerabilities pdv
  INNER JOIN project_dependencies pd
    ON pd.id = pdv.project_dependency_id
   AND pd.project_id = pdv.project_id
  WHERE pdv.project_id = p_project_id;
$$;
