-- Migration: Depscore Scoring
-- Adds asset_criticality to projects (1=Internet Facing, 2=Internal, 3=Sandbox).
-- Adds cvss_score, cisa_kev, and depscore to project_dependency_vulnerabilities.

-- ============================================================================
-- STEP 1: Add asset_criticality to projects
-- ============================================================================

ALTER TABLE projects
ADD COLUMN IF NOT EXISTS asset_criticality INTEGER NOT NULL DEFAULT 2;

ALTER TABLE projects
ADD CONSTRAINT chk_projects_asset_criticality
CHECK (asset_criticality >= 1 AND asset_criticality <= 3);

COMMENT ON COLUMN projects.asset_criticality IS '1 = Internet Facing, 2 = Internal, 3 = Sandbox';

-- ============================================================================
-- STEP 2: Add scoring columns to project_dependency_vulnerabilities
-- ============================================================================

ALTER TABLE project_dependency_vulnerabilities
ADD COLUMN IF NOT EXISTS cvss_score NUMERIC(3, 1);

ALTER TABLE project_dependency_vulnerabilities
ADD COLUMN IF NOT EXISTS cisa_kev BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE project_dependency_vulnerabilities
ADD COLUMN IF NOT EXISTS depscore INTEGER;

COMMENT ON COLUMN project_dependency_vulnerabilities.cvss_score IS 'Numeric CVSS base score (0.0-10.0) from dep-scan or severity mapping';
COMMENT ON COLUMN project_dependency_vulnerabilities.cisa_kev IS 'True if CVE appears in the CISA Known Exploited Vulnerabilities catalog';
COMMENT ON COLUMN project_dependency_vulnerabilities.depscore IS 'Depscore risk score (0-100) combining CVSS, EPSS, KEV, reachability, and asset criticality';
