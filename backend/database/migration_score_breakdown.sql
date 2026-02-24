-- Migration: Add score breakdown to dependencies and remove license from project_dependencies
-- Run this migration after the initial schema is set up

-- 1. Add score breakdown columns to dependencies table
ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS vuln_penalty INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS openssf_penalty INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS popularity_penalty INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS maintenance_penalty INTEGER DEFAULT 0;

-- 2. Add column to store full OpenSSF scorecard JSON
ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS openssf_data JSONB;

-- 3. Remove license column from project_dependencies (license now comes from dependencies table)
ALTER TABLE project_dependencies
DROP COLUMN IF EXISTS license;

-- 4. Add comments for documentation
COMMENT ON COLUMN dependencies.vuln_penalty IS 'Penalty from vulnerabilities: critical*50 + high*30 + medium*10';
COMMENT ON COLUMN dependencies.openssf_penalty IS 'Penalty from OpenSSF score: <3=-40, <5=-20, <7=-20';
COMMENT ON COLUMN dependencies.popularity_penalty IS 'Penalty from weekly downloads: <100=-30, <1000=-10';
COMMENT ON COLUMN dependencies.maintenance_penalty IS 'Penalty from days since publish: >50=-20, >30=-10';
COMMENT ON COLUMN dependencies.openssf_data IS 'Full OpenSSF Scorecard API response JSON';
