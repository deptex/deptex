-- ============================================================================
-- WATCHTOWER SCHEMA REFACTOR MIGRATION (FIXED)
-- ============================================================================
-- This migration restructures the database to a 3-layer architecture:
-- 1. dependencies       - Package-level data (name, license, github_url)
-- 2. dependency_versions - Version-specific data (version, score, security checks)
-- 3. watched_packages   - Polling state (links to dependencies)
-- ============================================================================

-- ============================================================================
-- STEP 1: Create dependency_versions table
-- ============================================================================

CREATE TABLE IF NOT EXISTS dependency_versions (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  dependency_id UUID NOT NULL,  -- FK added later
  version TEXT NOT NULL,
  
  -- Analysis status
  status TEXT NOT NULL DEFAULT 'pending',
  
  -- Scoring
  score INTEGER,
  critical_vulns INTEGER DEFAULT 0,
  high_vulns INTEGER DEFAULT 0,
  medium_vulns INTEGER DEFAULT 0,
  low_vulns INTEGER DEFAULT 0,
  
  -- Watchtower security analysis
  registry_integrity_status TEXT,
  install_scripts_status TEXT,
  entropy_analysis_status TEXT,
  
  -- Detailed analysis data
  analysis_data JSONB,
  
  -- Timestamps
  analyzed_at TIMESTAMP WITH TIME ZONE,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_dependency_versions_dependency_id 
  ON dependency_versions(dependency_id);
CREATE INDEX IF NOT EXISTS idx_dependency_versions_version 
  ON dependency_versions(version);
CREATE INDEX IF NOT EXISTS idx_dependency_versions_status 
  ON dependency_versions(status);

ALTER TABLE dependency_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role can manage dependency_versions" ON dependency_versions
  FOR ALL USING (true) WITH CHECK (true);

-- ============================================================================
-- STEP 2: Create a NEW consolidated dependencies table
-- ============================================================================
-- Instead of modifying the existing table with duplicates, we create a new one

CREATE TABLE IF NOT EXISTS dependencies_new (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  name TEXT NOT NULL UNIQUE,
  license TEXT,
  github_url TEXT,
  openssf_score DECIMAL(3,1),
  weekly_downloads INTEGER,
  last_published_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_dependencies_new_name ON dependencies_new(name);
CREATE INDEX IF NOT EXISTS idx_dependencies_new_github_url ON dependencies_new(github_url);

ALTER TABLE dependencies_new ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role can manage dependencies_new" ON dependencies_new
  FOR ALL USING (true) WITH CHECK (true);

-- ============================================================================
-- STEP 3: Populate the new consolidated dependencies table
-- ============================================================================
-- Take one row per package name (using the most recent one)

INSERT INTO dependencies_new (name, license, openssf_score, weekly_downloads, last_published_at, created_at, updated_at)
SELECT DISTINCT ON (name)
  name,
  license,
  openssf_score,
  weekly_downloads,
  last_published_at,
  created_at,
  updated_at
FROM dependencies
ORDER BY name, updated_at DESC NULLS LAST
ON CONFLICT (name) DO NOTHING;

-- ============================================================================
-- STEP 4: Populate dependency_versions from old dependencies
-- ============================================================================
-- Link each version to the consolidated package in dependencies_new

INSERT INTO dependency_versions (
  dependency_id,
  version,
  status,
  score,
  critical_vulns,
  high_vulns,
  medium_vulns,
  low_vulns,
  analyzed_at,
  error_message,
  created_at,
  updated_at
)
SELECT 
  dn.id as dependency_id,
  d.version,
  d.status,
  d.score,
  d.critical_vulns,
  d.high_vulns,
  d.medium_vulns,
  d.low_vulns,
  d.analyzed_at,
  d.error_message,
  d.created_at,
  d.updated_at
FROM dependencies d
JOIN dependencies_new dn ON d.name = dn.name
ON CONFLICT DO NOTHING;

-- ============================================================================
-- STEP 5: Add FK constraint to dependency_versions
-- ============================================================================

ALTER TABLE dependency_versions 
ADD CONSTRAINT fk_dependency_versions_dependency 
FOREIGN KEY (dependency_id) REFERENCES dependencies_new(id) ON DELETE CASCADE;

ALTER TABLE dependency_versions 
ADD CONSTRAINT dependency_versions_dependency_version_key 
UNIQUE (dependency_id, version);

-- ============================================================================
-- STEP 6: Refactor watched_packages table
-- ============================================================================

-- Add dependency_id FK column
ALTER TABLE watched_packages 
ADD COLUMN IF NOT EXISTS dependency_id UUID;

-- Link watched_packages to the new consolidated dependencies
UPDATE watched_packages wp
SET dependency_id = dn.id
FROM dependencies_new dn
WHERE dn.name = wp.name;

-- Copy github_url to dependencies_new
UPDATE dependencies_new dn
SET github_url = wp.github_url
FROM watched_packages wp
WHERE dn.name = wp.name AND wp.github_url IS NOT NULL;

-- Add FK constraint
ALTER TABLE watched_packages
ADD CONSTRAINT fk_watched_packages_dependency 
FOREIGN KEY (dependency_id) REFERENCES dependencies_new(id) ON DELETE CASCADE;

-- Drop columns that are moving or no longer needed
ALTER TABLE watched_packages
DROP COLUMN IF EXISTS name CASCADE,
DROP COLUMN IF EXISTS github_url CASCADE,
DROP COLUMN IF EXISTS registry_integrity_status CASCADE,
DROP COLUMN IF EXISTS install_scripts_status CASCADE,
DROP COLUMN IF EXISTS entropy_analysis_status CASCADE,
DROP COLUMN IF EXISTS maintainer_analysis_status CASCADE,
DROP COLUMN IF EXISTS latest_version CASCADE,
DROP COLUMN IF EXISTS latest_release_date CASCADE,
DROP COLUMN IF EXISTS quarantine_expires_at CASCADE,
DROP COLUMN IF EXISTS analysis_data CASCADE,
DROP COLUMN IF EXISTS analyzed_at CASCADE,
DROP COLUMN IF EXISTS last_npm_version CASCADE;

-- Add unique constraint
ALTER TABLE watched_packages 
ADD CONSTRAINT watched_packages_dependency_id_key UNIQUE (dependency_id);

-- ============================================================================
-- STEP 7: Update project_dependencies to reference dependency_versions
-- ============================================================================

ALTER TABLE project_dependencies 
ADD COLUMN IF NOT EXISTS dependency_version_id UUID;

-- Link existing project_dependencies to dependency_versions
UPDATE project_dependencies pd
SET dependency_version_id = dv.id
FROM dependency_versions dv
JOIN dependencies_new dn ON dv.dependency_id = dn.id
WHERE pd.name = dn.name AND pd.version = dv.version;

-- Add FK constraint
ALTER TABLE project_dependencies
ADD CONSTRAINT fk_project_dependencies_version 
FOREIGN KEY (dependency_version_id) REFERENCES dependency_versions(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_project_dependencies_dependency_version_id 
  ON project_dependencies(dependency_version_id);

-- ============================================================================
-- STEP 8: Swap the tables
-- ============================================================================

-- Drop old indexes first to avoid naming conflicts
DROP INDEX IF EXISTS idx_dependencies_name;
DROP INDEX IF EXISTS idx_dependencies_status;
DROP INDEX IF EXISTS idx_dependencies_name_version;
DROP INDEX IF EXISTS idx_dependencies_github_url;

-- Rename old table
ALTER TABLE dependencies RENAME TO dependencies_old;

-- Rename new table to dependencies
ALTER TABLE dependencies_new RENAME TO dependencies;

-- Rename indexes to final names
ALTER INDEX idx_dependencies_new_name RENAME TO idx_dependencies_name;
ALTER INDEX idx_dependencies_new_github_url RENAME TO idx_dependencies_github_url;

-- Update FK constraint name
ALTER TABLE dependency_versions 
DROP CONSTRAINT IF EXISTS fk_dependency_versions_dependency;

ALTER TABLE dependency_versions 
ADD CONSTRAINT fk_dependency_versions_dependency 
FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE;

ALTER TABLE watched_packages 
DROP CONSTRAINT IF EXISTS fk_watched_packages_dependency;

ALTER TABLE watched_packages 
ADD CONSTRAINT fk_watched_packages_dependency 
FOREIGN KEY (dependency_id) REFERENCES dependencies(id) ON DELETE CASCADE;

-- ============================================================================
-- STEP 9: Clean up (OPTIONAL - run after verifying migration works)
-- ============================================================================
-- DROP TABLE IF EXISTS dependencies_old;

-- ============================================================================
-- VERIFICATION QUERIES
-- ============================================================================
-- 
-- SELECT COUNT(*) as packages FROM dependencies;
-- SELECT COUNT(*) as versions FROM dependency_versions;
-- SELECT COUNT(*) as watched FROM watched_packages WHERE dependency_id IS NOT NULL;
-- SELECT COUNT(*) as linked_project_deps FROM project_dependencies WHERE dependency_version_id IS NOT NULL;
