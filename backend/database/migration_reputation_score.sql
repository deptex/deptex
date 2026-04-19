-- Migration: Reputation Score Refactor
-- Moves score + status from dependency_versions to dependencies (package-level).
-- Adds releases_last_12_months for maintenance scoring.
-- Removes score + status from dependency_versions.

-- ============================================================================
-- STEP 1: Add new columns to dependencies
-- ============================================================================

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending';

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS score INTEGER;

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS releases_last_12_months INTEGER;

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS analyzed_at TIMESTAMP WITH TIME ZONE;

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS error_message TEXT;

-- Index on status for filtering pending/analyzing dependencies
CREATE INDEX IF NOT EXISTS idx_dependencies_status ON dependencies(status);

COMMENT ON COLUMN dependencies.status IS 'Population status: pending, analyzing, ready, error';
COMMENT ON COLUMN dependencies.score IS 'Reputation score (0-100) based on OpenSSF, popularity, maintenance';
COMMENT ON COLUMN dependencies.releases_last_12_months IS 'Number of npm releases in the last 12 months (maintenance signal)';
COMMENT ON COLUMN dependencies.analyzed_at IS 'Timestamp when the dependency was last analyzed/populated';
COMMENT ON COLUMN dependencies.error_message IS 'Error message if population failed';

-- ============================================================================
-- STEP 2: Remove score and status from dependency_versions
-- ============================================================================

-- Drop the status index first
DROP INDEX IF EXISTS idx_dependency_versions_status;

ALTER TABLE dependency_versions
DROP COLUMN IF EXISTS score;

ALTER TABLE dependency_versions
DROP COLUMN IF EXISTS status;

-- ============================================================================
-- STEP 3: Set existing dependencies to 'ready' if they have openssf_score
--         (they were previously analyzed), otherwise leave as 'pending'
-- ============================================================================

UPDATE dependencies
SET status = 'ready'
WHERE openssf_score IS NOT NULL OR weekly_downloads IS NOT NULL;
