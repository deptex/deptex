-- Add ecosystem column to dependencies table for multi-ecosystem populate routing.
-- Existing rows default to 'npm' (the only ecosystem that was populated before this migration).
ALTER TABLE dependencies
  ADD COLUMN IF NOT EXISTS ecosystem TEXT NOT NULL DEFAULT 'npm';

COMMENT ON COLUMN dependencies.ecosystem IS 'Package ecosystem identifier (npm, pypi, maven, nuget, golang, cargo, gem, composer, pub, hex, swift).';

-- Make name unique per ecosystem (drop old unique on name alone if it exists, add composite).
-- Note: if there is already a unique constraint on (name), this will need manual adjustment.
-- We use CREATE UNIQUE INDEX IF NOT EXISTS to be safe.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dependencies_ecosystem_name ON dependencies (ecosystem, name);
