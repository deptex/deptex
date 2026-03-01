-- Phase 3A.2: SLSA provenance level from npm attestations API (0-4, null if unknown)
ALTER TABLE dependency_versions
  ADD COLUMN IF NOT EXISTS slsa_level INTEGER;
