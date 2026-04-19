-- Phase 3: New scoring multipliers on dependencies table
ALTER TABLE dependencies
  ADD COLUMN IF NOT EXISTS is_malicious BOOLEAN DEFAULT false;

ALTER TABLE dependencies
  ADD COLUMN IF NOT EXISTS slsa_multiplier DECIMAL(4,2) DEFAULT 1.0;

ALTER TABLE dependencies
  ADD COLUMN IF NOT EXISTS malicious_multiplier DECIMAL(4,2) DEFAULT 1.0;
