-- Phase 5: License Obligations reference table
-- Tracks what each SPDX license REQUIRES for legal compliance

CREATE TABLE IF NOT EXISTS license_obligations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  license_spdx_id TEXT NOT NULL UNIQUE,
  requires_attribution BOOLEAN NOT NULL DEFAULT false,
  requires_notice_file BOOLEAN NOT NULL DEFAULT false,
  requires_source_disclosure BOOLEAN NOT NULL DEFAULT false,
  requires_license_text BOOLEAN NOT NULL DEFAULT false,
  is_copyleft BOOLEAN NOT NULL DEFAULT false,
  is_weak_copyleft BOOLEAN NOT NULL DEFAULT false,
  summary TEXT,
  full_text TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_license_obligations_spdx
  ON license_obligations(license_spdx_id);

COMMENT ON TABLE license_obligations IS 'Reference table of SPDX license obligations for legal compliance tracking. Seeded with ~50 common licenses.';
COMMENT ON COLUMN license_obligations.license_spdx_id IS 'SPDX identifier (e.g. MIT, Apache-2.0, GPL-3.0-only)';
COMMENT ON COLUMN license_obligations.requires_attribution IS 'Must include copyright notice in distributions';
COMMENT ON COLUMN license_obligations.requires_notice_file IS 'Must include NOTICE file in distributions';
COMMENT ON COLUMN license_obligations.requires_source_disclosure IS 'Must disclose source for modifications';
COMMENT ON COLUMN license_obligations.requires_license_text IS 'Must include full license text in distributions';
COMMENT ON COLUMN license_obligations.is_copyleft IS 'Modifications must use same license (strong copyleft)';
COMMENT ON COLUMN license_obligations.is_weak_copyleft IS 'Only linked/combined code must use same license';
