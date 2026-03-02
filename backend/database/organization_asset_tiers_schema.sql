-- Organization Asset Tiers: customizable project criticality tiers.
-- Replaces the hardcoded asset_tier enum with org-defined tiers that include
-- an environmental_multiplier used in depscore calculation.

CREATE TABLE IF NOT EXISTS organization_asset_tiers (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#6b7280',
  rank INTEGER NOT NULL DEFAULT 50,
  description TEXT,
  is_system BOOLEAN NOT NULL DEFAULT false,
  environmental_multiplier DECIMAL(4,2) NOT NULL DEFAULT 1.0,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_organization_asset_tiers_org
  ON organization_asset_tiers(organization_id);

CREATE INDEX IF NOT EXISTS idx_organization_asset_tiers_rank
  ON organization_asset_tiers(organization_id, rank);

COMMENT ON TABLE organization_asset_tiers IS 'Org-defined asset criticality tiers (e.g. Crown Jewels, External, Internal, Non-Production). Used in depscore calculation via environmental_multiplier.';
COMMENT ON COLUMN organization_asset_tiers.rank IS 'Lower = more critical. Used for ordering.';
COMMENT ON COLUMN organization_asset_tiers.environmental_multiplier IS 'Multiplier applied to depscore calculation. Higher = more weight (e.g. 1.5 for Crown Jewels, 0.6 for Non-Production).';
COMMENT ON COLUMN organization_asset_tiers.is_system IS 'True for the 4 default tiers. Can rename/recolor/change multiplier but not delete.';
