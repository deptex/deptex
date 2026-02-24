-- Organization-level watchlist for Watchtower (per-org, per-package)
-- Replaces is_watching + watchtower_cleared_at on project_dependencies

CREATE TABLE IF NOT EXISTS organization_watchlist (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  watchtower_cleared_at TIMESTAMP WITH TIME ZONE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_organization_watchlist_org_name
  ON organization_watchlist(organization_id, name);

CREATE INDEX IF NOT EXISTS idx_organization_watchlist_name
  ON organization_watchlist(name);

COMMENT ON TABLE organization_watchlist IS 'Per-organization list of packages watched by Watchtower. One row per org per package name.';
