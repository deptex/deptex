-- Organization Statuses: custom project statuses defined per org.
-- Replaces binary is_compliant with flexible, org-defined status system.

CREATE TABLE IF NOT EXISTS organization_statuses (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  color TEXT NOT NULL DEFAULT '#6b7280',
  rank INTEGER NOT NULL DEFAULT 50,
  description TEXT,
  is_system BOOLEAN NOT NULL DEFAULT false,
  is_passing BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(organization_id, name)
);

CREATE INDEX IF NOT EXISTS idx_organization_statuses_org
  ON organization_statuses(organization_id);

CREATE INDEX IF NOT EXISTS idx_organization_statuses_rank
  ON organization_statuses(organization_id, rank);

COMMENT ON TABLE organization_statuses IS 'Org-defined project statuses (e.g. Compliant, Blocked, Under Review). Policy code assigns these to projects.';
COMMENT ON COLUMN organization_statuses.rank IS 'Lower = better. Used for ordering and worst-status-wins logic.';
COMMENT ON COLUMN organization_statuses.is_system IS 'True for the 2 required statuses (Compliant, Non-Compliant). Can rename/recolor but not delete.';
COMMENT ON COLUMN organization_statuses.is_passing IS 'Whether this status counts as passing for GitHub Check Runs and compliance metrics.';
