-- Organization Status Codes: per-project policy code that determines project status.
-- One row per org. Runs projectStatus(context) with all deps + their policyResults.

CREATE TABLE IF NOT EXISTS organization_status_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_status_code TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by_id UUID,
  UNIQUE(organization_id)
);

COMMENT ON TABLE organization_status_codes IS 'Stores the projectStatus() function code. Runs per-project to return { status, violations }.';
