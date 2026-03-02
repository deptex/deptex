-- Organization Package Policies: per-dep policy code that determines allowed/blocked.
-- One row per org. Runs packagePolicy(context) for each dependency.

CREATE TABLE IF NOT EXISTS organization_package_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  package_policy_code TEXT NOT NULL DEFAULT '',
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by_id UUID,
  UNIQUE(organization_id)
);

COMMENT ON TABLE organization_package_policies IS 'Stores the packagePolicy() function code. Runs per-dependency to return { allowed, reasons }.';
