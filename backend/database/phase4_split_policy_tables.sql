-- Phase 4B: Split policy code storage into 3 separate tables
-- Replaces the single organization_policies.policy_code column

-- Package Policy (per-dependency evaluation)
CREATE TABLE IF NOT EXISTS organization_package_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  package_policy_code TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  UNIQUE(organization_id)
);

ALTER TABLE organization_package_policies ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view package policies for their orgs"
  ON organization_package_policies FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage package policies"
  ON organization_package_policies FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

-- Project Status Code (per-project evaluation)
CREATE TABLE IF NOT EXISTS organization_status_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_status_code TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  UNIQUE(organization_id)
);

ALTER TABLE organization_status_codes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view status codes for their orgs"
  ON organization_status_codes FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage status codes"
  ON organization_status_codes FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

-- PR Check Code (per-PR evaluation)
CREATE TABLE IF NOT EXISTS organization_pr_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  pr_check_code TEXT,
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  updated_by_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  UNIQUE(organization_id)
);

ALTER TABLE organization_pr_checks ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view PR checks for their orgs"
  ON organization_pr_checks FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage PR checks"
  ON organization_pr_checks FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE INDEX idx_org_package_policies_org ON organization_package_policies(organization_id);
CREATE INDEX idx_org_status_codes_org ON organization_status_codes(organization_id);
CREATE INDEX idx_org_pr_checks_org ON organization_pr_checks(organization_id);

COMMENT ON TABLE organization_package_policies IS 'Stores the packagePolicy() function code. Runs per-dependency to return { allowed, reasons }.';
COMMENT ON TABLE organization_status_codes IS 'Stores the projectStatus() function code. Runs per-project to return { status, violations }.';
COMMENT ON TABLE organization_pr_checks IS 'Stores the pullRequestCheck() function code. Runs per-PR to return { status, violations }.';
