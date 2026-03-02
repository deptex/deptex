-- Phase 4 Policy Engine + Custom Statuses: consolidated migration
-- Replaces: add_manage_statuses_permission, add_policy_result_to_project_dependencies,
-- add_status_policy_columns_to_projects, organization_asset_tiers_schema,
-- organization_package_policies_schema, organization_policy_changes_schema,
-- organization_pr_checks_schema, organization_status_codes_schema,
-- organization_statuses_schema, phase4_alter_projects, phase4_policy_versioning_tables,
-- phase4_split_policy_tables, project_policy_changes_schema

-- =============================================================================
-- 1. Organization Statuses (projects will reference via status_id)
-- =============================================================================
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

-- =============================================================================
-- 2. Organization Asset Tiers (projects will reference via asset_tier_id)
-- =============================================================================
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

-- =============================================================================
-- 3. Split policy code storage (replaces single organization_policies.policy_code)
-- =============================================================================

-- Package Policy (per-dependency evaluation)
CREATE TABLE IF NOT EXISTS organization_package_policies (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  package_policy_code TEXT NOT NULL DEFAULT '',
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

CREATE INDEX IF NOT EXISTS idx_org_package_policies_org ON organization_package_policies(organization_id);

COMMENT ON TABLE organization_package_policies IS 'Stores the packagePolicy() function code. Runs per-dependency to return { allowed, reasons }.';

-- Project Status Code (per-project evaluation)
CREATE TABLE IF NOT EXISTS organization_status_codes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  project_status_code TEXT NOT NULL DEFAULT '',
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

CREATE INDEX IF NOT EXISTS idx_org_status_codes_org ON organization_status_codes(organization_id);

COMMENT ON TABLE organization_status_codes IS 'Stores the projectStatus() function code. Runs per-project to return { status, violations }.';

-- PR Check Code (per-PR evaluation)
CREATE TABLE IF NOT EXISTS organization_pr_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  pr_check_code TEXT NOT NULL DEFAULT '',
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

CREATE INDEX IF NOT EXISTS idx_org_pr_checks_org ON organization_pr_checks(organization_id);

COMMENT ON TABLE organization_pr_checks IS 'Stores the pullRequestCheck() function code. Runs per-PR to return { status, violations }.';

-- =============================================================================
-- 4. Add manage_statuses permission to organization roles
-- =============================================================================
UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_statuses}',
  CASE
    WHEN name = 'owner' THEN 'true'::jsonb
    ELSE 'false'::jsonb
  END,
  true
)
WHERE permissions IS NULL OR NOT (permissions ? 'manage_statuses');

-- =============================================================================
-- 5. Alter projects: status_id, asset_tier_id, policy overrides
-- =============================================================================
ALTER TABLE projects
  ADD COLUMN IF NOT EXISTS status_id UUID REFERENCES organization_statuses(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS status_violations TEXT[] DEFAULT '{}',
  ADD COLUMN IF NOT EXISTS policy_evaluated_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS asset_tier_id UUID REFERENCES organization_asset_tiers(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS effective_package_policy_code TEXT,
  ADD COLUMN IF NOT EXISTS effective_project_status_code TEXT,
  ADD COLUMN IF NOT EXISTS effective_pr_check_code TEXT;

CREATE INDEX IF NOT EXISTS idx_projects_status_id ON projects(status_id);
CREATE INDEX IF NOT EXISTS idx_projects_asset_tier_id ON projects(asset_tier_id);

COMMENT ON COLUMN projects.status_id IS 'FK to organization_statuses. Set by policy engine after evaluation. Replaces is_compliant.';
COMMENT ON COLUMN projects.status_violations IS 'Array of violation messages from the last policy evaluation.';
COMMENT ON COLUMN projects.policy_evaluated_at IS 'Timestamp of the last policy evaluation run.';
COMMENT ON COLUMN projects.asset_tier_id IS 'FK to organization_asset_tiers. Replaces the hardcoded asset_tier enum.';
COMMENT ON COLUMN projects.effective_package_policy_code IS 'Project-level package policy override. NULL = inherited from org.';
COMMENT ON COLUMN projects.effective_project_status_code IS 'Project-level status code override. NULL = inherited from org.';
COMMENT ON COLUMN projects.effective_pr_check_code IS 'Project-level PR check code override. NULL = inherited from org.';

-- =============================================================================
-- 6. Add policy_result to project_dependencies
-- =============================================================================
ALTER TABLE project_dependencies
  ADD COLUMN IF NOT EXISTS policy_result JSONB;

CREATE INDEX IF NOT EXISTS idx_project_dependencies_policy_result
  ON project_dependencies USING gin(policy_result);

COMMENT ON COLUMN project_dependencies.policy_result IS 'Result of packagePolicy() execution: { allowed: boolean, reasons: string[] }. NULL if policy has not been evaluated.';

-- =============================================================================
-- 7. Organization Policy Changes (version history for org-level policy edits)
-- =============================================================================
CREATE TABLE IF NOT EXISTS organization_policy_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_type TEXT NOT NULL CHECK (code_type IN ('package_policy', 'project_status', 'pr_check')),
  author_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES organization_policy_changes(id) ON DELETE SET NULL,
  previous_code TEXT,
  new_code TEXT,
  message TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE organization_policy_changes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view org policy changes for their orgs"
  ON organization_policy_changes FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage org policy changes"
  ON organization_policy_changes FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE INDEX IF NOT EXISTS idx_org_policy_changes_org ON organization_policy_changes(organization_id);
CREATE INDEX IF NOT EXISTS idx_org_policy_changes_type ON organization_policy_changes(organization_id, code_type);

COMMENT ON TABLE organization_policy_changes IS 'Version history for org-level policy edits. Each save creates a new row for revert capability.';
COMMENT ON COLUMN organization_policy_changes.parent_id IS 'Points to the previous change of the same code_type for the same org.';

-- =============================================================================
-- 8. Project Policy Changes (git-like commit chain for project-level overrides)
-- =============================================================================
CREATE TABLE IF NOT EXISTS project_policy_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_type TEXT NOT NULL CHECK (code_type IN ('package_policy', 'project_status', 'pr_check')),
  author_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  reviewer_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  parent_id UUID REFERENCES project_policy_changes(id) ON DELETE SET NULL,
  base_code TEXT,
  proposed_code TEXT,
  message TEXT,
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
  is_ai_generated BOOLEAN NOT NULL DEFAULT false,
  ai_merged_code TEXT,
  has_conflict BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  reviewed_at TIMESTAMPTZ
);

ALTER TABLE project_policy_changes ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view policy changes for their orgs"
  ON project_policy_changes FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Users can create policy changes"
  ON project_policy_changes FOR INSERT
  WITH CHECK (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage policy changes"
  ON project_policy_changes FOR UPDATE
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE INDEX IF NOT EXISTS idx_project_policy_changes_project ON project_policy_changes(project_id);
CREATE INDEX IF NOT EXISTS idx_project_policy_changes_org ON project_policy_changes(organization_id);
CREATE INDEX IF NOT EXISTS idx_project_policy_changes_status ON project_policy_changes(organization_id, status);
CREATE INDEX IF NOT EXISTS idx_project_policy_changes_type ON project_policy_changes(project_id, code_type, status);

COMMENT ON TABLE project_policy_changes IS 'Git-like commit chain for project-level policy overrides. Each code_type has its own chain per project.';
COMMENT ON COLUMN project_policy_changes.parent_id IS 'Points to the previously accepted change of the same code_type for the same project.';
COMMENT ON COLUMN project_policy_changes.base_code IS 'Snapshot of the effective code when this change was authored (for conflict detection).';
COMMENT ON COLUMN project_policy_changes.has_conflict IS 'True when base_code does not match current effective code at review time.';

-- =============================================================================
-- 9. Policy Evaluation Jobs (async re-evaluation queue)
-- =============================================================================
CREATE TABLE IF NOT EXISTS policy_evaluation_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  triggered_by_id UUID REFERENCES auth.users(id) ON DELETE SET NULL,
  trigger_reason TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'processing', 'completed', 'failed')),
  total_projects INTEGER DEFAULT 0,
  processed_projects INTEGER DEFAULT 0,
  failed_projects INTEGER DEFAULT 0,
  error_log JSONB DEFAULT '[]'::jsonb,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

ALTER TABLE policy_evaluation_jobs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view evaluation jobs for their orgs"
  ON policy_evaluation_jobs FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members WHERE user_id = auth.uid()
    )
  );

CREATE POLICY "Admins can manage evaluation jobs"
  ON policy_evaluation_jobs FOR ALL
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid() AND role IN ('owner', 'admin')
    )
  );

CREATE INDEX IF NOT EXISTS idx_policy_eval_jobs_org ON policy_evaluation_jobs(organization_id);
CREATE INDEX IF NOT EXISTS idx_policy_eval_jobs_status ON policy_evaluation_jobs(organization_id, status);
