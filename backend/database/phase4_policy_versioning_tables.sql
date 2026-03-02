-- Phase 4D: Git-like policy versioning tables

-- Project-level policy changes (commit chain per project per code_type)
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

CREATE INDEX idx_project_policy_changes_project ON project_policy_changes(project_id);
CREATE INDEX idx_project_policy_changes_org ON project_policy_changes(organization_id);
CREATE INDEX idx_project_policy_changes_status ON project_policy_changes(organization_id, status);
CREATE INDEX idx_project_policy_changes_type ON project_policy_changes(project_id, code_type, status);

-- Org-level policy version history
CREATE TABLE IF NOT EXISTS organization_policy_changes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  code_type TEXT NOT NULL CHECK (code_type IN ('package_policy', 'project_status', 'pr_check')),
  author_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  parent_id UUID REFERENCES organization_policy_changes(id) ON DELETE SET NULL,
  previous_code TEXT,
  new_code TEXT,
  message TEXT,
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

CREATE INDEX idx_org_policy_changes_org ON organization_policy_changes(organization_id);
CREATE INDEX idx_org_policy_changes_type ON organization_policy_changes(organization_id, code_type);

-- Policy evaluation jobs (async re-evaluation queue)
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

CREATE INDEX idx_policy_eval_jobs_org ON policy_evaluation_jobs(organization_id);
CREATE INDEX idx_policy_eval_jobs_status ON policy_evaluation_jobs(organization_id, status);
