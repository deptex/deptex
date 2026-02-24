-- Activities table for organization activity log
CREATE TABLE IF NOT EXISTS activities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE SET NULL,
  activity_type TEXT NOT NULL,
  description TEXT NOT NULL,
  metadata JSONB DEFAULT '{}', -- Store additional context (project_id, team_id, role_name, etc.)
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Activity types enum (for reference):
-- 'created_org'
-- 'updated_org_name'
-- 'changed_org_profile_image'
-- 'transferred_ownership'
-- 'created_role'
-- 'changed_role_settings'
-- 'updated_policy'
-- 'removed_member'
-- 'left_org'
-- 'changed_member_role'
-- 'invited_member'
-- 'cancelled_invite'
-- 'new_member_joined'
-- 'team_created'
-- 'member_joined_team'
-- 'project_created'

-- Enable Row Level Security
ALTER TABLE activities ENABLE ROW LEVEL SECURITY;

-- RLS Policies for activities
-- Users can view activities for organizations they are members of
CREATE POLICY "Users can view activities for their orgs"
  ON activities FOR SELECT
  USING (
    organization_id IN (
      SELECT organization_id FROM organization_members
      WHERE user_id = auth.uid()
    )
  );

-- Only authenticated users can create activities (typically done by backend/triggers)
CREATE POLICY "Authenticated users can create activities"
  ON activities FOR INSERT
  WITH CHECK (auth.uid() IS NOT NULL);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_activities_organization_id ON activities(organization_id);
CREATE INDEX IF NOT EXISTS idx_activities_created_at ON activities(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_activities_activity_type ON activities(activity_type);
CREATE INDEX IF NOT EXISTS idx_activities_user_id ON activities(user_id);

-- Composite index for common filter queries
CREATE INDEX IF NOT EXISTS idx_activities_org_type_date ON activities(organization_id, activity_type, created_at DESC);

