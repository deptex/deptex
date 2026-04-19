-- Add invitation_teams junction table to support multiple teams per invitation
CREATE TABLE IF NOT EXISTS invitation_teams (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  invitation_id UUID REFERENCES organization_invitations(id) ON DELETE CASCADE,
  team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(invitation_id, team_id)
);

-- Enable Row Level Security
ALTER TABLE invitation_teams ENABLE ROW LEVEL SECURITY;

-- RLS Policies for invitation_teams
-- Users can view invitation teams for invitations they can view
CREATE POLICY "Users can view invitation teams for their orgs"
  ON invitation_teams FOR SELECT
  USING (
    invitation_id IN (
      SELECT id FROM organization_invitations
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
      )
    )
  );

-- Users can view their own invitation teams
CREATE POLICY "Users can view their own invitation teams"
  ON invitation_teams FOR SELECT
  USING (
    invitation_id IN (
      SELECT id FROM organization_invitations
      WHERE email = (SELECT email FROM auth.users WHERE id = auth.uid())
      AND status = 'pending'
    )
  );

-- Admins can create invitation teams
CREATE POLICY "Admins can create invitation teams"
  ON invitation_teams FOR INSERT
  WITH CHECK (
    invitation_id IN (
      SELECT id FROM organization_invitations
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
        AND role IN ('owner', 'admin')
      )
    )
  );

-- Admins can delete invitation teams
CREATE POLICY "Admins can delete invitation teams"
  ON invitation_teams FOR DELETE
  USING (
    invitation_id IN (
      SELECT id FROM organization_invitations
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
        AND role IN ('owner', 'admin')
      )
    )
  );

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_invitation_teams_invitation_id ON invitation_teams(invitation_id);
CREATE INDEX IF NOT EXISTS idx_invitation_teams_team_id ON invitation_teams(team_id);

