-- Add team_id column to organization_invitations table
ALTER TABLE organization_invitations
ADD COLUMN team_id UUID REFERENCES teams(id) ON DELETE SET NULL;

-- Create index for better query performance
CREATE INDEX idx_organization_invitations_team_id ON organization_invitations(team_id);

