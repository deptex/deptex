-- Junction table for many-to-many relationship between projects and teams
CREATE TABLE project_teams (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  team_id UUID REFERENCES teams(id) ON DELETE CASCADE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  UNIQUE(project_id, team_id)
);

-- Enable Row Level Security
ALTER TABLE project_teams ENABLE ROW LEVEL SECURITY;

-- RLS Policies for project_teams
-- Users can view project-team relationships for projects in their organizations
CREATE POLICY "Users can view project teams in their orgs"
  ON project_teams FOR SELECT
  USING (
    project_id IN (
      SELECT id FROM projects
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
      )
    )
  );

-- Admins can manage project-team relationships
CREATE POLICY "Admins can manage project teams"
  ON project_teams FOR ALL
  USING (
    project_id IN (
      SELECT id FROM projects
      WHERE organization_id IN (
        SELECT organization_id FROM organization_members
        WHERE user_id = auth.uid()
        AND role IN ('owner', 'admin')
      )
    )
  );

-- Create indexes for better query performance
CREATE INDEX idx_project_teams_project_id ON project_teams(project_id);
CREATE INDEX idx_project_teams_team_id ON project_teams(team_id);

