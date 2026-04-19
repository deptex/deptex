-- Add color column to team_roles
ALTER TABLE team_roles ADD COLUMN IF NOT EXISTS color TEXT;
