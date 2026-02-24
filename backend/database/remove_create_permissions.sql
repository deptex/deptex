-- Migration: Remove create_teams and create_projects permissions
-- This removes the create_teams and create_projects keys from all existing role permissions
-- since "View All Teams" and "View All Projects" now include creation capabilities

UPDATE organization_roles
SET permissions = permissions - 'create_teams' - 'create_projects',
    updated_at = NOW()
WHERE permissions ? 'create_teams' OR permissions ? 'create_projects';

