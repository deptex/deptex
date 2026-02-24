-- Migration: Add can_create_teams permission to organization_roles
-- This migration adds the can_create_teams permission to the permissions JSONB column

DO $$
DECLARE
  role_record RECORD;
  current_permissions JSONB;
  updated_permissions JSONB;
BEGIN
  -- Loop through all organization roles
  FOR role_record IN SELECT id, name, permissions FROM organization_roles
  LOOP
    current_permissions := COALESCE(role_record.permissions, '{}'::jsonb);
    
    -- Add can_create_teams permission if it doesn't exist
    IF NOT (current_permissions ? 'can_create_teams') THEN
      -- Owner and admin roles get true by default, others get false
      IF role_record.name IN ('owner', 'admin') THEN
        updated_permissions := current_permissions || '{"can_create_teams": true}'::jsonb;
      ELSE
        updated_permissions := current_permissions || '{"can_create_teams": false}'::jsonb;
      END IF;
      
      -- Update the role with new permissions
      UPDATE organization_roles
      SET permissions = updated_permissions
      WHERE id = role_record.id;
    END IF;
  END LOOP;
END $$;
