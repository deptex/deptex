-- Add manage_findings permission to all organization roles.
-- Controls ignoring / un-ignoring findings and setting their status across all
-- finding types (the unified status endpoint). Default: true for owner, false
-- for member — orgs grant it to other roles as they see fit.

UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_findings}',
  CASE
    WHEN name = 'owner' THEN 'true'::jsonb
    ELSE 'false'::jsonb
  END,
  true
);
