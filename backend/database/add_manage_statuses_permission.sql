-- Add manage_statuses permission to all organization roles.
-- Controls CRUD on custom statuses AND asset tiers.
-- Default: true for owner, false for member.

UPDATE organization_roles
SET permissions = jsonb_set(
  COALESCE(permissions, '{}'::jsonb),
  '{manage_statuses}',
  CASE
    WHEN name = 'owner' THEN 'true'::jsonb
    ELSE 'false'::jsonb
  END,
  true
);
