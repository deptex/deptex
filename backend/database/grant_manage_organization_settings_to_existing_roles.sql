-- Backfill manage_organization_settings on existing organization_roles rows.
-- The permission was added to backend route gates without a corresponding
-- update to the seed in routes/organizations.ts, so older roles miss it.
-- Grant to any role that already has manage_billing (admin-class proxy).

UPDATE organization_roles
SET permissions = permissions || '{"manage_organization_settings": true}'::jsonb
WHERE (permissions->>'manage_billing')::boolean = true
  AND (permissions->'manage_organization_settings') IS NULL;
