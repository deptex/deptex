-- Allow the same GitHub App installation to be connected to multiple organizations.
-- Drops the unique index on organizations.github_installation_id.

DROP INDEX IF EXISTS idx_organizations_github_installation_id_unique;

COMMENT ON COLUMN organizations.github_installation_id IS
  'GitHub App installation ID for this organization. Multiple orgs may share the same installation.';
