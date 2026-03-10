-- Add default_organization_id to user_profiles for "main org" UX
-- When set, logged-in users land in this org; ON DELETE SET NULL if org is removed

ALTER TABLE user_profiles
  ADD COLUMN IF NOT EXISTS default_organization_id UUID REFERENCES organizations(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS idx_user_profiles_default_organization_id
  ON user_profiles(default_organization_id);
