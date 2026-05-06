-- Move avatar_url + full_name from user_profiles into auth.users.raw_user_meta_data
-- as custom_avatar_url + custom_full_name. The custom_ prefix prevents OAuth
-- providers from overwriting these fields on re-login (OAuth re-populates
-- provider-owned keys like picture, full_name, avatar_url; custom_* keys are
-- preserved).
--
-- After this migration, identity data rides along with the JWT — chrome widgets
-- read user.user_metadata.custom_* directly, no /api/user-profile fetch needed.
-- user_profiles retains only default_organization_id (which has a real FK).

UPDATE auth.users u
SET raw_user_meta_data = COALESCE(u.raw_user_meta_data, '{}'::jsonb)
  || jsonb_strip_nulls(jsonb_build_object(
    'custom_full_name', up.full_name,
    'custom_avatar_url', up.avatar_url
  ))
FROM public.user_profiles up
WHERE u.id = up.user_id
  AND (up.full_name IS NOT NULL OR up.avatar_url IS NOT NULL);

ALTER TABLE public.user_profiles DROP COLUMN IF EXISTS full_name;
ALTER TABLE public.user_profiles DROP COLUMN IF EXISTS avatar_url;
