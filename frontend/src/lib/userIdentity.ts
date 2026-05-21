import type { User } from '@supabase/supabase-js';

const FALLBACK_AVATAR = '/images/blank_profile_image.png';

// Read priority for both helpers:
//   1. custom_*  — set by us via supabase.auth.updateUser; preserved across OAuth re-login
//   2. user_metadata provider field (picture / full_name)
//   3. user_metadata provider alt (avatar_url) — GitHub uses this key
//   4. identities[0].identity_data — raw OAuth profile. Supabase doesn't always
//      merge this into user_metadata on the first session after sign-up, so we
//      fall back to the raw identity payload before giving up.
//   5. final fallback (email for name, blank image for avatar)

function firstIdentityData(user: User): Record<string, unknown> | null {
  const id = user.identities?.[0];
  return (id?.identity_data as Record<string, unknown> | undefined) ?? null;
}

export function getDisplayName(user: User | null | undefined): string {
  if (!user) return 'Account';
  const meta = user.user_metadata ?? {};
  const id = firstIdentityData(user);
  return (
    meta.custom_full_name
    || meta.full_name
    || (id?.full_name as string | undefined)
    || (id?.name as string | undefined)
    || user.email
    || 'Account'
  );
}

export function getDisplayNameOrNull(user: User | null | undefined): string | null {
  if (!user) return null;
  const meta = user.user_metadata ?? {};
  const id = firstIdentityData(user);
  return (
    meta.custom_full_name
    || meta.full_name
    || (id?.full_name as string | undefined)
    || (id?.name as string | undefined)
    || null
  );
}

export function getAvatarUrl(user: User | null | undefined): string {
  if (!user) return FALLBACK_AVATAR;
  const meta = user.user_metadata ?? {};
  const id = firstIdentityData(user);
  return (
    meta.custom_avatar_url
    || meta.picture
    || meta.avatar_url
    || (id?.picture as string | undefined)
    || (id?.avatar_url as string | undefined)
    || FALLBACK_AVATAR
  );
}
