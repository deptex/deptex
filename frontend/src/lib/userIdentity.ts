import type { User } from '@supabase/supabase-js';

const FALLBACK_AVATAR = '/images/blank_profile_image.png';

// Read priority for both helpers:
//   1. custom_*  — set by us via supabase.auth.updateUser; preserved across OAuth re-login
//   2. provider field (picture / full_name) — populated by OAuth on every login
//   3. provider alt (avatar_url) — GitHub uses this key
//   4. final fallback (email for name, blank image for avatar)

export function getDisplayName(user: User | null | undefined): string {
  if (!user) return 'Account';
  const meta = user.user_metadata ?? {};
  return meta.custom_full_name || meta.full_name || user.email || 'Account';
}

export function getDisplayNameOrNull(user: User | null | undefined): string | null {
  if (!user) return null;
  const meta = user.user_metadata ?? {};
  return meta.custom_full_name || meta.full_name || null;
}

export function getAvatarUrl(user: User | null | undefined): string {
  if (!user) return FALLBACK_AVATAR;
  const meta = user.user_metadata ?? {};
  return meta.custom_avatar_url || meta.picture || meta.avatar_url || FALLBACK_AVATAR;
}
