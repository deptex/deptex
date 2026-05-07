import { describe, it, expect } from 'vitest';
import type { User } from '@supabase/supabase-js';
import { getAvatarUrl, getDisplayName, getDisplayNameOrNull } from '../userIdentity';

function makeUser(overrides: Partial<User> = {}): User {
  return {
    id: 'user-1',
    aud: 'authenticated',
    app_metadata: {},
    user_metadata: {},
    created_at: '2026-01-01T00:00:00Z',
    ...overrides,
  } as User;
}

describe('userIdentity helpers', () => {
  describe('getDisplayName', () => {
    it('prefers custom_full_name over OAuth full_name and email', () => {
      const user = makeUser({
        email: 'henry@example.com',
        user_metadata: { custom_full_name: 'Henry', full_name: 'OAuth Name' },
      });
      expect(getDisplayName(user)).toBe('Henry');
    });

    it('falls through to OAuth full_name when custom is absent', () => {
      const user = makeUser({
        email: 'henry@example.com',
        user_metadata: { full_name: 'OAuth Name' },
      });
      expect(getDisplayName(user)).toBe('OAuth Name');
    });

    it('falls through to email when no name is set', () => {
      const user = makeUser({ email: 'henry@example.com', user_metadata: {} });
      expect(getDisplayName(user)).toBe('henry@example.com');
    });

    it('returns "Account" when user is null', () => {
      expect(getDisplayName(null)).toBe('Account');
    });
  });

  describe('getDisplayNameOrNull', () => {
    it('returns null when no name is set, not the email fallback', () => {
      const user = makeUser({ email: 'henry@example.com', user_metadata: {} });
      expect(getDisplayNameOrNull(user)).toBeNull();
    });

    it('returns custom_full_name when present', () => {
      const user = makeUser({ user_metadata: { custom_full_name: 'Henry' } });
      expect(getDisplayNameOrNull(user)).toBe('Henry');
    });

    it('returns null for null user', () => {
      expect(getDisplayNameOrNull(null)).toBeNull();
    });
  });

  describe('getAvatarUrl', () => {
    it('prefers custom_avatar_url over OAuth picture and avatar_url', () => {
      const user = makeUser({
        user_metadata: {
          custom_avatar_url: 'https://example.com/custom.png',
          picture: 'https://lh3.googleusercontent.com/a/photo',
          avatar_url: 'https://avatars.githubusercontent.com/u/1',
        },
      });
      expect(getAvatarUrl(user)).toBe('https://example.com/custom.png');
    });

    it('falls through to OAuth picture (Google) when custom is absent', () => {
      const user = makeUser({
        user_metadata: { picture: 'https://lh3.googleusercontent.com/a/photo' },
      });
      expect(getAvatarUrl(user)).toBe('https://lh3.googleusercontent.com/a/photo');
    });

    it('falls through to OAuth avatar_url (GitHub) when picture is absent', () => {
      const user = makeUser({
        user_metadata: { avatar_url: 'https://avatars.githubusercontent.com/u/1' },
      });
      expect(getAvatarUrl(user)).toBe('https://avatars.githubusercontent.com/u/1');
    });

    it('returns the blank placeholder when nothing is set', () => {
      const user = makeUser({ user_metadata: {} });
      expect(getAvatarUrl(user)).toBe('/images/blank_profile_image.png');
    });

    it('returns the blank placeholder for null user', () => {
      expect(getAvatarUrl(null)).toBe('/images/blank_profile_image.png');
    });
  });
});
