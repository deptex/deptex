import { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { api } from '../lib/api';

interface UserProfile {
  user_id: string;
  avatar_url: string | null;
  full_name: string | null;
}

const CACHE_KEY_PREFIX = 'user_profile_';
const CACHE_EXPIRY = 5 * 60 * 1000; // 5 minutes

function getCachedProfile(userId: string): UserProfile | null {
  try {
    const cached = localStorage.getItem(`${CACHE_KEY_PREFIX}${userId}`);
    if (!cached) return null;
    
    const { data, timestamp } = JSON.parse(cached);
    if (Date.now() - timestamp > CACHE_EXPIRY) {
      localStorage.removeItem(`${CACHE_KEY_PREFIX}${userId}`);
      return null;
    }
    
    return data;
  } catch {
    return null;
  }
}

function setCachedProfile(userId: string, profile: UserProfile) {
  try {
    localStorage.setItem(`${CACHE_KEY_PREFIX}${userId}`, JSON.stringify({
      data: profile,
      timestamp: Date.now(),
    }));
  } catch {
    // Ignore localStorage errors
  }
}

export function useUserProfile() {
  const { user } = useAuth();
  
  // Initialize with cached data immediately to prevent flash
  const [profile, setProfile] = useState<UserProfile | null>(() => {
    if (user?.id) {
      return getCachedProfile(user.id);
    }
    return null;
  });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!user?.id) {
      setProfile(null);
      setLoading(false);
      return;
    }

    // Load from cache immediately to prevent flash (if not already set)
    const cached = getCachedProfile(user.id);
    if (cached && !profile) {
      setProfile(cached);
      setLoading(false);
    }

    // Then fetch fresh data
    const loadProfile = async () => {
      try {
        const data = await api.getUserProfile();
        setProfile(data);
        setCachedProfile(user.id, data);
      } catch (error) {
        console.error('Failed to load user profile:', error);
        // If fetch fails and we have cache, keep using cache
        if (!cached && !profile) {
          setProfile(null);
        }
      } finally {
        setLoading(false);
      }
    };

    loadProfile();
  }, [user?.id]);

  // Get avatar URL with priority:
  // 1. Database profile (user_profiles table)
  // 2. OAuth metadata picture (from raw_user_meta_data.picture)
  // 3. OAuth metadata avatar_url (from raw_user_meta_data.avatar_url)
  // 4. Fallback image as last resort
  const avatarUrl = profile?.avatar_url 
    || user?.user_metadata?.picture 
    || user?.user_metadata?.avatar_url 
    || '/images/blank_profile_image.png';
  const fullName = profile?.full_name || user?.user_metadata?.full_name || null;

  return {
    profile,
    avatarUrl,
    fullName,
    loading,
  };
}

