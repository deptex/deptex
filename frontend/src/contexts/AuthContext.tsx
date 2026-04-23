import { createContext, useContext, useEffect, useState, useCallback, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '../lib/supabase';

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInWithGitHub: () => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Read the cached Supabase session from localStorage synchronously.
// Returns the user regardless of token expiry — INITIAL_SESSION confirms/refreshes.
// Returns null only when there is genuinely no stored session at all.
function getCachedUser(): User | null {
  try {
    const key = Object.keys(localStorage).find(
      (k) => k.startsWith('sb-') && k.endsWith('-auth-token')
    );
    if (!key) return null;
    const stored = JSON.parse(localStorage.getItem(key) ?? 'null');
    return (stored?.user as User) ?? null;
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(getCachedUser);
  const [session, setSession] = useState<Session | null>(null);
  // loading=true only when there is no cached session — meaning we don't yet know
  // if the user is authenticated and ProtectedRoute must wait before redirecting.
  // When there IS a cached user, we already know the state; loading stays false.
  const [loading, setLoading] = useState(() => getCachedUser() === null);

  // Check and restore avatar if missing from profile but exists in storage or OAuth metadata
  const checkAndRestoreAvatar = useCallback(async (user: User | null) => {
    if (!user?.id) return;
    
    try {
      // Check user profile first
      const { api } = await import('../lib/api');
      const profile = await api.getUserProfile();
      if (profile.avatar_url) return; // Already has avatar in profile
      
      // Check for OAuth profile picture (Google, GitHub, etc.)
      // Priority: picture first, then avatar_url
      const oauthPicture = user.user_metadata?.picture || user.user_metadata?.avatar_url;
      if (oauthPicture) {
        // Sync OAuth profile picture to user_profiles table
        await api.updateUserProfile({ avatar_url: oauthPicture });
        console.log('OAuth avatar synced to user profile');
        return;
      }
      
      // List files in the user's avatar folder
      const { data: files, error } = await supabase.storage
        .from('avatars')
        .list(user.id, {
          limit: 1,
          sortBy: { column: 'created_at', order: 'desc' }
        });
      
      if (error) {
        // Silently fail - storage might not be accessible or folder doesn't exist yet
        return;
      }
      
      // If we found a file, restore the avatar_url in profile
      if (files && files.length > 0) {
        const filePath = `${user.id}/${files[0].name}`;
        const { data: { publicUrl } } = supabase.storage
          .from('avatars')
          .getPublicUrl(filePath);
        
        // Update user profile with the restored avatar URL
        await api.updateUserProfile({ avatar_url: publicUrl });
        console.log('Avatar restored from storage to user profile');
      }
    } catch (error) {
      // Silently fail - don't interrupt the login flow
      console.error('Error in checkAndRestoreAvatar:', error);
    }
  }, []);

  useEffect(() => {
    // Get initial session (for fast first paint). Do NOT set loading=false here —
    // getSession() can return null during token refresh; wait for INITIAL_SESSION.
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      const user = session?.user ?? null;
      setUser(user);
      // Check and restore avatar if needed
      if (user) {
        checkAndRestoreAvatar(user);
      }
    });

    // Only consider auth "ready" when Supabase emits INITIAL_SESSION (after any refresh).
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event, session) => {
      setSession(session);
      const user = session?.user ?? null;
      setUser(user);
      if (event === 'INITIAL_SESSION') {
        setLoading(false);
      }
      // Check and restore avatar when user logs in or session is restored
      if (user) {
        checkAndRestoreAvatar(user);
      }
    });

    // Safety: if INITIAL_SESSION hasn't fired within 2s, stop loading (edge cases).
    const fallbackTimer = setTimeout(() => setLoading(false), 2000);

    return () => {
      subscription.unsubscribe();
      clearTimeout(fallbackTimer);
    };
  }, [checkAndRestoreAvatar]);

  const signInWithGoogle = async () => {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'google',
      options: {
        redirectTo: `${window.location.origin}/organizations`,
      },
    });
    if (error) {
      console.error('Error signing in with Google:', error);
      throw error;
    }
  };

  const signInWithGitHub = async () => {
    const { error } = await supabase.auth.signInWithOAuth({
      provider: 'github',
      options: {
        redirectTo: `${window.location.origin}/organizations`,
      },
    });
    if (error) {
      console.error('Error signing in with GitHub:', error);
      throw error;
    }
  };

  const signOut = async () => {
    localStorage.removeItem('deptex_default_org');
    const { error } = await supabase.auth.signOut();
    if (error) {
      console.error('Error signing out:', error);
      throw error;
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        session,
        loading,
        signInWithGoogle,
        signInWithGitHub,
        signOut,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

