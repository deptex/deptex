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

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

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
    // Get initial session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      const user = session?.user ?? null;
      setUser(user);
      setLoading(false);
      
      // Check and restore avatar if needed
      if (user) {
        checkAndRestoreAvatar(user);
      }
    });

    // Listen for auth changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setSession(session);
      const user = session?.user ?? null;
      setUser(user);
      setLoading(false);
      
      // Check and restore avatar when user logs in or session is restored
      if (user) {
        checkAndRestoreAvatar(user);
      }
    });

    return () => subscription.unsubscribe();
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

