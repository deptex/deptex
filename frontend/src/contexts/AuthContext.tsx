import { createContext, useContext, useEffect, useState, ReactNode } from 'react';
import { User, Session } from '@supabase/supabase-js';
import { supabase } from '../lib/supabase';
import { clearOverviewCache } from '../lib/overview-cache';

interface AuthContextType {
  user: User | null;
  session: Session | null;
  loading: boolean;
  signInWithGoogle: () => Promise<void>;
  signInWithGoogleIdToken: (idToken: string) => Promise<void>;
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

  useEffect(() => {
    // Get initial session (for fast first paint). Do NOT set loading=false here —
    // getSession() can return null during token refresh; wait for INITIAL_SESSION.
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      // Push the initial token to the realtime socket so private-channel RLS
      // evaluates auth.uid() correctly. Without this, realtime.messages policies
      // silently reject broadcasts after the first token refresh.
      supabase.realtime.setAuth(session?.access_token ?? null);
    });

    // Only consider auth "ready" when Supabase emits INITIAL_SESSION (after any refresh).
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
      // Keep the realtime socket's JWT in sync on every auth transition so
      // long sessions don't silently break when Supabase rotates the token.
      supabase.realtime.setAuth(session?.access_token ?? null);
      if (event === 'INITIAL_SESSION') {
        setLoading(false);
      }
    });

    // Safety: if INITIAL_SESSION hasn't fired within 2s, stop loading (edge cases).
    const fallbackTimer = setTimeout(() => setLoading(false), 2000);

    return () => {
      subscription.unsubscribe();
      clearTimeout(fallbackTimer);
    };
  }, []);

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

  // Used by the login page's Google ID-token flow: the frontend runs Google
  // OAuth on our own client/domain (so the consent screen shows deptex.dev, not
  // the supabase.co callback), exchanges the code for an id_token server-side,
  // then trades that id_token for a Supabase session here.
  const signInWithGoogleIdToken = async (idToken: string) => {
    const { error } = await supabase.auth.signInWithIdToken({
      provider: 'google',
      token: idToken,
    });
    if (error) {
      console.error('Error signing in with Google ID token:', error);
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
    Object.keys(localStorage)
      .filter((k) => k.startsWith('user_profile_'))
      .forEach((k) => localStorage.removeItem(k));
    // Drop the cached org-overview bundles so the next user in this browser never
    // paints the previous user's permission-scoped view.
    clearOverviewCache();
    const { error } = await supabase.auth.signOut();
    if (error) {
      console.error('Error signing out:', error);
      throw error;
    }
    // Notify in-memory caches (org switcher etc.) so they don't leak to the
    // next user that signs in within the same tab session.
    window.dispatchEvent(new Event('auth:signedOut'));
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        session,
        loading,
        signInWithGoogle,
        signInWithGoogleIdToken,
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

