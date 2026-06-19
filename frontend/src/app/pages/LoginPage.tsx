import { useState, useEffect } from 'react';
import { Loader2, ScanSearch, KeyRound, ShieldAlert } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../../components/ui/button';
import { Link, useNavigate } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';
const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID as string | undefined;
const GIS_SRC = 'https://accounts.google.com/gsi/client';

// Google Identity Services is loaded from a <script> at runtime, so it isn't
// in the module graph — declare the minimal surface we touch.
declare global {
  interface Window {
    google?: any;
  }
}

const TYPE_MS = 60;
const BACKSPACE_MS = 40;
const HOLD_AFTER_TYPED_MS = 2200;

const AegisIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" className="h-5 w-5 shrink-0" aria-hidden>
    <path d="M12 2L4 6v5c0 5 4 8 8 10 4-2 8-5 8-10V6l-8-4z" />
    <path d="M12 9l1 2 2 1-1 2-2 1-1-2-2-1 1-2 2-1z" fill="currentColor" stroke="none" />
  </svg>
);

const CYCLING_ITEMS: { phrase: string; icon: React.ReactNode }[] = [
  { phrase: "Every finding scored by what's actually reachable", icon: <ScanSearch className="h-5 w-5 shrink-0" /> },
  { phrase: "Aegis investigates, writes the fix, and opens a PR", icon: <AegisIcon /> },
  { phrase: "Leaked secrets, caught and live-verified", icon: <KeyRound className="h-5 w-5 shrink-0" /> },
  { phrase: "Malicious packages flagged before they reach you", icon: <ShieldAlert className="h-5 w-5 shrink-0" /> },
];

function LoginTypewriterBlock() {
  const [index, setIndex] = useState(0);
  const [visibleLength, setVisibleLength] = useState(0);
  const [phase, setPhase] = useState<'typing' | 'hold' | 'backspacing'>('typing');
  const { phrase, icon } = CYCLING_ITEMS[index];

  useEffect(() => {
    if (phase !== 'hold') return;
    const t = setTimeout(() => setPhase('backspacing'), HOLD_AFTER_TYPED_MS);
    return () => clearTimeout(t);
  }, [phase]);

  useEffect(() => {
    if (phase === 'typing') {
      if (visibleLength >= phrase.length) {
        setPhase('hold');
        return;
      }
      const t = setTimeout(() => setVisibleLength((n) => n + 1), TYPE_MS);
      return () => clearTimeout(t);
    }
    if (phase === 'backspacing') {
      if (visibleLength <= 0) {
        setIndex((i) => (i + 1) % CYCLING_ITEMS.length);
        setPhase('typing');
        return;
      }
      const t = setTimeout(() => setVisibleLength((n) => n - 1), BACKSPACE_MS);
      return () => clearTimeout(t);
    }
  }, [phase, visibleLength, phrase.length]);

  return (
    <div className="flex items-center gap-3 w-full max-w-md">
      <span className="flex-shrink-0 text-white/70">
        {icon}
      </span>
      <p className="min-h-[1.5rem] text-base text-white">
        {phrase.slice(0, visibleLength)}
        <span className="animate-pulse">|</span>
      </p>
    </div>
  );
}

export default function LoginPage() {
  const { signInWithGoogleIdToken, signInWithGitHub, loading } = useAuth();
  const navigate = useNavigate();
  const [googleLoading, setGoogleLoading] = useState(false);
  const [githubLoading, setGitHubLoading] = useState(false);

  const busy = googleLoading || githubLoading;

  // Load Google Identity Services once so the Google button can open its popup.
  useEffect(() => {
    if (document.querySelector(`script[src="${GIS_SRC}"]`)) return;
    const s = document.createElement('script');
    s.src = GIS_SRC;
    s.async = true;
    s.defer = true;
    document.head.appendChild(s);
  }, []);

  // Google sign-in via the GIS popup code flow: Google runs on OUR client (so the
  // consent screen is branded to deptex.dev, not supabase.co), returns an auth
  // code, our backend swaps it for an id_token, and Supabase trades that for a
  // session. Keeps the gray button — a fully custom button can't use the simpler
  // client-side id_token flow.
  const handleGoogleSignIn = () => {
    const oauth2 = window.google?.accounts?.oauth2;
    if (!GOOGLE_CLIENT_ID || !oauth2) {
      console.error('Google sign-in unavailable: set VITE_GOOGLE_CLIENT_ID and wait for GIS to load.');
      return;
    }
    setGoogleLoading(true);

    const codeClient = oauth2.initCodeClient({
      client_id: GOOGLE_CLIENT_ID,
      scope: 'openid email profile',
      ux_mode: 'popup',
      callback: async (resp: { code?: string }) => {
        if (!resp.code) {
          setGoogleLoading(false);
          return;
        }
        try {
          const r = await fetch(`${API_BASE}/api/auth/google/exchange`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code: resp.code }),
          });
          const data = await r.json();
          if (!r.ok || !data.id_token) throw new Error(data.error || 'exchange_failed');
          await signInWithGoogleIdToken(data.id_token);
          navigate('/organizations', { replace: true });
        } catch (error) {
          console.error('Failed to sign in with Google:', error);
          setGoogleLoading(false);
        }
      },
      // Fires when the user closes/cancels the popup or it's blocked.
      error_callback: () => setGoogleLoading(false),
    });

    codeClient.requestCode();
  };

  const handleGitHubSignIn = async () => {
    setGitHubLoading(true);
    try {
      await signInWithGitHub();
    } catch (error) {
      console.error('Failed to sign in with GitHub:', error);
      setGitHubLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-foreground-muted" aria-hidden />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-background">
      {/* Left: branding - emerald, one-third width */}
      <div className="hidden lg:flex lg:w-1/3 flex-col justify-center p-12 xl:p-16 bg-emerald-900 border-r border-white/10">
        <div>
          <h2 className="text-2xl xl:text-3xl font-semibold text-white mb-4 max-w-md">
            You're signing in to Deptex
          </h2>
          <p className="text-white/90 text-base max-w-sm leading-relaxed mb-8">
            The AI-powered dependency security platform. Secure your supply chain, automate compliance, and ship with confidence.
          </p>
          <LoginTypewriterBlock />
        </div>
      </div>

      {/* Right: sign-in */}
      <div className="w-full lg:flex-1 flex flex-col justify-center p-8 sm:p-12 lg:p-16">
        <div className="w-full max-w-sm mx-auto">
          <img
            src="/images/logo_with_text.png"
            alt="Deptex"
            className="h-7 object-contain mb-8"
          />
          <h1 className="text-2xl font-semibold text-foreground mb-1">
            Welcome back
          </h1>
          <p className="text-foreground-secondary text-sm mb-8">
            Sign in to your account to continue
          </p>

          <div className="space-y-3">
            <Button
              variant="outline"
              onClick={handleGoogleSignIn}
              disabled={busy}
              className="relative w-full h-11 rounded-lg text-[15px] text-foreground [&_svg]:size-5"
            >
              <span className={`inline-flex items-center gap-2.5 ${googleLoading ? 'invisible' : ''}`}>
                <svg
                  className="h-5 w-5 shrink-0"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                  aria-hidden
                >
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                </svg>
                Continue with Google
              </span>
              {googleLoading && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-5 w-5 animate-spin" aria-hidden />
                </span>
              )}
            </Button>

            <Button
              variant="outline"
              onClick={handleGitHubSignIn}
              disabled={busy}
              className="relative w-full h-11 rounded-lg text-[15px] text-foreground [&_svg]:size-5"
            >
              <span className={`inline-flex items-center gap-2.5 ${githubLoading ? 'invisible' : ''}`}>
                <img src="/images/integrations/github.png" alt="" className="h-5 w-5 shrink-0 rounded-full" aria-hidden />
                Continue with GitHub
              </span>
              {githubLoading && (
                <span className="absolute inset-0 flex items-center justify-center">
                  <Loader2 className="h-5 w-5 animate-spin" aria-hidden />
                </span>
              )}
            </Button>
          </div>

          <p className="mt-8 text-sm text-foreground-secondary">
            By continuing, you agree to Deptex's{' '}
            <Link to="/docs/terms" className="text-foreground hover:underline">Terms of Service</Link>
            {' '}and{' '}
            <Link to="/docs/privacy" className="text-foreground hover:underline">Privacy Policy</Link>.
          </p>
        </div>
      </div>
    </div>
  );
}
