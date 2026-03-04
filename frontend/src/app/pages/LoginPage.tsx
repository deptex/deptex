import { useState, useEffect } from 'react';
import { Loader2, Lock, Scale, Bell, Telescope, ScanSearch } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../../components/ui/button';
import { useSearchParams, useNavigate, useLocation } from 'react-router-dom';
import { Link } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';

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
  { phrase: "Try our custom policy as code", icon: <Scale className="h-5 w-5 shrink-0" /> },
  { phrase: "Check out our integrations — connect anything you want", icon: <Bell className="h-5 w-5 shrink-0" /> },
  { phrase: "Aegis AI that investigates, fixes, and reports", icon: <AegisIcon /> },
  { phrase: "Supply chain forensics and Watchtower", icon: <Telescope className="h-5 w-5 shrink-0" /> },
  { phrase: "Dependency intelligence with reachability", icon: <ScanSearch className="h-5 w-5 shrink-0" /> },
  { phrase: "SBOM and compliance made simple", icon: <Scale className="h-5 w-5 shrink-0" /> },
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
  const { signInWithGoogle, signInWithGitHub, loading } = useAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const location = useLocation();
  const ssoError = searchParams.get('sso_error');
  const showSSO = searchParams.get('sso') === '1';

  const [ssoEmail, setSsoEmail] = useState('');
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoCheckError, setSsoCheckError] = useState<string | null>(null);
  const [googleLoading, setGoogleLoading] = useState(false);
  const [githubLoading, setGitHubLoading] = useState(false);

  // Clear SSO form state when user goes back to main sign-in (e.g. via browser back)
  useEffect(() => {
    if (!showSSO) {
      setSsoEmail('');
      setSsoCheckError(null);
    }
  }, [showSSO]);

  const openSSOView = () => {
    const next = new URLSearchParams(searchParams);
    next.set('sso', '1');
    navigate({ pathname: location.pathname, search: next.toString() });
  };

  const handleGoogleSignIn = async () => {
    setGoogleLoading(true);
    try {
      await signInWithGoogle();
    } catch (error) {
      console.error('Failed to sign in with Google:', error);
      setGoogleLoading(false);
    }
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

  const handleSSOContinue = async () => {
    if (!ssoEmail || !ssoEmail.includes('@')) {
      setSsoCheckError('Please enter a valid email address');
      return;
    }
    setSsoLoading(true);
    setSsoCheckError(null);

    try {
      const resp = await fetch(`${API_BASE}/api/sso/check?email=${encodeURIComponent(ssoEmail)}`);
      const data = await resp.json();

      if (data.has_sso) {
        window.location.href = `${API_BASE}/api/sso/login?email=${encodeURIComponent(ssoEmail)}`;
      } else {
        setSsoCheckError('No SSO configured for this domain. Use Google or GitHub to sign in.');
        setSsoLoading(false);
      }
    } catch {
      setSsoCheckError('Failed to check SSO configuration');
      setSsoLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex bg-background">
      {/* Left: branding - dark green, one-third width */}
      <div className="hidden lg:flex lg:w-1/3 flex-col justify-between p-12 xl:p-16 bg-[#012a18] border-r border-white/10">
        <div>
          <h2 className="text-2xl xl:text-3xl font-semibold text-white mb-4 max-w-md">
            You're signing in to Deptex
          </h2>
          <p className="text-white/90 text-base max-w-sm leading-relaxed mb-8">
            The AI-powered dependency security platform. Secure your supply chain, automate compliance, and ship with confidence.
          </p>
          <LoginTypewriterBlock />
        </div>
        <p className="text-sm text-white/60">
          Trusted by engineering and security teams
        </p>
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

          {ssoError && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
              SSO login failed. Please try again or use another sign-in method.
            </div>
          )}

          {!showSSO ? (
            <>
              <div className="space-y-3">
                <Button
                  onClick={handleGoogleSignIn}
                  disabled={googleLoading || githubLoading}
                  className="w-full bg-background-card border border-border hover:bg-background-subtle text-foreground h-11"
                  size="lg"
                >
                  {googleLoading ? (
                    <Loader2 className="mr-2.5 h-5 w-5 shrink-0 animate-spin" aria-hidden />
                  ) : (
                    <svg
                      className="mr-2.5 h-5 w-5 shrink-0"
                      viewBox="0 0 24 24"
                      fill="currentColor"
                      aria-hidden
                    >
                      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                    </svg>
                  )}
                  Continue with Google
                </Button>

                <Button
                  onClick={handleGitHubSignIn}
                  disabled={googleLoading || githubLoading}
                  className="w-full bg-background-card border border-border hover:bg-background-subtle text-foreground h-11"
                  size="lg"
                >
                  {githubLoading ? (
                    <Loader2 className="mr-2.5 h-5 w-5 shrink-0 animate-spin" aria-hidden />
                  ) : (
                    <img src="/images/integrations/github.png" alt="" className="mr-2.5 h-5 w-5 shrink-0 rounded-full" aria-hidden />
                  )}
                  Continue with GitHub
                </Button>
              </div>

              <div className="relative my-6">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-border"></div>
                </div>
                <div className="relative flex justify-center text-xs uppercase tracking-wider">
                  <span className="bg-background px-2 text-foreground-muted">or</span>
                </div>
              </div>

              <Button
                onClick={openSSOView}
                className="w-full bg-background-card border border-border hover:bg-background-subtle text-foreground h-11"
                size="lg"
              >
                <Lock className="mr-2.5 h-5 w-5 shrink-0" />
                Sign in with SSO
              </Button>
            </>
          ) : (
            <div className="space-y-4">
              <div>
                <label htmlFor="login-work-email" className="demo-page-label block text-sm font-medium mb-1.5">
                  Work email
                </label>
                <input
                  id="login-work-email"
                  type="email"
                  value={ssoEmail}
                  onChange={(e) => setSsoEmail(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleSSOContinue()}
                  placeholder="you@company.com"
                  className="demo-page-input w-full px-3 py-2.5 rounded-lg text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all placeholder:text-white/[0.2]"
                  autoFocus
                />
              </div>

              {ssoCheckError && (
                <p className="text-sm text-red-400">{ssoCheckError}</p>
              )}

              <Button
                onClick={handleSSOContinue}
                disabled={ssoLoading || !ssoEmail}
                className="w-full h-11 bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 font-semibold"
                size="lg"
              >
                {ssoLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin shrink-0" /> : <Lock className="mr-2 h-4 w-4 shrink-0" />}
                Sign in
              </Button>
            </div>
          )}

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
