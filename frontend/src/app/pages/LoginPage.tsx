import { useState } from 'react';
import { Github, Building2, ArrowLeft, Loader2 } from 'lucide-react';
import { useAuth } from '../../contexts/AuthContext';
import { Button } from '../../components/ui/button';
import { useSearchParams } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:3001';

export default function LoginPage() {
  const { signInWithGoogle, signInWithGitHub, loading } = useAuth();
  const [searchParams] = useSearchParams();
  const ssoError = searchParams.get('sso_error');

  const [showSSO, setShowSSO] = useState(false);
  const [ssoEmail, setSsoEmail] = useState('');
  const [ssoLoading, setSsoLoading] = useState(false);
  const [ssoCheckError, setSsoCheckError] = useState<string | null>(null);

  const handleGoogleSignIn = async () => {
    try {
      await signInWithGoogle();
    } catch (error) {
      console.error('Failed to sign in with Google:', error);
    }
  };

  const handleGitHubSignIn = async () => {
    try {
      await signInWithGitHub();
    } catch (error) {
      console.error('Failed to sign in with GitHub:', error);
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
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background">
      <div className="w-full max-w-md p-8">
        <div className="text-center mb-8">
          <img
            src="/images/logo.png"
            alt="Deptex"
            className="h-12 mx-auto mb-4"
          />
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Welcome to Deptex
          </h1>
          <p className="text-foreground-secondary">
            Sign in to continue to your account
          </p>
        </div>

        {ssoError && (
          <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg text-sm text-red-400">
            SSO login failed. Please try again or use another sign-in method.
          </div>
        )}

        {!showSSO ? (
          <>
            <div className="space-y-4">
              <Button
                onClick={handleGoogleSignIn}
                className="w-full bg-background-card border border-border hover:bg-background-subtle text-foreground"
                size="lg"
              >
                <svg
                  className="mr-2 h-5 w-5"
                  viewBox="0 0 24 24"
                  fill="currentColor"
                >
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4" />
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
                </svg>
                Continue with Google
              </Button>

              <Button
                onClick={handleGitHubSignIn}
                className="w-full bg-background-card border border-border hover:bg-background-subtle text-foreground"
                size="lg"
              >
                <Github className="mr-2 h-5 w-5" />
                Continue with GitHub
              </Button>
            </div>

            <div className="relative my-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-border"></div>
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-background px-2 text-foreground-secondary">or</span>
              </div>
            </div>

            <Button
              onClick={() => setShowSSO(true)}
              variant="outline"
              className="w-full border-border text-foreground-secondary hover:text-foreground"
              size="lg"
            >
              <Building2 className="mr-2 h-4 w-4" />
              Sign in with SSO
            </Button>
          </>
        ) : (
          <div className="space-y-4">
            <button
              onClick={() => { setShowSSO(false); setSsoCheckError(null); }}
              className="flex items-center gap-1 text-sm text-foreground-secondary hover:text-foreground transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Back to sign in
            </button>

            <div>
              <label className="block text-sm font-medium text-foreground mb-1.5">
                Work email
              </label>
              <input
                type="email"
                value={ssoEmail}
                onChange={(e) => setSsoEmail(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleSSOContinue()}
                placeholder="you@company.com"
                className="w-full px-3 py-2.5 bg-background border border-border rounded-lg text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary/50 focus:border-primary transition-all"
                autoFocus
              />
            </div>

            {ssoCheckError && (
              <p className="text-sm text-red-400">{ssoCheckError}</p>
            )}

            <Button
              onClick={handleSSOContinue}
              disabled={ssoLoading || !ssoEmail}
              className="w-full"
              size="lg"
            >
              {ssoLoading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Building2 className="mr-2 h-4 w-4" />}
              Continue with SSO
            </Button>
          </div>
        )}

        <p className="mt-6 text-center text-sm text-foreground-secondary">
          By continuing, you agree to Deptex's Terms of Service and Privacy Policy
        </p>
      </div>
    </div>
  );
}
