import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate, Link } from 'react-router-dom';
import { Loader2 } from 'lucide-react';
import { supabase } from '../../lib/supabase';

export default function SSOCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [status, setStatus] = useState<'loading' | 'success' | 'error'>('loading');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  useEffect(() => {
    const token = searchParams.get('token');
    const tokenHash = searchParams.get('token_hash');
    const type = (searchParams.get('type') || 'magiclink') as
      | 'magiclink'
      | 'email'
      | 'recovery'
      | 'signup';

    if (!token && !tokenHash) {
      setErrorMessage('Missing token in callback URL');
      setStatus('error');
      return;
    }

    const verify = async () => {
      try {
        const email = searchParams.get('email');
        const { error } = tokenHash
          ? await supabase.auth.verifyOtp({ token_hash: tokenHash, type })
          : await supabase.auth.verifyOtp(
              type === 'email' && email
                ? { token: token!, type, email }
                : ({ token: token!, type } as Parameters<typeof supabase.auth.verifyOtp>[0])
            );
        if (error) {
          setErrorMessage(error.message);
          setStatus('error');
          return;
        }
        setStatus('success');
        navigate('/organizations', { replace: true });
      } catch (err) {
        setErrorMessage(err instanceof Error ? err.message : 'Verification failed');
        setStatus('error');
      }
    };

    verify();
  }, [searchParams, navigate]);

  if (status === 'loading') {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-background p-4">
        <Loader2 className="h-10 w-10 animate-spin text-foreground-secondary mb-4" />
        <p className="text-foreground-secondary">Verifying your sign-in...</p>
      </div>
    );
  }

  if (status === 'error') {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-background p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-background-card p-6 shadow-card text-center">
          <h2 className="text-title-sm font-semibold text-foreground mb-2">
            Sign-in failed
          </h2>
          <p className="text-sm text-foreground-secondary mb-4">
            {errorMessage}
          </p>
          <Link
            to="/login"
            className="inline-flex items-center justify-center rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            Try again
          </Link>
        </div>
      </div>
    );
  }

  // success: redirecting (brief flash before navigate)
  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background p-4">
      <Loader2 className="h-10 w-10 animate-spin text-foreground-secondary mb-4" />
      <p className="text-foreground-secondary">Redirecting...</p>
    </div>
  );
}
