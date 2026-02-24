import { useEffect, useState } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

const API_BASE = import.meta.env.VITE_API_BASE_URL || (typeof window !== 'undefined' ? `${window.location.protocol}//${window.location.hostname}:3001` : 'http://localhost:3001');

/**
 * GitHub OAuth callback route. GitHub redirects here (so it shows "Redirect to yourapp.com").
 * We exchange the code with our backend, then redirect to the returned magic link to establish the session.
 */
export default function AuthCallbackPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const code = searchParams.get('code');
    const state = searchParams.get('state');
    const err = searchParams.get('error');

    if (err) {
      setError(searchParams.get('error_description') || err);
      return;
    }
    if (!code) {
      setError('No authorization code');
      return;
    }

    const base = API_BASE.replace(/\/$/, '');
    fetch(`${base}/api/auth/github/exchange`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, state: state || undefined }),
    })
      .then((r) => r.json())
      .then((data) => {
        if (data.error) {
          setError(data.error);
          return;
        }
        if (data.magicLinkUrl) {
          window.location.href = data.magicLinkUrl;
          return;
        }
        setError('Invalid response');
      })
      .catch((e) => setError(e.message || 'Exchange failed'));
  }, [searchParams]);

  if (error) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-background p-4">
        <p className="text-foreground-secondary mb-4">{error}</p>
        <button
          type="button"
          onClick={() => navigate('/login', { replace: true })}
          className="text-primary hover:underline"
        >
          Back to login
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-background">
      <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mb-4" />
      <p className="text-sm text-foreground-secondary">Signing you in…</p>
    </div>
  );
}
