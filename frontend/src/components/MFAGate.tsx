import { useState, useEffect, useCallback, useRef } from 'react';
import { Loader2 } from 'lucide-react';
import { supabase } from '../lib/supabase';
import { useAuth } from '../contexts/AuthContext';
import { Button } from './ui/button';
import { Input } from './ui/input';

type AALLevel = 'aal1' | 'aal2';

interface MFAGateProps {
  children: React.ReactNode;
  /** When true and user has no MFA factors, show enrollment wizard. Use when org enforces MFA. */
  enforceMfa?: boolean;
}

export default function MFAGate({ children, enforceMfa = false }: MFAGateProps) {
  const { user, loading: authLoading } = useAuth();
  const [mfaState, setMfaState] = useState<
    'checking' | 'pass' | 'challenge' | 'enroll'
  >('checking');
  const [error, setError] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');
  const [verifyLoading, setVerifyLoading] = useState(false);

  // Enrollment state
  const [enrollFactorId, setEnrollFactorId] = useState<string | null>(null);
  const [enrollQrCode, setEnrollQrCode] = useState<string | null>(null);
  const [enrollVerifyCode, setEnrollVerifyCode] = useState('');
  const [enrollLoading, setEnrollLoading] = useState(false);
  const [enrollError, setEnrollError] = useState<string | null>(null);
  const hasStartedEnrollment = useRef(false);

  const checkMfaStatus = useCallback(async () => {
    if (!user) return;
    setMfaState('checking');
    setError(null);
    try {
      const { data, error: aalError } =
        await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      if (aalError) {
        setError(aalError.message);
        setMfaState('pass'); // Fail open to avoid blocking
        return;
      }
      const { currentLevel, nextLevel } = data as {
        currentLevel: AALLevel;
        nextLevel: AALLevel;
      };

      // aal2 + aal2 or aal2 + aal1: already verified or MFA disabled
      if (currentLevel === 'aal2' || nextLevel === 'aal1') {
        setMfaState('pass');
        return;
      }

      // aal1 + aal2: user has factors, needs to verify
      if (currentLevel === 'aal1' && nextLevel === 'aal2') {
        setMfaState('challenge');
        return;
      }

      // aal1 + aal1: no factors enrolled
      if (currentLevel === 'aal1' && nextLevel === 'aal1') {
        if (enforceMfa) {
          setMfaState('enroll');
        } else {
          setMfaState('pass');
        }
        return;
      }

      setMfaState('pass');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to check MFA status');
      setMfaState('pass');
    }
  }, [user, enforceMfa]);

  useEffect(() => {
    if (!user || authLoading) return;
    checkMfaStatus();
  }, [user, authLoading, checkMfaStatus]);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!totpCode.trim() || totpCode.length !== 6) return;
    setVerifyLoading(true);
    setError(null);
    try {
      const { data: factors, error: listError } =
        await supabase.auth.mfa.listFactors();
      if (listError) throw listError;
      const totpFactor = factors.totp?.[0];
      if (!totpFactor) {
        throw new Error('No TOTP factor found');
      }
      const { data: challenge, error: challengeError } =
        await supabase.auth.mfa.challenge({ factorId: totpFactor.id });
      if (challengeError) throw challengeError;
      const { error: verifyError } = await supabase.auth.mfa.verify({
        factorId: totpFactor.id,
        challengeId: challenge.id,
        code: totpCode.trim(),
      });
      if (verifyError) throw verifyError;
      setMfaState('pass');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setVerifyLoading(false);
    }
  };

  const startEnrollment = useCallback(async () => {
    setEnrollError(null);
    try {
      const { data, error: enrollErr } = await supabase.auth.mfa.enroll({
        factorType: 'totp',
      });
      if (enrollErr) throw enrollErr;
      setEnrollFactorId(data.id);
      setEnrollQrCode(data.totp?.qr_code ?? null);
    } catch (err) {
      setEnrollError(err instanceof Error ? err.message : 'Enrollment failed');
    }
  }, []);

  useEffect(() => {
    if (
      mfaState === 'enroll' &&
      enforceMfa &&
      !enrollQrCode &&
      !hasStartedEnrollment.current
    ) {
      hasStartedEnrollment.current = true;
      startEnrollment();
    }
  }, [mfaState, enforceMfa, enrollQrCode, startEnrollment]);

  const handleEnrollVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!enrollFactorId || !enrollVerifyCode.trim()) return;
    setEnrollLoading(true);
    setEnrollError(null);
    try {
      const { data: challenge, error: challengeError } =
        await supabase.auth.mfa.challenge({ factorId: enrollFactorId });
      if (challengeError) throw challengeError;
      const { error: verifyError } = await supabase.auth.mfa.verify({
        factorId: enrollFactorId,
        challengeId: challenge.id,
        code: enrollVerifyCode.trim(),
      });
      if (verifyError) throw verifyError;
      setMfaState('pass');
    } catch (err) {
      setEnrollError(err instanceof Error ? err.message : 'Verification failed');
    } finally {
      setEnrollLoading(false);
    }
  };

  const handleCancelEnrollment = () => {
    setEnrollFactorId(null);
    setEnrollQrCode(null);
    setEnrollVerifyCode('');
    setEnrollError(null);
    setMfaState('pass'); // Allow through; org may still enforce elsewhere
  };

  // No user or auth loading: let parent (e.g. ProtectedRoute) handle
  if (!user || authLoading) {
    return <>{children}</>;
  }

  // Still checking AAL
  if (mfaState === 'checking') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <Loader2 className="h-8 w-8 animate-spin text-foreground-secondary" />
      </div>
    );
  }

  // Enrollment wizard (org enforces MFA, no factors)
  if (mfaState === 'enroll' && enrollQrCode) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-background-card p-6 shadow-card">
          <h2 className="text-title-sm font-semibold text-foreground mb-2">
            Set up two-factor authentication
          </h2>
          <p className="text-sm text-foreground-secondary mb-4">
            Your organization requires MFA. Scan the QR code with your
            authenticator app, then enter the 6-digit code.
          </p>
          <div className="flex justify-center mb-4">
            <img
              src={enrollQrCode}
              alt="TOTP QR code"
              className="w-48 h-48 rounded border border-border"
            />
          </div>
          <form onSubmit={handleEnrollVerify} className="space-y-4">
            <Input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="000000"
              value={enrollVerifyCode}
              onChange={(e) =>
                setEnrollVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))
              }
              maxLength={6}
              className="text-center text-lg tracking-widest font-mono"
            />
            {enrollError && (
              <p className="text-sm text-error">{enrollError}</p>
            )}
            <div className="flex gap-3">
              <Button
                type="submit"
                disabled={enrollVerifyCode.length !== 6 || enrollLoading}
                className="flex-1"
              >
                {enrollLoading ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  'Enable'
                )}
              </Button>
              <Button
                type="button"
                variant="outline"
                onClick={handleCancelEnrollment}
                disabled={enrollLoading}
              >
                Cancel
              </Button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  // Enrollment loading (fetching QR) or error before QR
  if (mfaState === 'enroll' && !enrollQrCode) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-background-card p-6 shadow-card text-center">
          {enrollError ? (
            <>
              <p className="text-sm text-error mb-4">{enrollError}</p>
              <Button onClick={startEnrollment} variant="outline">
                Try again
              </Button>
            </>
          ) : (
            <Loader2 className="h-8 w-8 animate-spin text-foreground-secondary mx-auto" />
          )}
        </div>
      </div>
    );
  }

  // TOTP challenge (user has factors, needs to verify)
  if (mfaState === 'challenge') {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="w-full max-w-md rounded-lg border border-border bg-background-card p-6 shadow-card">
          <h2 className="text-title-sm font-semibold text-foreground mb-2">
            Two-factor authentication
          </h2>
          <p className="text-sm text-foreground-secondary mb-4">
            Enter the 6-digit code from your authenticator app.
          </p>
          <form onSubmit={handleVerify} className="space-y-4">
            <Input
              type="text"
              inputMode="numeric"
              autoComplete="one-time-code"
              placeholder="000000"
              value={totpCode}
              onChange={(e) =>
                setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))
              }
              maxLength={6}
              className="text-center text-lg tracking-widest font-mono"
            />
            {error && <p className="text-sm text-error">{error}</p>}
            <Button
              type="submit"
              disabled={totpCode.length !== 6 || verifyLoading}
              className="w-full"
            >
              {verifyLoading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                'Verify'
              )}
            </Button>
          </form>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
