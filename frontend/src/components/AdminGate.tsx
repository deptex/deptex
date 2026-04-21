import { ReactNode, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { apiAdminPing } from '../lib/api';

type Status = 'pending' | 'ok' | 'denied';

interface AdminGateProps {
  children: ReactNode;
}

export default function AdminGate({ children }: AdminGateProps) {
  const [status, setStatus] = useState<Status>('pending');

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const resp = await apiAdminPing();
        if (cancelled) return;
        setStatus(resp?.ok ? 'ok' : 'denied');
      } catch {
        if (!cancelled) setStatus('denied');
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  if (status === 'pending') {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-primary" />
      </div>
    );
  }

  if (status === 'denied') {
    return (
      <div className="min-h-screen flex items-center justify-center px-4">
        <div className="max-w-md w-full rounded-lg border border-border bg-background-card p-6 text-center">
          <h2 className="text-lg font-semibold text-foreground mb-2">Access denied</h2>
          <p className="text-sm text-foreground-secondary">
            You don't have access to this page.
          </p>
        </div>
      </div>
    );
  }

  return <>{children}</>;
}
