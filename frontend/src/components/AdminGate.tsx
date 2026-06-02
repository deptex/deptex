import { ReactNode, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { Navigate } from 'react-router-dom';
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

  // Non-admins are bounced to the homepage rather than shown a dead-end screen.
  if (status === 'denied') {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}
