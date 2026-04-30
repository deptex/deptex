import { useCallback, useEffect, useState } from 'react';
import { AlertCircle, CheckCircle2, ExternalLink, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type FixRecord, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';

interface FixStatusCardProps {
  fixId: string;
  initialFix?: FixRecord | null;
}

function statusLabel(status: FixStatus): string {
  switch (status) {
    case 'approved':
      return 'Queued — waiting for fix-worker';
    case 'executing':
      return 'Executing fix';
    case 'completed':
      return 'Fix complete';
    case 'failed':
      return 'Fix failed';
    case 'rejected':
      return 'Fix rejected';
    default:
      return 'Pending';
  }
}

export function FixStatusCard({ fixId, initialFix = null }: FixStatusCardProps) {
  const [fix, setFix] = useState<FixRecord | null>(initialFix);

  const refresh = useCallback(async () => {
    try {
      const { fix: refreshed } = await api.getFix(fixId);
      setFix(refreshed);
    } catch {
      // ignore — realtime keeps us up to date
    }
  }, [fixId]);

  useEffect(() => {
    if (!initialFix) void refresh();
  }, [initialFix, refresh]);

  useEffect(() => {
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    (async () => {
      const { data: { session } } = await supabase.auth.getSession();
      await (supabase.realtime as any).setAuth(session?.access_token ?? null);
      if (cancelled) return;
      channel = supabase
        .channel(`fix-status-${fixId}`)
        .on(
          'postgres_changes',
          { event: 'UPDATE', schema: 'public', table: 'project_security_fixes', filter: `id=eq.${fixId}` },
          () => { void refresh(); },
        )
        .subscribe();
    })();
    return () => {
      cancelled = true;
      if (channel) supabase.removeChannel(channel);
    };
  }, [fixId, refresh]);

  const status: FixStatus = fix?.status ?? 'approved';
  const label = statusLabel(status);

  const Icon =
    status === 'completed'
      ? CheckCircle2
      : status === 'failed'
        ? AlertCircle
        : Loader2;

  const tone =
    status === 'completed'
      ? 'text-success'
      : status === 'failed'
        ? 'text-destructive'
        : 'text-foreground-secondary';

  return (
    <div className="my-1 rounded-md border border-border bg-background-card px-3 py-2.5">
      <div className={cn('flex items-center gap-2 text-xs', tone)}>
        <Icon className={cn('h-3.5 w-3.5', status !== 'completed' && status !== 'failed' && status !== 'rejected' && 'animate-spin')} />
        <span>{label}</span>
        {fix?.prUrl && (
          <a
            href={fix.prUrl}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1 text-foreground hover:underline"
          >
            PR #{fix.prNumber ?? '—'}
            <ExternalLink className="h-3 w-3" />
          </a>
        )}
      </div>
      {status === 'failed' && fix?.errorMessage && (
        <div className="mt-1.5 text-xs text-foreground-secondary">{fix.errorMessage}</div>
      )}
    </div>
  );
}
