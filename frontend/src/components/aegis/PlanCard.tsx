import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Loader2, RefreshCw, ShieldOff, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type FixRecord, type FixPlan, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';

interface PlanCardProps {
  fixId: string;
  initialFix?: FixRecord | null;
  initialPlan?: FixPlan | null;
  onStatusChange?: (status: FixStatus) => void;
}

interface StalenessState {
  isStale: boolean;
  currentHeadSha: string | null;
  loaded: boolean;
}

const TERMINAL_STATUSES: readonly FixStatus[] = [
  'completed',
  'failed',
  'rejected',
];

function StatusPill({ status }: { status: FixStatus }) {
  if (status === 'planning') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-foreground-secondary border border-border">
        <Loader2 className="h-3 w-3 animate-spin" />
        Generating plan
      </span>
    );
  }
  if (status === 'awaiting_approval') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-warning/10 text-warning border border-warning/30">
        Awaiting approval
      </span>
    );
  }
  if (status === 'approved' || status === 'executing') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-blue-500/10 text-blue-300 border border-blue-500/30">
        <Loader2 className="h-3 w-3 animate-spin" />
        {status === 'approved' ? 'Approved · queued' : 'Executing'}
      </span>
    );
  }
  if (status === 'completed') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-success/10 text-success border border-success/30">
        <CheckCircle2 className="h-3 w-3" />
        Completed
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-destructive/10 text-destructive border border-destructive/30">
        <AlertTriangle className="h-3 w-3" />
        Failed
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium bg-zinc-500/10 text-foreground-secondary border border-border">
      <X className="h-3 w-3" />
      Rejected
    </span>
  );
}

function SectionLabel({ children }: { children: React.ReactNode }) {
  return (
    <div className="text-[10px] uppercase tracking-wider text-foreground-secondary mb-1.5">
      {children}
    </div>
  );
}

function BulletList({ items }: { items: string[] }) {
  if (items.length === 0) return null;
  return (
    <ul className="text-sm text-foreground space-y-1">
      {items.map((b, i) => (
        <li key={i} className="flex gap-2">
          <span className="text-foreground-secondary">•</span>
          <span>{b}</span>
        </li>
      ))}
    </ul>
  );
}

export function PlanCard({
  fixId,
  initialFix = null,
  initialPlan = null,
  onStatusChange,
}: PlanCardProps) {
  const [fix, setFix] = useState<FixRecord | null>(initialFix);
  const [plan, setPlan] = useState<FixPlan | null>(initialPlan ?? initialFix?.plan ?? null);
  const token = fix?.approvalToken ?? null;
  const [busy, setBusy] = useState<'approve' | 'reject' | 'regenerate' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [staleness, setStaleness] = useState<StalenessState>({
    isStale: false,
    currentHeadSha: null,
    loaded: false,
  });

  const status: FixStatus = fix?.status ?? 'planning';

  const refresh = useCallback(async () => {
    try {
      const { fix: refreshed } = await api.getFix(fixId);
      setFix(refreshed);
      if (refreshed.plan) setPlan(refreshed.plan);
      onStatusChange?.(refreshed.status);
    } catch {
      // ignore — realtime will fill in eventually
    }
  }, [fixId, onStatusChange]);

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
        .channel(`fix-${fixId}`)
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

  // Staleness check (one-shot on mount, then poll every 60s while
  // awaiting_approval). Cheap: 1 GitHub API call per fix per minute.
  useEffect(() => {
    if (status !== 'awaiting_approval') return;
    let cancelled = false;
    const tick = async () => {
      try {
        const s = await api.getFixStaleness(fixId);
        if (cancelled) return;
        setStaleness({ isStale: s.isStale, currentHeadSha: s.currentHeadSha, loaded: true });
      } catch {
        if (cancelled) return;
        setStaleness((prev) => ({ ...prev, loaded: true }));
      }
    };
    void tick();
    const id = setInterval(tick, 60_000);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [fixId, status]);

  const handleApprove = useCallback(async () => {
    if (!token) {
      setError('No approval token — try refreshing the plan.');
      return;
    }
    setBusy('approve');
    setError(null);
    try {
      const { fix: updated } = await api.approveFix(fixId, token);
      setFix(updated);
      onStatusChange?.(updated.status);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to approve');
    } finally {
      setBusy(null);
    }
  }, [fixId, token, onStatusChange]);

  const handleReject = useCallback(async () => {
    setBusy('reject');
    setError(null);
    try {
      const { fix: updated } = await api.rejectFix(fixId);
      setFix(updated);
      onStatusChange?.(updated.status);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to reject');
    } finally {
      setBusy(null);
    }
  }, [fixId, onStatusChange]);

  const handleRegenerate = useCallback(async () => {
    setBusy('regenerate');
    setError(null);
    try {
      const res = await api.regenerateFixPlan(fixId);
      if (res.fix) setFix(res.fix);
      if (res.plan) setPlan(res.plan);
      onStatusChange?.(res.status);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to regenerate');
    } finally {
      setBusy(null);
    }
  }, [fixId, onStatusChange]);

  if (status === 'planning' && !plan) {
    return (
      <div className="rounded-lg border border-border bg-background-card overflow-hidden">
        <div className="px-5 py-3.5 border-b border-border flex items-center justify-between">
          <div className="text-sm font-semibold text-foreground">Generating plan…</div>
          <StatusPill status="planning" />
        </div>
        <div className="px-5 py-4 space-y-3">
          <div className="h-3 w-3/4 rounded bg-muted/50 animate-pulse" />
          <div className="h-3 w-2/3 rounded bg-muted/50 animate-pulse" />
          <div className="h-3 w-1/2 rounded bg-muted/40 animate-pulse" />
        </div>
      </div>
    );
  }

  if (!plan) {
    return (
      <div className="rounded-lg border border-border bg-background-card px-5 py-4">
        <div className="text-sm text-foreground-secondary">Plan unavailable.</div>
      </div>
    );
  }

  const refusal = plan.refusal;
  const findingLabel =
    plan.finding.type === 'vulnerability'
      ? plan.finding.id
      : plan.finding.type === 'semgrep'
        ? `Code finding ${plan.finding.id}`
        : `Secret ${plan.finding.id}`;

  return (
    <div className="rounded-lg border border-border bg-background-card overflow-hidden">
      <div className="px-5 py-3.5 border-b border-border flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-foreground truncate">{plan.summary}</div>
          <div className="mt-0.5 text-xs text-foreground-secondary">
            {findingLabel}
            {plan.finding.severity && (
              <>
                <span className="mx-1.5 text-foreground/30">·</span>
                <span className="capitalize">{plan.finding.severity}</span>
              </>
            )}
          </div>
        </div>
        <StatusPill status={status} />
      </div>

      {refusal ? (
        <div className="px-5 py-4 space-y-3">
          <div className="flex gap-2.5 items-start text-sm text-foreground">
            <ShieldOff className="h-4 w-4 mt-0.5 text-warning shrink-0" />
            <div>
              <div className="font-medium">Aegis can&apos;t safely fix this.</div>
              <div className="text-foreground-secondary mt-1">{refusal.reason}</div>
              {refusal.manualSuggestion && (
                <div className="mt-2 rounded-md border border-border bg-background-subtle px-3 py-2 text-xs text-foreground-secondary">
                  {refusal.manualSuggestion}
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="px-5 py-4 space-y-4">
          <div>
            <SectionLabel>Current state</SectionLabel>
            <BulletList items={plan.currentState} />
          </div>
          <div>
            <SectionLabel>Desired state</SectionLabel>
            <BulletList items={plan.desiredState} />
          </div>
          {plan.fileChanges.length > 0 && (
            <div>
              <SectionLabel>Files to change</SectionLabel>
              <ul className="text-sm text-foreground space-y-1">
                {plan.fileChanges.map((c, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="text-foreground-secondary">•</span>
                    <span className="font-mono text-xs">{c.path}</span>
                    <span className="text-foreground-secondary">— {c.description}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="text-sm text-foreground-secondary font-mono">
            Tests: <span className="text-foreground">{plan.testCommand}</span>
          </div>
          {status === 'awaiting_approval' && staleness.loaded && staleness.isStale && (
            <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-xs text-warning flex items-start gap-2">
              <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              <div className="flex-1">
                This plan is based on a commit that no longer matches the branch head. Regenerate to refresh against the latest commit.
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                disabled={busy === 'regenerate'}
                onClick={handleRegenerate}
                className="h-7 text-xs gap-1.5 shrink-0"
              >
                {busy === 'regenerate' ? <Loader2 className="h-3 w-3 animate-spin" /> : <RefreshCw className="h-3 w-3" />}
                Regenerate
              </Button>
            </div>
          )}
          {fix?.errorMessage && status === 'failed' && !refusal && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {fix.errorMessage}
            </div>
          )}
        </div>
      )}

      {!refusal && status === 'awaiting_approval' && (
        <div className="px-5 py-3 bg-background-card-header border-t border-border flex items-center justify-between">
          <div className="text-xs text-foreground-secondary">
            {error ? <span className="text-destructive">{error}</span> : 'Review and approve to start the fix.'}
          </div>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="outline"
              size="sm"
              disabled={busy !== null}
              onClick={handleReject}
            >
              {busy === 'reject' ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
              Reject
            </Button>
            <Button
              type="button"
              size="sm"
              disabled={busy !== null || !token}
              onClick={handleApprove}
              className={cn('bg-primary text-primary-foreground hover:bg-primary/90')}
            >
              {busy === 'approve' ? <Loader2 className="h-3 w-3 animate-spin" /> : null}
              Approve
            </Button>
          </div>
        </div>
      )}

      {TERMINAL_STATUSES.includes(status) && fix?.prUrl && (
        <div className="px-5 py-3 bg-background-card-header border-t border-border text-xs text-foreground-secondary">
          PR{' '}
          <a
            href={fix.prUrl}
            target="_blank"
            rel="noreferrer"
            className="text-foreground hover:underline"
          >
            #{fix.prNumber ?? '—'}
          </a>{' '}
          opened.
        </div>
      )}
    </div>
  );
}
