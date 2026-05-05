import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, CheckCircle2, Circle, ExternalLink, ListChecks, Loader2, RefreshCw, ShieldOff, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type AIModelMetadata, type FixRecord, type FixPlan, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { Button } from '../ui/button';
import { ModelPicker } from './ModelPicker';
import { usePlanPanel } from './PlanPanelContext';

interface PlanCardProps {
  fixId: string;
  organizationId?: string;
  initialFix?: FixRecord | null;
  initialPlan?: FixPlan | null;
  onStatusChange?: (status: FixStatus) => void;
}

interface StalenessState {
  isStale: boolean;
  currentHeadSha: string | null;
  loaded: boolean;
}

const TERMINAL_STATUSES: readonly FixStatus[] = ['completed', 'failed', 'rejected'];

function StatusPill({ status }: { status: FixStatus }) {
  const base =
    'inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[10px] font-medium border';
  if (status === 'planning') {
    return (
      <span className={cn(base, 'bg-foreground/5 text-foreground-secondary border-border')}>
        <Loader2 className="h-3 w-3 animate-spin" />
        Generating plan
      </span>
    );
  }
  if (status === 'awaiting_approval') {
    return (
      <span className={cn(base, 'bg-warning/10 text-warning border-warning/30')}>
        Awaiting approval
      </span>
    );
  }
  if (status === 'approved' || status === 'executing') {
    return (
      <span className={cn(base, 'bg-blue-500/10 text-blue-300 border-blue-500/30')}>
        <Loader2 className="h-3 w-3 animate-spin" />
        {status === 'approved' ? 'Approved · queued' : 'Executing'}
      </span>
    );
  }
  if (status === 'completed') {
    return (
      <span className={cn(base, 'bg-success/10 text-success border-success/30')}>
        <CheckCircle2 className="h-3 w-3" />
        Completed
      </span>
    );
  }
  if (status === 'failed') {
    return (
      <span className={cn(base, 'bg-destructive/10 text-destructive border-destructive/30')}>
        <AlertTriangle className="h-3 w-3" />
        Failed
      </span>
    );
  }
  return (
    <span className={cn(base, 'bg-foreground/5 text-foreground-secondary border-border')}>
      <X className="h-3 w-3" />
      Rejected
    </span>
  );
}

export function PlanCard({
  fixId,
  organizationId,
  initialFix = null,
  initialPlan = null,
  onStatusChange,
}: PlanCardProps) {
  const [fix, setFix] = useState<FixRecord | null>(initialFix);
  const [plan, setPlan] = useState<FixPlan | null>(initialPlan ?? initialFix?.plan ?? null);
  const token = fix?.approvalToken ?? null;
  const [busy, setBusy] = useState<'approve' | 'reject' | 'regenerate' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { activeFixId, togglePlan } = usePlanPanel();
  const isPanelOpenForThisFix = activeFixId === fixId;
  const [staleness, setStaleness] = useState<StalenessState>({
    isStale: false,
    currentHeadSha: null,
    loaded: false,
  });

  // Per-fix execution model picker. Defaults to the org's default model;
  // selection persists per-org in localStorage. The selectedModelId is
  // passed to approveFix so the fix-worker can use it for execution
  // (backend wiring forthcoming — for now the selector is functional UI
  // but the worker still uses the org default).
  const orgIdForState = organizationId ?? fix?.organizationId ?? '';
  const modelStorageKey = orgIdForState ? `aegis:fix-model:${orgIdForState}` : null;
  const [enabledModels, setEnabledModels] = useState<AIModelMetadata[]>([]);
  const [selectedModelId, setSelectedModelId] = useState<string>('');

  useEffect(() => {
    if (!orgIdForState) return;
    let cancelled = false;
    api.getAIModels(orgIdForState).then((res) => {
      if (cancelled) return;
      const enabled = res.models.filter((m) => res.enabledModels.includes(m.id));
      setEnabledModels(enabled);
      const stored = (() => {
        try {
          return modelStorageKey ? localStorage.getItem(modelStorageKey) : null;
        } catch {
          return null;
        }
      })();
      const fallback =
        (stored && enabled.find((m) => m.id === stored)?.id) ||
        enabled.find((m) => m.id === res.defaultModel)?.id ||
        enabled[0]?.id ||
        '';
      setSelectedModelId(fallback);
    }).catch(() => {
      // Picker stays hidden — the worker uses the org default anyway.
    });
    return () => { cancelled = true; };
  }, [orgIdForState, modelStorageKey]);

  const handleSelectModel = useCallback((id: string) => {
    setSelectedModelId(id);
    if (modelStorageKey) {
      try { localStorage.setItem(modelStorageKey, id); } catch { /* ignore */ }
    }
  }, [modelStorageKey]);

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
      <div className="my-2 rounded-lg border border-border bg-background-card-header overflow-hidden">
        <div className="px-5 py-4 flex items-center justify-between">
          <div className="text-sm font-semibold text-foreground">Generating plan…</div>
          <StatusPill status="planning" />
        </div>
        <div className="px-5 pb-4 space-y-3">
          <div className="h-3 w-3/4 rounded bg-muted/50 animate-pulse" />
          <div className="h-3 w-2/3 rounded bg-muted/50 animate-pulse" />
          <div className="h-3 w-1/2 rounded bg-muted/40 animate-pulse" />
        </div>
      </div>
    );
  }

  if (!plan) {
    return (
      <div className="my-2 rounded-lg border border-border bg-background-card-header px-5 py-4">
        <div className="text-sm text-foreground-secondary">Plan unavailable.</div>
      </div>
    );
  }

  const refusal = plan.refusal;

  // Right-aligned action bar content. Awaiting approval = model picker +
  // Approve. Terminal-with-PR = PR link + status pill. Otherwise just the
  // status pill.
  const actionBarRight = (() => {
    if (!refusal && status === 'awaiting_approval') {
      return (
        <>
          {enabledModels.length > 0 && selectedModelId && (
            <ModelPicker
              models={enabledModels}
              selectedModelId={selectedModelId}
              onSelect={handleSelectModel}
            />
          )}
          <Button
            type="button"
            variant="solid"
            disabled={busy !== null || !token}
            onClick={handleApprove}
            className="h-8 px-3 shrink-0"
          >
            {busy === 'approve' ? <Loader2 className="animate-spin" /> : null}
            Approve
          </Button>
        </>
      );
    }
    if (TERMINAL_STATUSES.includes(status) && fix?.prUrl) {
      return (
        <>
          <a
            href={fix.prUrl}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-1.5 rounded-md border border-border bg-background-subtle px-2.5 py-1 text-xs font-medium text-foreground hover:bg-background-subtle/70 transition-colors"
          >
            PR #{fix.prNumber ?? '—'}
            <ExternalLink className="h-3 w-3" />
          </a>
          <StatusPill status={status} />
        </>
      );
    }
    return <StatusPill status={status} />;
  })();

  return (
    <div className="my-2 rounded-lg border border-border bg-background-card-header overflow-hidden">
      {/* Body */}
      {refusal ? (
        <div className="px-5 py-4">
          <div className="flex gap-2.5 items-start text-sm text-foreground">
            <ShieldOff className="h-4 w-4 mt-0.5 text-warning shrink-0" />
            <div className="min-w-0 flex-1">
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
        <div className="px-5 py-4 space-y-3">
          {/* Title only — the full description lives in the side panel so
              the card stays a tight summary surface. */}
          <div className="text-[15px] font-semibold text-foreground leading-snug">
            {plan.summary}
          </div>

          {/* Inset to-dos card — bordered tile listing each file change as a
              circle-bulleted todo. Capped at the first 3 in the chat surface
              with a "+N more" hint that nudges to View Plan; the panel shows
              the full list. */}
          {plan.fileChanges.length > 0 && (() => {
            const TODO_LIMIT = 3;
            const visible = plan.fileChanges.slice(0, TODO_LIMIT);
            const overflow = plan.fileChanges.length - visible.length;
            return (
              <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
                <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
                  <ListChecks className="h-3.5 w-3.5" />
                  To-dos
                </div>
                <ul className="space-y-1.5 text-sm text-foreground/90">
                  {visible.map((c, i) => (
                    <li key={i} className="flex items-start gap-2.5 leading-relaxed">
                      <Circle className="h-3 w-3 mt-1 text-foreground-secondary shrink-0" />
                      <div className="min-w-0 flex-1">
                        <span className="font-mono text-xs text-foreground">{c.path}</span>
                        <div className="mt-0.5 text-xs text-foreground-secondary leading-relaxed">
                          {c.description}
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
                {overflow > 0 && (
                  <button
                    type="button"
                    onClick={() => togglePlan(fixId)}
                    className="mt-2 text-xs text-foreground-secondary hover:text-foreground transition-colors"
                  >
                    +{overflow} more
                  </button>
                )}
              </div>
            );
          })()}

          {status === 'awaiting_approval' && staleness.loaded && staleness.isStale && (
            <div className="rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-xs text-warning flex items-start gap-2">
              <AlertTriangle className="h-3.5 w-3.5 mt-0.5 shrink-0" />
              <div className="flex-1">
                This plan is based on a commit that no longer matches the branch head. Regenerate
                to refresh against the latest commit.
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
          {error && status === 'awaiting_approval' && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {error}
            </div>
          )}
          {fix?.errorMessage && status === 'failed' && !refusal && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {fix.errorMessage}
            </div>
          )}
        </div>
      )}

      {/* Action bar — bottom row. View Plan toggles the right-side detail
          panel for this fix; model picker + Approve on the right. */}
      <div className="border-t border-border bg-background px-5 py-2 flex items-center justify-between gap-2">
        <button
          type="button"
          onClick={() => togglePlan(fixId)}
          className={cn(
            'text-xs font-medium transition-colors',
            isPanelOpenForThisFix
              ? 'text-foreground'
              : 'text-foreground-secondary hover:text-foreground',
          )}
        >
          {isPanelOpenForThisFix ? 'Hide plan' : 'View Plan'}
        </button>
        <div className="flex items-center gap-2">
          {actionBarRight}
        </div>
      </div>
    </div>
  );
}
