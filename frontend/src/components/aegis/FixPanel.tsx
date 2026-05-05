import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, ArrowLeft, CheckCircle2, ChevronRight, Circle, ExternalLink, ListChecks, Loader2, RefreshCw, ShieldOff, X } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type AIModelMetadata, type FixPlan, type FixRecord, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { MarkdownRenderer } from './MarkdownRenderer';
import { ModelPicker } from './ModelPicker';
import { Button } from '../ui/button';
import { FixStatusPill } from './FixStatusPill';
import { useFixPanel } from './FixPanelContext';

interface StalenessState {
  isStale: boolean;
  currentHeadSha: string | null;
  loaded: boolean;
}

const TERMINAL_STATUSES: readonly FixStatus[] = ['completed', 'failed', 'rejected'];

interface FixPanelProps {
  // Null when the panel is showing the list view (no fix focused).
  fixId: string | null;
  onClose: () => void;
}

export function FixPanel({ fixId, onClose }: FixPanelProps) {
  const { view, registeredFixIds, openFix, showList } = useFixPanel();

  // ESC always closes the panel regardless of view.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const showListView = view === 'list' || !fixId;
  const fixCount = registeredFixIds.length;

  return (
    <div className="h-full flex flex-col bg-background overflow-hidden relative">
      {/* Breadcrumb — only shows when there are siblings to navigate to.
          In detail view it offers a way back to the list; in list view it
          is hidden because the list IS the top level. The panel's close
          affordance lives on the resize divider in FixPanelHost (hover to
          reveal a chevron), not in this header. */}
      {!showListView && fixCount > 1 && (
        <button
          type="button"
          onClick={showList}
          className="flex items-center gap-1.5 px-6 pt-4 text-xs text-foreground-secondary hover:text-foreground transition-colors text-left"
        >
          <ArrowLeft className="h-3 w-3" />
          {fixCount} plan{fixCount === 1 ? '' : 's'}
        </button>
      )}

      <div className="flex-1 overflow-y-auto">
        {showListView ? (
          <FixListBody fixIds={registeredFixIds} onSelect={openFix} />
        ) : (
          <FixDetailBody fixId={fixId} />
        )}
      </div>
    </div>
  );
}

interface FixDetailBodyProps {
  fixId: string;
}

function FixDetailBody({ fixId }: FixDetailBodyProps) {
  const [fix, setFix] = useState<FixRecord | null>(null);
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<'approve' | 'regenerate' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [staleness, setStaleness] = useState<StalenessState>({
    isStale: false,
    currentHeadSha: null,
    loaded: false,
  });
  const [enabledModels, setEnabledModels] = useState<AIModelMetadata[]>([]);
  const [selectedModelId, setSelectedModelId] = useState<string>('');

  const refresh = useCallback(async () => {
    try {
      const { fix: refreshed } = await api.getFix(fixId);
      setFix(refreshed);
      if (refreshed.plan) setPlan(refreshed.plan);
    } catch {
      // ignore — realtime will fill in eventually
    } finally {
      setLoading(false);
    }
  }, [fixId]);

  useEffect(() => {
    setLoading(true);
    setFix(null);
    setPlan(null);
    setError(null);
    setStaleness({ isStale: false, currentHeadSha: null, loaded: false });
    void refresh();
  }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    (async () => {
      const { data: { session } } = await supabase.auth.getSession();
      await (supabase.realtime as any).setAuth(session?.access_token ?? null);
      if (cancelled) return;
      channel = supabase
        .channel(`fix-panel-${fixId}`)
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

  const status: FixStatus = fix?.status ?? 'planning';
  const token = fix?.approvalToken ?? null;
  const orgIdForState = fix?.organizationId ?? '';
  const modelStorageKey = orgIdForState ? `aegis:fix-model:${orgIdForState}` : null;

  // Model picker fetch + persist. Per-fix execution model picker; defaults
  // to the org's default model and persists per-org in localStorage.
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
    }).catch(() => { /* picker stays hidden */ });
    return () => { cancelled = true; };
  }, [orgIdForState, modelStorageKey]);

  const handleSelectModel = useCallback((id: string) => {
    setSelectedModelId(id);
    if (modelStorageKey) {
      try { localStorage.setItem(modelStorageKey, id); } catch { /* ignore */ }
    }
  }, [modelStorageKey]);

  // Staleness polling — only while awaiting_approval. Polls every 60s.
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
      setError('No approval token — try regenerating the plan.');
      return;
    }
    setBusy('approve');
    setError(null);
    try {
      const { fix: updated } = await api.approveFix(fixId, token);
      setFix(updated);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to approve');
    } finally {
      setBusy(null);
    }
  }, [fixId, token]);

  const handleRegenerate = useCallback(async () => {
    setBusy('regenerate');
    setError(null);
    try {
      const res = await api.regenerateFixPlan(fixId);
      if (res.fix) setFix(res.fix);
      if (res.plan) setPlan(res.plan);
    } catch (err: any) {
      setError(err?.message ?? 'Failed to regenerate');
    } finally {
      setBusy(null);
    }
  }, [fixId]);

  if (loading && !plan) return <FixPanelSkeleton />;
  if (!plan) return <div className="p-6 text-sm text-foreground-secondary">Plan unavailable.</div>;

  const refusal = plan.refusal;

  return (
    <div className="px-6 pt-5 pb-6">
      <div className="flex items-start justify-between gap-3">
        <div className="text-lg font-semibold text-foreground leading-snug pr-8 flex-1 min-w-0">
          {plan.summary}
        </div>
      </div>

      {/* Action area — sits right under the title so the primary action
          (Approve) is reachable without scrolling. Refusal blocks render
          in place of the action bar; PR link replaces it on completion. */}
      {refusal ? (
        <div className="mt-4 rounded-md border border-warning/30 bg-warning/5 px-3 py-2.5">
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
      ) : status === 'awaiting_approval' ? (
        <div className="mt-4 space-y-2">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <FixStatusPill status={status} />
            <div className="flex items-center gap-2">
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
            </div>
          </div>
          {staleness.loaded && staleness.isStale && (
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
          {error && (
            <div className="rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
              {error}
            </div>
          )}
        </div>
      ) : TERMINAL_STATUSES.includes(status) ? (
        <div className="mt-4 flex items-center gap-2">
          <FixStatusPill status={status} />
          {fix?.errorMessage && status === 'failed' && (
            <span className="text-xs text-destructive truncate min-w-0">{fix.errorMessage}</span>
          )}
        </div>
      ) : (
        <div className="mt-4">
          <FixStatusPill status={status} />
        </div>
      )}

      <div className="mt-6 space-y-6">
              {plan.issue && (
                <div>
                  <div className="text-sm font-semibold text-foreground mb-2">
                    Issue
                  </div>
                  <div className="text-sm leading-relaxed text-foreground/80">
                    <MarkdownRenderer content={plan.issue} />
                  </div>
                </div>
              )}
              {plan.description && (
                <div>
                  <div className="text-sm font-semibold text-foreground mb-2">
                    Plan
                  </div>
                  <p className="text-sm leading-relaxed text-foreground/80 whitespace-pre-wrap">
                    {plan.description}
                  </p>
                </div>
              )}
              {(() => {
                const aiTodos = plan.todos ?? [];
                const todos = aiTodos.length > 0
                  ? aiTodos.map((t) => ({ primary: t.title, secondary: t.detail, mono: false }))
                  : plan.fileChanges.map((c) => ({ primary: c.path, secondary: c.description, mono: true }));
                if (todos.length === 0) return null;
                return (
                  <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
                    <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
                      <ListChecks className="h-3.5 w-3.5" />
                      To-dos
                    </div>
                    <ul className="space-y-3">
                      {todos.map((t, i) => (
                        <li key={i} className="flex items-start gap-2.5">
                          <Circle className="h-3 w-3 mt-1 text-foreground-secondary shrink-0" />
                          <div className="min-w-0 flex-1">
                            <div className={
                              t.mono
                                ? 'font-mono text-xs text-foreground break-all'
                                : 'text-sm text-foreground leading-snug'
                            }>
                              {t.primary}
                            </div>
                            {t.secondary && (
                              <div className="mt-1 text-xs text-foreground-secondary leading-relaxed">
                                {t.secondary}
                              </div>
                            )}
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                );
              })()}

              <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
                <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Verification
                </div>
                {plan.verificationSteps && plan.verificationSteps.length > 0 ? (
                  <ul className="space-y-3">
                    {plan.verificationSteps.map((s, i) => (
                      <li key={i} className="flex items-start gap-2.5">
                        <Circle className="h-3 w-3 mt-1 text-foreground-secondary shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="font-mono text-xs text-foreground break-all">{s.command}</div>
                          <div className="mt-1 text-xs text-foreground-secondary leading-relaxed">
                            {s.description}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                ) : plan.verification ? (
                  <p className="text-sm leading-relaxed text-foreground/80 whitespace-pre-wrap">
                    {plan.verification}
                  </p>
                ) : (
                  <p className="text-sm leading-relaxed text-foreground-secondary">
                    The worker runs{' '}
                    <span className="font-mono text-foreground break-all">{plan.testCommand}</span>{' '}
                    after the fix to confirm nothing regressed.
                  </p>
                )}
              </div>

        {fix?.prUrl && (
          <div className="pt-4 border-t border-border">
            <a
              href={fix.prUrl}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-sm font-medium text-foreground hover:underline"
            >
              Pull request #{fix.prNumber ?? '—'}
              <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
        )}
      </div>
    </div>
  );
}

interface FixListBodyProps {
  fixIds: string[];
  onSelect: (fixId: string) => void;
}

function FixListBody({ fixIds, onSelect }: FixListBodyProps) {
  if (fixIds.length === 0) {
    return (
      <div className="px-6 pt-5 pb-6 text-sm text-foreground-secondary">
        No plans yet. Ask Aegis to fix an issue and the plan will appear here.
      </div>
    );
  }
  return (
    <div className="px-6 pt-5 pb-6">
      <div className="text-lg font-semibold text-foreground leading-snug pr-8">
        Plans
      </div>
      <ul className="mt-4 space-y-2">
        {fixIds.map((id) => (
          <li key={id}>
            <FixListRow fixId={id} onSelect={onSelect} />
          </li>
        ))}
      </ul>
    </div>
  );
}

interface FixListRowProps {
  fixId: string;
  onSelect: (fixId: string) => void;
}

function FixListRow({ fixId, onSelect }: FixListRowProps) {
  const [fix, setFix] = useState<FixRecord | null>(null);

  const refresh = useCallback(async () => {
    try {
      const { fix: refreshed } = await api.getFix(fixId);
      setFix(refreshed);
    } catch {
      // ignore
    }
  }, [fixId]);

  useEffect(() => { void refresh(); }, [refresh]);

  useEffect(() => {
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    (async () => {
      const { data: { session } } = await supabase.auth.getSession();
      await (supabase.realtime as any).setAuth(session?.access_token ?? null);
      if (cancelled) return;
      channel = supabase
        .channel(`fix-list-${fixId}`)
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

  const summary = fix?.plan?.summary ?? 'Generating plan…';
  const status: FixStatus = fix?.status ?? 'planning';

  return (
    <button
      type="button"
      onClick={() => onSelect(fixId)}
      className="w-full flex items-center gap-3 px-3 py-2.5 rounded-md border border-border bg-background-subtle/30 hover:bg-background-subtle text-left transition-colors"
    >
      <ListRowStatusIcon status={status} />
      <div className="min-w-0 flex-1">
        <div className="text-sm text-foreground truncate">{summary}</div>
        <div className="mt-0.5 text-xs text-foreground-secondary">
          {statusLabel(status)}
        </div>
      </div>
      <ChevronRight className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />
    </button>
  );
}

function statusLabel(status: FixStatus): string {
  switch (status) {
    case 'planning': return 'Generating plan…';
    case 'awaiting_approval': return 'Awaiting approval';
    case 'approved': return 'Approved · queued';
    case 'executing': return 'Executing';
    case 'completed': return 'Completed';
    case 'failed': return 'Failed';
    case 'rejected': return 'Rejected';
    default: return status;
  }
}

function ListRowStatusIcon({ status }: { status: FixStatus }) {
  if (status === 'planning' || status === 'approved' || status === 'executing') {
    return <Loader2 className="h-3.5 w-3.5 text-foreground-secondary animate-spin shrink-0" />;
  }
  if (status === 'completed') {
    return <CheckCircle2 className="h-3.5 w-3.5 text-success shrink-0" />;
  }
  if (status === 'failed') {
    return <AlertTriangle className="h-3.5 w-3.5 text-destructive shrink-0" />;
  }
  if (status === 'rejected') {
    return <X className="h-3.5 w-3.5 text-foreground-secondary shrink-0" />;
  }
  // awaiting_approval
  return <Circle className="h-3.5 w-3.5 text-warning shrink-0" />;
}

// Skeleton mirror of the real plan panel layout — title, Issue (label +
// prose + code block), Plan (label + prose), To-dos card, Verification
// card. Mirrors the real DOM 1:1 so when the plan resolves nothing shifts.
function FixPanelSkeleton() {
  const ISSUE_PROSE_WIDTHS = ['w-11/12', 'w-10/12', 'w-9/12'];
  const PLAN_PROSE_WIDTHS = ['w-11/12', 'w-7/12'];
  const CODE_LINE_WIDTHS = ['w-2/3', 'w-1/2'];
  const TODO_WIDTHS: Array<[string, string]> = [
    ['w-3/4', 'w-2/3'],
    ['w-5/6', 'w-1/2'],
  ];
  const VERIFY_WIDTHS: Array<[string, string]> = [
    ['w-1/4', 'w-3/4'],
    ['w-1/3', 'w-2/3'],
  ];
  return (
    <div className="px-6 pt-5 pb-6">
      {/* Title bar */}
      <div className="h-5 w-2/3 rounded bg-muted/50 animate-pulse" />

      <div className="mt-6 space-y-6">
        {/* Issue section */}
        <div>
          <div className="h-4 w-12 rounded bg-muted/50 animate-pulse mb-3" />
          <div className="space-y-2">
            {ISSUE_PROSE_WIDTHS.map((w, i) => (
              <div key={i} className={cn('h-3 rounded bg-muted/40 animate-pulse', w)} />
            ))}
          </div>
          <div className="mt-3 rounded-md border border-border bg-[#0a0a0b] overflow-hidden">
            <div className="px-3 py-2 border-b border-border/60 flex items-center justify-between">
              <div className="h-2.5 w-6 rounded bg-muted/40 animate-pulse" />
              <div className="h-2.5 w-8 rounded bg-muted/40 animate-pulse" />
            </div>
            <div className="px-3 py-3 space-y-1.5">
              {CODE_LINE_WIDTHS.map((w, i) => (
                <div key={i} className={cn('h-2.5 rounded bg-muted/30 animate-pulse', w)} />
              ))}
            </div>
          </div>
        </div>

        {/* Plan section */}
        <div>
          <div className="h-4 w-10 rounded bg-muted/50 animate-pulse mb-3" />
          <div className="space-y-2">
            {PLAN_PROSE_WIDTHS.map((w, i) => (
              <div key={i} className={cn('h-3 rounded bg-muted/40 animate-pulse', w)} />
            ))}
          </div>
        </div>

        {/* To-dos card */}
        <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
          <div className="flex items-center gap-1.5 mb-3">
            <div className="h-3.5 w-3.5 rounded-sm bg-muted/40 animate-pulse" />
            <div className="h-3 w-12 rounded bg-muted/40 animate-pulse" />
          </div>
          <ul className="space-y-3">
            {TODO_WIDTHS.map(([primary, secondary], i) => (
              <li key={i} className="flex items-start gap-2.5">
                <div className="h-3 w-3 mt-1 rounded-full bg-muted/40 animate-pulse shrink-0" />
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className={cn('h-3 rounded bg-muted/50 animate-pulse', primary)} />
                  <div className={cn('h-2.5 rounded bg-muted/40 animate-pulse', secondary)} />
                </div>
              </li>
            ))}
          </ul>
        </div>

        {/* Verification card */}
        <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
          <div className="flex items-center gap-1.5 mb-3">
            <div className="h-3.5 w-3.5 rounded-sm bg-muted/40 animate-pulse" />
            <div className="h-3 w-20 rounded bg-muted/40 animate-pulse" />
          </div>
          <ul className="space-y-3">
            {VERIFY_WIDTHS.map(([primary, secondary], i) => (
              <li key={i} className="flex items-start gap-2.5">
                <div className="h-3 w-3 mt-1 rounded-full bg-muted/40 animate-pulse shrink-0" />
                <div className="min-w-0 flex-1 space-y-1.5">
                  <div className={cn('h-3 rounded bg-muted/50 animate-pulse', primary)} />
                  <div className={cn('h-2.5 rounded bg-muted/40 animate-pulse', secondary)} />
                </div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </div>
  );
}

