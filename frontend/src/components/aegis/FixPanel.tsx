import { useCallback, useEffect, useState } from 'react';
import { AlertCircle, AlertTriangle, Ban, CheckCircle2, ChevronDown, ChevronRight, Circle, ClipboardList, ExternalLink, ListChecks, Loader2, RefreshCw, ShieldOff } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type AIModelMetadata, type FixPlan, type FixRecord, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { MarkdownRenderer } from './MarkdownRenderer';
import { ModelPicker } from './ModelPicker';
import { Button } from '../ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/dropdown-menu';
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
  const { view } = useFixPanel();

  // ESC always closes the panel regardless of view.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const showListView = view === 'list' || !fixId;

  return (
    <div className="h-full flex flex-col bg-background overflow-hidden relative">
      <div className="flex-1 overflow-y-auto">
        {showListView ? (
          <FixListBody />
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
  const { fixes, openFix } = useFixPanel();
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

  if (!plan && (loading || status === 'planning')) return <FixPanelSkeleton />;
  if (!plan) return <div className="p-6 text-sm text-foreground-secondary">Plan unavailable.</div>;

  const refusal = plan.refusal;

  const hasSiblings = fixes.length > 1;

  const showInlineAction = !refusal && status === 'awaiting_approval';

  return (
    <div className="px-6 pt-5 pb-6">
      {/* Title + (when awaiting_approval) inline action area on a single row,
          so the primary action (Start) sits beside the plan name rather
          than dropping to a second row beneath it. */}
      <div className="flex items-center justify-between gap-3">
        {hasSiblings ? (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="group flex items-center gap-1.5 text-lg font-semibold text-foreground leading-snug min-w-0 max-w-full text-left rounded-sm hover:opacity-80 transition-opacity focus:outline-none"
              >
                <span className="truncate">{plan.summary}</span>
                <ChevronDown className="h-4 w-4 shrink-0 text-foreground-secondary" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent
              align="start"
              className="min-w-[var(--radix-dropdown-menu-trigger-width)] max-w-[calc(100vw-3rem)]"
            >
              {fixes.map((f) => {
                const isActive = f.id === fixId;
                return (
                  <DropdownMenuItem
                    key={f.id}
                    onSelect={() => { if (!isActive) openFix(f.id); }}
                    className={cn('gap-2 items-center', isActive && 'bg-background-subtle')}
                  >
                    <FixStatusIcon status={f.status} />
                    {f.plan?.summary ? (
                      <span className="flex-1 truncate text-sm">{f.plan.summary}</span>
                    ) : (
                      <div className="h-3.5 rounded bg-foreground/[0.12] animate-pulse flex-1 min-w-0 max-w-[14rem]" />
                    )}
                  </DropdownMenuItem>
                );
              })}
            </DropdownMenuContent>
          </DropdownMenu>
        ) : (
          <div className="text-lg font-semibold text-foreground leading-snug min-w-0 truncate">
            {plan.summary}
          </div>
        )}
        {showInlineAction && (
          <div className="flex items-center gap-2 shrink-0">
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
              Start
            </Button>
          </div>
        )}
      </div>

      {/* Below the title row: contextual status / warning / error blocks
          that aren't the inline action. Refusal block, staleness banner,
          approval error, terminal-state pill, in-flight pill. */}
      {refusal && (
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
      )}
      {showInlineAction && staleness.loaded && staleness.isStale && (
        <div className="mt-3 rounded-md border border-warning/30 bg-warning/5 px-3 py-2 text-xs text-warning flex items-start gap-2">
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
      {showInlineAction && error && (
        <div className="mt-3 rounded-md border border-destructive/30 bg-destructive/5 px-3 py-2 text-xs text-destructive">
          {error}
        </div>
      )}
      {!refusal && TERMINAL_STATUSES.includes(status) && (
        <div className="mt-4 flex items-center gap-2">
          <FixStatusPill status={status} />
          {fix?.errorMessage && status === 'failed' && (
            <span className="text-xs text-destructive truncate min-w-0">{fix.errorMessage}</span>
          )}
        </div>
      )}
      {!refusal && status !== 'awaiting_approval' && !TERMINAL_STATUSES.includes(status) && (
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

function FixListBody() {
  const { fixes, openFix } = useFixPanel();

  if (fixes.length === 0) {
    return (
      <div className="px-6 pt-5 pb-6 text-sm text-foreground-secondary">
        No fixes yet. Ask Aegis to fix an issue and the plan will appear here.
      </div>
    );
  }

  return (
    <div className="px-6 pt-5 pb-6">
      <div className="text-lg font-semibold text-foreground leading-snug pr-8">
        Fixes
      </div>
      <ul className="mt-4 space-y-1">
        {fixes.map((f) => (
          <li key={f.id}>
            <FixListRow fix={f} onSelect={() => openFix(f.id)} />
          </li>
        ))}
      </ul>
    </div>
  );
}

interface FixListRowProps {
  fix: FixRecord;
  onSelect: () => void;
}

function FixListRow({ fix, onSelect }: FixListRowProps) {
  const summary = fix.plan?.summary ?? null;
  const status = fix.status;

  return (
    <button
      type="button"
      onClick={onSelect}
      className="group w-full flex items-center gap-3 px-4 py-3 rounded-md border border-border bg-background-subtle/30 hover:bg-background-subtle/60 transition-colors text-left"
    >
      <FixStatusIcon status={status} />
      {summary ? (
        <span className="text-sm font-medium text-foreground truncate flex-1">{summary}</span>
      ) : (
        <div className="h-3.5 w-48 rounded bg-foreground/[0.12] animate-pulse shrink-0 mr-auto" />
      )}
      <ChevronRight className="h-3.5 w-3.5 text-foreground-secondary/60 shrink-0 group-hover:text-foreground-secondary transition-colors" />
    </button>
  );
}

// Single icon that reflects the fix's lifecycle state. Sits at the start of
// each row in place of the wordy badge — at-a-glance status without
// repeating words the title already implies.
function FixStatusIcon({ status }: { status: FixStatus }) {
  const iconCls = 'h-4 w-4 shrink-0';
  switch (status) {
    case 'planning':
      return <Loader2 className={cn(iconCls, 'animate-spin text-foreground-secondary')} aria-label="Planning" />;
    case 'awaiting_approval':
      return <ClipboardList className={cn(iconCls, 'text-foreground-secondary')} aria-label="Plan ready" />;
    case 'approved':
    case 'executing':
      return <Loader2 className={cn(iconCls, 'animate-spin text-foreground-secondary')} aria-label="Executing" />;
    case 'completed':
      return <CheckCircle2 className={cn(iconCls, 'text-success')} aria-label="Completed" />;
    case 'failed':
      return <AlertCircle className={cn(iconCls, 'text-destructive')} aria-label="Failed" />;
    case 'rejected':
      return <Ban className={cn(iconCls, 'text-foreground-secondary')} aria-label="Rejected" />;
    default:
      return <Circle className={cn(iconCls, 'text-foreground-secondary')} />;
  }
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

