import { useCallback, useEffect, useState } from 'react';
import { CheckCircle2, Circle, ExternalLink, ListChecks, Loader2, X } from 'lucide-react';
import { api, type FixPlan, type FixRecord } from '../../lib/api';
import { supabase } from '../../lib/supabase';

interface PlanPanelProps {
  fixId: string;
  onClose: () => void;
}

export function PlanPanel({ fixId, onClose }: PlanPanelProps) {
  const [fix, setFix] = useState<FixRecord | null>(null);
  const [plan, setPlan] = useState<FixPlan | null>(null);
  const [loading, setLoading] = useState(true);

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
        .channel(`plan-panel-${fixId}`)
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

  // ESC closes the panel.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  return (
    <div className="h-full flex flex-col bg-background overflow-hidden relative">
      <button
        type="button"
        onClick={onClose}
        aria-label="Close plan"
        className="absolute top-3 right-3 z-10 inline-flex items-center justify-center h-7 w-7 rounded-md text-foreground-secondary hover:bg-background-subtle hover:text-foreground transition-colors"
      >
        <X className="h-4 w-4" />
      </button>

      <div className="flex-1 overflow-y-auto">
        {loading && !plan ? (
          <div className="p-6 flex items-center gap-2 text-sm text-foreground-secondary">
            <Loader2 className="h-4 w-4 animate-spin" />
            Loading plan…
          </div>
        ) : !plan ? (
          <div className="p-6 text-sm text-foreground-secondary">Plan unavailable.</div>
        ) : (
          <div className="px-6 pt-5 pb-6">
            <div className="text-lg font-semibold text-foreground leading-snug pr-8">
              {plan.summary}
            </div>

            {plan.description && (
              <p className="mt-3 text-sm leading-relaxed text-foreground/80 whitespace-pre-wrap">
                {plan.description}
              </p>
            )}

            <div className="mt-6 space-y-6">
              {plan.fileChanges.length > 0 && (
                <div className="rounded-md border border-border bg-background-subtle/30 px-4 py-3">
                  <div className="flex items-center gap-1.5 mb-2 text-xs font-medium text-foreground-secondary">
                    <ListChecks className="h-3.5 w-3.5" />
                    To-dos
                  </div>
                  <ul className="space-y-3">
                    {plan.fileChanges.map((c, i) => (
                      <li key={i} className="flex items-start gap-2.5">
                        <Circle className="h-3 w-3 mt-1 text-foreground-secondary shrink-0" />
                        <div className="min-w-0 flex-1">
                          <div className="font-mono text-xs text-foreground break-all">{c.path}</div>
                          <div className="mt-1 text-xs text-foreground-secondary leading-relaxed">
                            {c.description}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

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
        )}
      </div>
    </div>
  );
}
