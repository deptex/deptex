import { useCallback, useEffect, useState } from 'react';
import { ChevronRight, ClipboardList, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type FixRecord, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { useFixPanel } from './FixPanelContext';

interface PlanCardProps {
  fixId: string;
  // Kept for compatibility with MessageBubble's call sites; the panel now
  // owns model picker / approve / staleness state, so this prop is unused
  // here. Leaving the type means the chat surface doesn't have to change.
  organizationId?: string;
  initialFix?: FixRecord | null;
  onStatusChange?: (status: FixStatus) => void;
  // True when this pill represents a revise_fix tool call (vs. the original
  // request_fix). Renders a small "Revised" tag so the chat history reads
  // "first plan → revised plan" naturally.
  revised?: boolean;
}

// One-line pill rendered in the chat scroll. Click to focus the side panel
// on this fix; the panel owns the full plan body, action bar, and approval
// flow. Keeping the pill chat-side avoids "5 fat cards in scrollback"
// when Aegis fans out to N parallel fixes.
export function PlanCard({
  fixId,
  initialFix = null,
  onStatusChange,
  revised = false,
}: PlanCardProps) {
  const [fix, setFix] = useState<FixRecord | null>(initialFix);
  const { activeFixId, openFix, registerFix } = useFixPanel();
  const isPanelOpenForThisFix = activeFixId === fixId;

  // Tell the panel about this fix on mount so it appears in the list view
  // and so the FIRST fix in the thread auto-opens the panel.
  useEffect(() => {
    registerFix(fixId);
  }, [fixId, registerFix]);

  const refresh = useCallback(async () => {
    try {
      const { fix: refreshed } = await api.getFix(fixId);
      setFix(refreshed);
      onStatusChange?.(refreshed.status);
    } catch {
      // ignore — realtime catches up
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
        .channel(`plan-card-pill-${fixId}`)
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

  const planSummary = fix?.plan?.summary ?? null;
  // Revise in flight: status flipped to 'planning' but the previous plan is
  // still in place (the backend keeps it until the new plan overwrites).
  // We render the existing title with a "Revising" pill so the card doesn't
  // momentarily lose its name.
  const isRevising = fix?.status === 'planning' && !!fix?.plan;

  return (
    <button
      type="button"
      onClick={() => openFix(fixId)}
      className={cn(
        'group my-2 w-full flex items-center gap-3 px-4 py-3 rounded-md border border-border transition-colors text-left',
        isPanelOpenForThisFix ? 'bg-background-subtle/60' : 'bg-background-subtle/30 hover:bg-background-subtle/60',
      )}
    >
      <ClipboardList className="h-4 w-4 text-foreground-secondary shrink-0" />
      {planSummary ? (
        <span className="text-sm text-foreground truncate flex-1 min-w-0">{planSummary}</span>
      ) : (
        <div className="h-3.5 w-56 rounded bg-foreground/[0.12] animate-pulse shrink-0 mr-auto" />
      )}
      {isRevising ? (
        <span className="flex items-center gap-1 shrink-0 rounded-sm border border-border bg-background-card-header px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-foreground-secondary">
          <Loader2 className="h-2.5 w-2.5 animate-spin" />
          Revising
        </span>
      ) : revised ? (
        <span className="shrink-0 rounded-sm border border-border bg-background-card-header px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-foreground-secondary">
          Revised
        </span>
      ) : null}
      <ChevronRight className="h-3.5 w-3.5 text-foreground-secondary shrink-0 group-hover:text-foreground transition-colors" />
    </button>
  );
}

// In-flight skeleton for the chat pill — rendered while request_fix is
// streaming and we don't have a fixId yet. Mirrors the resolved card's
// chrome (same bg / border / padding as FixListRow in the side panel) so
// nothing shifts when the plan resolves; only the inner bars are skeletons.
export function PlanCardSkeleton(_props: { revised?: boolean } = {}) {
  return (
    <div className="my-2 w-full flex items-center gap-3 px-4 py-3 rounded-md border border-border bg-background-subtle/30">
      <div className="h-4 w-4 rounded bg-foreground/[0.08] animate-pulse shrink-0" />
      <div className="h-3.5 w-56 rounded bg-foreground/[0.08] animate-pulse shrink-0 mr-auto" />
      <div className="h-3.5 w-3.5 rounded bg-foreground/[0.08] animate-pulse shrink-0" />
    </div>
  );
}
