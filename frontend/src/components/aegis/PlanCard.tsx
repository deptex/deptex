import { useCallback, useEffect, useState } from 'react';
import { ChevronRight, ListChecks, Loader2 } from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, type FixRecord, type FixStatus } from '../../lib/api';
import { supabase } from '../../lib/supabase';
import { useFixPanel } from './FixPanelContext';
import { FixStatusPill } from './FixStatusPill';

interface PlanCardProps {
  fixId: string;
  // Kept for compatibility with MessageBubble's call sites; the panel now
  // owns model picker / approve / staleness state, so this prop is unused
  // here. Leaving the type means the chat surface doesn't have to change.
  organizationId?: string;
  initialFix?: FixRecord | null;
  onStatusChange?: (status: FixStatus) => void;
}

// One-line pill rendered in the chat scroll. Click to focus the side panel
// on this fix; the panel owns the full plan body, action bar, and approval
// flow. Keeping the pill chat-side avoids "5 fat cards in scrollback"
// when Aegis fans out to N parallel fixes.
export function PlanCard({
  fixId,
  initialFix = null,
  onStatusChange,
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

  const status: FixStatus = fix?.status ?? 'planning';
  const summary = fix?.plan?.summary ?? 'Generating plan…';

  return (
    <button
      type="button"
      onClick={() => openFix(fixId)}
      className={cn(
        'group my-2 w-full flex items-center gap-3 px-4 py-2.5 rounded-md border bg-background-card-header hover:bg-background-subtle transition-colors text-left',
        isPanelOpenForThisFix ? 'border-foreground/30' : 'border-border',
      )}
    >
      <ListChecks className="h-4 w-4 text-foreground-secondary shrink-0" />
      <span className="text-sm text-foreground truncate flex-1 min-w-0">{summary}</span>
      <FixStatusPill status={status} />
      <ChevronRight className="h-3.5 w-3.5 text-foreground-secondary shrink-0 group-hover:text-foreground transition-colors" />
    </button>
  );
}

// In-flight skeleton for the chat pill — rendered while request_fix is
// streaming and we don't have a fixId yet. Mirrors the pill shape so when
// the tool resolves nothing shifts.
export function PlanCardSkeleton() {
  return (
    <div className="my-2 w-full flex items-center gap-3 px-4 py-2.5 rounded-md border border-border bg-background-card-header">
      <Loader2 className="h-4 w-4 text-foreground-secondary shrink-0 animate-spin" />
      <span className="text-sm text-foreground-secondary flex-1 min-w-0">Generating plan…</span>
    </div>
  );
}
