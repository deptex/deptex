import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { api, type FixRecord } from '../../lib/api';
import { supabase } from '../../lib/supabase';

export type FixPanelView = 'detail' | 'list';

interface FixPanelContextValue {
  // Every fix attached to the current chat thread, ordered by creation
  // (oldest first). Source of truth is the DB via getFixesByThread + a
  // realtime subscription filtered to thread_id; chat-side PlanCard pills
  // still call registerFix(id) as a fast-path to trigger a refetch in
  // case the realtime event hasn't landed yet.
  fixes: FixRecord[];
  loading: boolean;

  // Currently focused fix when view === 'detail'.
  activeFixId: string | null;
  // 'detail' shows a single fix; 'list' shows every fix in this thread.
  view: FixPanelView;

  // Multi-select state for batch actions in the list view.
  selectedIds: Set<string>;

  openFix: (fixId: string) => void;
  closeFix: () => void;
  toggleFix: (fixId: string) => void;
  showList: () => void;

  toggleSelected: (fixId: string) => void;
  clearSelection: () => void;
  selectAll: () => void;

  // Back-compat fast path. PlanCard pills call this on mount; if we don't
  // already have the fix in our list (e.g. because realtime hasn't fired
  // yet), it triggers a refetch. Otherwise it's a no-op.
  registerFix: (fixId: string) => void;
}

const FixPanelContext = createContext<FixPanelContextValue | null>(null);

interface FixPanelProviderProps {
  children: ReactNode;
  // The chat thread the panel is scoped to. When this changes, we refetch
  // and reset all panel state. Null = no thread (e.g. landing screen).
  threadId: string | null;
}

export function FixPanelProvider({ children, threadId }: FixPanelProviderProps) {
  const [fixes, setFixes] = useState<FixRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeFixId, setActiveFixId] = useState<string | null>(null);
  const [view, setView] = useState<FixPanelView>('detail');
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [userDismissed, setUserDismissed] = useState(false);
  // Becomes true after the first fetch resolves for the current thread.
  // Auto-open logic only fires once per thread, gated on this flag.
  const autoOpenedRef = useRef(false);

  const refresh = useCallback(async () => {
    if (!threadId) return;
    try {
      const res = await api.getFixesByThread(threadId);
      setFixes(res.fixes);
    } catch {
      // Silent — realtime will retry; surfacing errors to the user adds
      // noise without recovery action they can take.
    } finally {
      setLoading(false);
    }
  }, [threadId]);

  // Reset everything on threadId change and kick off the initial fetch.
  useEffect(() => {
    setFixes([]);
    setActiveFixId(null);
    setView('detail');
    setSelectedIds(new Set());
    setUserDismissed(false);
    autoOpenedRef.current = false;
    if (!threadId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    void refresh();
  }, [threadId, refresh]);

  // Realtime subscription — INSERTs / UPDATEs for fixes attached to this
  // thread trigger a refetch. Cheaper than diffing per-row in the channel.
  useEffect(() => {
    if (!threadId) return;
    let cancelled = false;
    let channel: ReturnType<typeof supabase.channel> | null = null;
    (async () => {
      const { data: { session } } = await supabase.auth.getSession();
      await (supabase.realtime as any).setAuth(session?.access_token ?? null);
      if (cancelled) return;
      channel = supabase
        .channel(`fix-panel-thread-${threadId}`)
        .on(
          'postgres_changes',
          { event: '*', schema: 'public', table: 'project_security_fixes', filter: `thread_id=eq.${threadId}` },
          () => { void refresh(); },
        )
        .subscribe();
    })();
    return () => {
      cancelled = true;
      if (channel) supabase.removeChannel(channel);
    };
  }, [threadId, refresh]);

  // Auto-open rules. Fires once per thread once at least one fix has an
  // actual plan to show — opening on a row that's still in `planning`
  // surfaces the skeleton (or worse, "Plan unavailable") before the user
  // has anything to look at. User-dismissed wins.
  useEffect(() => {
    if (loading || userDismissed || autoOpenedRef.current) return;
    const openable = fixes.filter((f) => f.plan != null);
    if (openable.length === 0) return;
    autoOpenedRef.current = true;
    if (openable.length >= 2) {
      setView('list');
      setActiveFixId(null);
    } else {
      setActiveFixId(openable[0].id);
      setView('detail');
    }
  }, [fixes, loading, userDismissed]);

  const openFix = useCallback((fixId: string) => {
    setActiveFixId(fixId);
    setView('detail');
    setUserDismissed(false);
  }, []);

  const closeFix = useCallback(() => {
    setActiveFixId(null);
    setView('detail');
    setUserDismissed(true);
  }, []);

  const toggleFix = useCallback((fixId: string) => {
    setActiveFixId((curr) => {
      if (curr === fixId) {
        setUserDismissed(true);
        return null;
      }
      setView('detail');
      setUserDismissed(false);
      return fixId;
    });
  }, []);

  const showList = useCallback(() => {
    setView('list');
    setUserDismissed(false);
  }, []);

  const toggleSelected = useCallback((fixId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(fixId)) next.delete(fixId);
      else next.add(fixId);
      return next;
    });
  }, []);

  const clearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  const selectAll = useCallback(() => {
    setSelectedIds(new Set(fixes.map((f) => f.id)));
  }, [fixes]);

  const registerFix = useCallback((fixId: string) => {
    if (!threadId) return;
    // If we already have it, nothing to do — realtime will keep us fresh.
    if (fixes.some((f) => f.id === fixId)) return;
    void refresh();
  }, [threadId, fixes, refresh]);

  return (
    <FixPanelContext.Provider
      value={{
        fixes,
        loading,
        activeFixId,
        view,
        selectedIds,
        openFix,
        closeFix,
        toggleFix,
        showList,
        toggleSelected,
        clearSelection,
        selectAll,
        registerFix,
      }}
    >
      {children}
    </FixPanelContext.Provider>
  );
}

export function useFixPanel() {
  const ctx = useContext(FixPanelContext);
  if (!ctx) throw new Error('useFixPanel must be used within FixPanelProvider');
  return ctx;
}
