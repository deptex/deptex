import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent as ReactMouseEvent } from 'react';
import { useLocation, useNavigate, useOutletContext, useParams, useSearchParams } from 'react-router-dom';
import { aegisApi, type AegisThread } from '../../lib/aegis-api';
import type { Organization, RolePermissions } from '../../lib/api';
import { ThreadList } from '../../components/aegis/ThreadList';
import { ChatPane } from '../../components/aegis/ChatPane';
import { SearchChatsModal } from '../../components/aegis/SearchChatsModal';
import { PlanCard } from '../../components/aegis/PlanCard';
import { RoutinesPanel } from '../../components/aegis/RoutinesPanel';
import { PlanPanelProvider } from '../../components/aegis/PlanPanelContext';
import { PlanPanelHost } from '../../components/aegis/PlanPanelHost';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../hooks/use-toast';

interface OrgOutlet {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
  userPermissions: RolePermissions | null;
}

export default function AegisPage() {
  const { id: orgId, threadId: activeThreadId } = useParams<{ id: string; threadId?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const routinesActive = location.pathname.endsWith('/aegis/routines');
  const [searchParams] = useSearchParams();
  const fixIdParam = searchParams.get('fix');
  const { userPermissions } = useOutletContext<OrgOutlet>();
  const { user } = useAuth();
  const { toast } = useToast();

  const displayName = (() => {
    const full = user?.user_metadata?.full_name as string | undefined;
    if (full) return full.split(' ')[0];
    if (user?.email) return user.email.split('@')[0];
    return 'there';
  })();

  const [threads, setThreads] = useState<AegisThread[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchOpen, setSearchOpen] = useState(false);
  const [pendingTitleThreadId, setPendingTitleThreadId] = useState<string | null>(null);
  const pendingTitleTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const SIDEBAR_MIN = 200;
  const SIDEBAR_MAX = 380;
  const SIDEBAR_DEFAULT = 260;
  const SIDEBAR_KEY = 'aegis-sidebar-width';
  const [sidebarWidth, setSidebarWidth] = useState<number>(() => {
    if (typeof window === 'undefined') return SIDEBAR_DEFAULT;
    const stored = window.localStorage.getItem(SIDEBAR_KEY);
    const parsed = stored ? parseInt(stored, 10) : NaN;
    return Number.isFinite(parsed) ? Math.min(Math.max(parsed, SIDEBAR_MIN), SIDEBAR_MAX) : SIDEBAR_DEFAULT;
  });

  const startSidebarResize = useCallback((e: ReactMouseEvent) => {
    e.preventDefault();
    const startX = e.clientX;
    const startWidth = sidebarWidth;
    const clamp = (n: number) => Math.min(Math.max(n, SIDEBAR_MIN), SIDEBAR_MAX);
    const onMove = (ev: globalThis.MouseEvent) => {
      setSidebarWidth(clamp(startWidth + (ev.clientX - startX)));
    };
    const onUp = (ev: globalThis.MouseEvent) => {
      const next = clamp(startWidth + (ev.clientX - startX));
      window.localStorage.setItem(SIDEBAR_KEY, String(next));
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  }, [sidebarWidth]);

  // The key passed to ChatPane. It stays stable across "silent" URL updates
  // (e.g. when ChatPane creates a thread from the landing state and we just
  // want to reflect the new threadId in the URL). It only changes when the
  // user intentionally switches context — clicking a different thread in the
  // sidebar, hitting "New chat", etc.
  const [chatKey, setChatKey] = useState<string>(() => activeThreadId ?? 'new');
  const silentUrlUpdateRef = useRef(false);

  useEffect(() => {
    if (silentUrlUpdateRef.current) {
      silentUrlUpdateRef.current = false;
      return;
    }
    setChatKey(activeThreadId ?? `new-${Date.now()}`);
  }, [activeThreadId]);

  // userPermissions === null means "still resolving" (cache miss + dbPermissions
  // still in flight). Only treat the absence of `interact_with_aegis` as a true
  // denial once we actually have a permissions object — otherwise the gate
  // flashes on every refresh before OrganizationLayout finishes loading.
  const permissionsLoading = userPermissions === null;
  const canUseAegis = userPermissions?.interact_with_aegis === true;

  const refreshThreads = useCallback(async () => {
    if (!orgId) return;
    try {
      const list = await aegisApi.listThreads(orgId);
      setThreads(list);
      return list;
    } catch (err: any) {
      toast({ title: 'Failed to load chats', description: err?.message ?? 'Unknown error', variant: 'destructive' });
      return [];
    }
  }, [orgId, toast]);

  useEffect(() => {
    if (!orgId || !canUseAegis) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    refreshThreads().then(() => {
      if (cancelled) return;
      setLoading(false);
    });
    return () => { cancelled = true; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, canUseAegis, refreshThreads]);

  const handleCreate = useCallback(() => {
    if (!orgId) return;
    // Force a fresh chatKey synchronously. Without this, hitting "New chat"
    // immediately after sending the first message of a new chat (silent URL
    // update path: chatKey stays "new" while activeThreadId becomes the new
    // id) won't remount ChatPane, because the only chatKey transition the
    // useEffect would trigger is "new" -> `new-${ts}` which sometimes races
    // with the navigate-driven param update. Setting it here guarantees a
    // remount regardless of the effect ordering.
    setChatKey(`new-${Date.now()}`);
    navigate(`/organizations/${orgId}/aegis`);
  }, [orgId, navigate]);

  const handleSelect = useCallback((threadId: string) => {
    if (!orgId) return;
    navigate(`/organizations/${orgId}/aegis/${threadId}`);
  }, [orgId, navigate]);

  // Called by ChatPane when it creates a thread from the landing state.
  // Updates the URL silently (no remount) and injects an optimistic thread
  // into the sidebar so the user sees the skeleton title immediately.
  const handleThreadCreated = useCallback((threadId: string) => {
    if (!orgId) return;
    silentUrlUpdateRef.current = true;
    const now = new Date().toISOString();
    setThreads((prev) => {
      if (prev.some((t) => t.id === threadId)) return prev;
      const optimistic: AegisThread = {
        id: threadId,
        organizationId: orgId,
        userId: user?.id ?? '',
        createdBy: user?.id ?? '',
        isCreator: true,
        participantCount: 1,
        title: 'New chat',
        createdAt: now,
        updatedAt: now,
        pinnedAt: null,
        archivedAt: null,
        fixStatus: null,
      };
      return [optimistic, ...prev];
    });
    setPendingTitleThreadId(threadId);
    if (pendingTitleTimeoutRef.current) clearTimeout(pendingTitleTimeoutRef.current);
    pendingTitleTimeoutRef.current = setTimeout(() => setPendingTitleThreadId(null), 20_000);
    navigate(`/organizations/${orgId}/aegis/${threadId}`, { replace: true });
  }, [orgId, user, navigate]);

  const handleThreadUpdated = useCallback(async () => {
    if (pendingTitleTimeoutRef.current) clearTimeout(pendingTitleTimeoutRef.current);
    const list = await refreshThreads();
    // The auto-title runs in the background on the server (fire-and-forget so
    // the response stream closes immediately). On a brand-new thread the
    // first refresh may still see the placeholder "New chat" — keep the
    // skeleton up and poll a few times until the title lands or we hit the
    // 20s ceiling.
    const pendingId = pendingTitleThreadId;
    const stillPlaceholder =
      pendingId && list?.find((t) => t.id === pendingId)?.title === 'New chat';
    if (!pendingId || !stillPlaceholder) {
      setPendingTitleThreadId(null);
      return;
    }
    let attempts = 0;
    const poll = async () => {
      attempts += 1;
      const next = await refreshThreads();
      const stillPending = next?.find((t) => t.id === pendingId)?.title === 'New chat';
      if (!stillPending) {
        setPendingTitleThreadId(null);
        return;
      }
      if (attempts < 8) {
        pendingTitleTimeoutRef.current = setTimeout(() => { void poll(); }, 1500);
      } else {
        setPendingTitleThreadId(null);
      }
    };
    pendingTitleTimeoutRef.current = setTimeout(() => { void poll(); }, 800);
  }, [refreshThreads, pendingTitleThreadId]);

  const handleRename = useCallback(async (threadId: string, title: string) => {
    let previous: AegisThread | undefined;
    setThreads((prev) => {
      previous = prev.find((t) => t.id === threadId);
      return prev.map((t) => (t.id === threadId ? { ...t, title } : t));
    });
    try {
      await aegisApi.renameThread(threadId, title);
    } catch (err: any) {
      if (previous) {
        setThreads((prev) => prev.map((t) => (t.id === threadId ? previous! : t)));
      }
      toast({ title: 'Rename failed', description: err?.message, variant: 'destructive' });
    }
  }, [toast]);

  const handleSetPinned = useCallback(async (threadId: string, pinned: boolean) => {
    const nowIso = new Date().toISOString();
    let snapshot: AegisThread[] = [];
    setThreads((prev) => {
      snapshot = prev;
      return prev.map((t) => (t.id === threadId ? { ...t, pinnedAt: pinned ? nowIso : null } : t));
    });
    try {
      await aegisApi.setThreadPinned(threadId, pinned);
    } catch (err: any) {
      setThreads(snapshot);
      toast({ title: pinned ? 'Pin failed' : 'Unpin failed', description: err?.message, variant: 'destructive' });
    }
  }, [toast]);

  const handleSetArchived = useCallback(async (threadId: string, archived: boolean) => {
    const nowIso = new Date().toISOString();
    let snapshot: AegisThread[] = [];
    setThreads((prev) => {
      snapshot = prev;
      return prev.map((t) => (t.id === threadId ? { ...t, archivedAt: archived ? nowIso : null } : t));
    });
    if (archived && activeThreadId === threadId && orgId) {
      navigate(`/organizations/${orgId}/aegis`, { replace: true });
    }
    try {
      await aegisApi.setThreadArchived(threadId, archived);
    } catch (err: any) {
      setThreads(snapshot);
      toast({ title: archived ? 'Archive failed' : 'Unarchive failed', description: err?.message, variant: 'destructive' });
    }
  }, [activeThreadId, orgId, navigate, toast]);

  const handleDelete = useCallback(async (threadId: string) => {
    let snapshot: AegisThread[] = [];
    setThreads((prev) => {
      snapshot = prev;
      return prev.filter((t) => t.id !== threadId);
    });
    if (activeThreadId === threadId && orgId) {
      navigate(`/organizations/${orgId}/aegis`, { replace: true });
    }
    try {
      await aegisApi.deleteThread(threadId);
    } catch (err: any) {
      setThreads(snapshot);
      toast({ title: 'Delete failed', description: err?.message, variant: 'destructive' });
    }
  }, [activeThreadId, orgId, navigate, toast]);

  if (!orgId) return null;
  // While permissions resolve, render an empty shell rather than the denial
  // gate. The OrganizationLayout sidebar/header is already on screen, so a
  // blank main pane is the least jarring intermediate state.
  if (permissionsLoading) {
    return <div className="h-[calc(100vh-3rem)] bg-background" />;
  }
  if (!canUseAegis) {
    return (
      <div className="flex h-[calc(100vh-3rem)] items-center justify-center p-12">
        <div className="max-w-md text-center">
          <h1 className="text-base font-semibold text-foreground mb-2">Aegis is not available</h1>
          <p className="text-sm text-foreground/80">
            Your role does not have the <code className="px-1 py-0.5 rounded bg-background-subtle text-xs">interact_with_aegis</code> permission.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-[calc(100vh-3rem)] bg-background">
      <aside
        className="relative flex-shrink-0 border-r border-border bg-background"
        style={{ width: sidebarWidth }}
      >
        <ThreadList
          threads={threads}
          activeThreadId={activeThreadId ?? null}
          loading={loading}
          pendingTitleThreadId={pendingTitleThreadId}
          onCreate={handleCreate}
          onSelect={handleSelect}
          onRename={handleRename}
          onDelete={handleDelete}
          onSetPinned={handleSetPinned}
          onSetArchived={handleSetArchived}
          onOpenSearch={() => setSearchOpen(true)}
          onOpenRoutines={() => orgId && navigate(`/organizations/${orgId}/aegis/routines`)}
          routinesActive={routinesActive}
        />
        <div
          onMouseDown={startSidebarResize}
          role="separator"
          aria-orientation="vertical"
          aria-label="Resize sidebar"
          className="absolute top-0 right-0 h-full w-1 -mr-0.5 cursor-col-resize hover:bg-foreground/15 active:bg-foreground/25 transition-colors z-10"
        />
      </aside>
      <PlanPanelProvider resetKey={`${activeThreadId ?? 'home'}|${routinesActive ? 'routines' : 'chat'}`}>
        <main className="flex-1 flex min-w-0">
          <div className="flex-1 flex flex-col min-w-0">
            {routinesActive ? (
              <RoutinesPanel />
            ) : (
              <>
                {fixIdParam && (
                  <div className="px-4 pt-4">
                    <div className="mx-auto max-w-3xl">
                      <PlanCard fixId={fixIdParam} organizationId={orgId} />
                    </div>
                  </div>
                )}
                <ChatPane
                  key={chatKey}
                  organizationId={orgId}
                  threadId={activeThreadId}
                  currentUserId={user?.id ?? ''}
                  displayName={displayName}
                  onThreadCreated={handleThreadCreated}
                  onThreadUpdated={handleThreadUpdated}
                  recents={threads}
                  onSelectRecent={handleSelect}
                />
              </>
            )}
          </div>
          <PlanPanelHost />
        </main>
      </PlanPanelProvider>

      <SearchChatsModal
        open={searchOpen}
        onOpenChange={setSearchOpen}
        threads={threads}
        onSelect={handleSelect}
        onSetArchived={handleSetArchived}
      />
    </div>
  );
}
