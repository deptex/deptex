import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useNavigate, useOutletContext, useParams } from 'react-router-dom';
import { aegisApi, type AegisThread } from '../../lib/aegis-api';
import type { Organization } from '../../lib/api';
import { ThreadList } from '../../components/aegis/ThreadList';
import { LandingHero } from '../../components/aegis/LandingHero';
import { ChatPane } from '../../components/aegis/ChatPane';
import { JoinByCodeModal } from '../../components/aegis/JoinByCodeModal';
import { SearchChatsModal } from '../../components/aegis/SearchChatsModal';
import { useAuth } from '../../contexts/AuthContext';
import { useToast } from '../../hooks/use-toast';

interface OrgOutlet {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

export default function AegisPage() {
  const { id: orgId, threadId: activeThreadId } = useParams<{ id: string; threadId?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { organization } = useOutletContext<OrgOutlet>();
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
  const [joinByCodeOpen, setJoinByCodeOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const activeThread = useMemo(
    () => threads.find((t) => t.id === activeThreadId) ?? null,
    [threads, activeThreadId],
  );

  // Capture initialMessage once per thread navigation so it isn't resent on re-renders.
  const consumedInitialRef = useRef<string | null>(null);
  const [initialMessageForThread, setInitialMessageForThread] = useState<string | undefined>(undefined);
  useEffect(() => {
    const state = location.state as { initialMessage?: string } | null;
    const key = activeThreadId ?? null;
    if (state?.initialMessage && consumedInitialRef.current !== key) {
      consumedInitialRef.current = key;
      setInitialMessageForThread(state.initialMessage);
      // Clear the state so refresh doesn't re-trigger.
      navigate(location.pathname, { replace: true, state: null });
    } else if (consumedInitialRef.current !== key) {
      consumedInitialRef.current = key;
      setInitialMessageForThread(undefined);
    }
  }, [activeThreadId, location, navigate]);

  const canUseAegis = organization?.permissions?.interact_with_aegis === true;

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

  // Tracks whether we've already done the initial auto-navigate to the latest thread.
  // Prevents "New chat" (which clears activeThreadId) from being immediately overridden.
  const autoNavigatedRef = useRef(false);
  const activeThreadIdRef = useRef(activeThreadId);
  activeThreadIdRef.current = activeThreadId;

  useEffect(() => {
    if (!orgId || !canUseAegis) {
      setLoading(false);
      return;
    }
    let cancelled = false;
    setLoading(true);
    refreshThreads().then((list) => {
      if (cancelled) return;
      setLoading(false);
      if (!autoNavigatedRef.current && !activeThreadIdRef.current && list && list.length > 0) {
        autoNavigatedRef.current = true;
        const firstVisible = list.find((t) => !t.archivedAt);
        if (firstVisible) {
          navigate(`/organizations/${orgId}/aegis/${firstVisible.id}`, { replace: true });
        }
      }
    });
    return () => { cancelled = true; };
  // activeThreadId intentionally excluded — navigating away from a thread should
  // not retrigger a load+auto-navigate that would override "New chat".
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, canUseAegis, refreshThreads]);

  // "New chat" just returns to the landing screen; the thread is created when the
  // user actually submits their first message.
  const handleCreate = useCallback(() => {
    if (!orgId) return;
    navigate(`/organizations/${orgId}/aegis`);
  }, [orgId, navigate]);

  const handleSelect = useCallback((threadId: string) => {
    if (!orgId) return;
    navigate(`/organizations/${orgId}/aegis/${threadId}`);
  }, [orgId, navigate]);

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

  const handleLeave = useCallback(async (threadId: string) => {
    if (!user) return;
    let snapshot: AegisThread[] = [];
    setThreads((prev) => {
      snapshot = prev;
      return prev.filter((t) => t.id !== threadId);
    });
    if (activeThreadId === threadId && orgId) {
      navigate(`/organizations/${orgId}/aegis`, { replace: true });
    }
    try {
      await aegisApi.removeParticipant(threadId, user.id);
    } catch (err: any) {
      setThreads(snapshot);
      toast({ title: 'Leave failed', description: err?.message, variant: 'destructive' });
    }
  }, [activeThreadId, orgId, navigate, toast, user]);

  const handleJoined = useCallback((threadId: string) => {
    if (!orgId) return;
    refreshThreads();
    navigate(`/organizations/${orgId}/aegis/${threadId}`);
  }, [orgId, navigate, refreshThreads]);

  const handleDelete = useCallback(async (threadId: string) => {
    // Optimistic — remove locally and navigate away, rollback on failure.
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

  const startChatWithMessage = useCallback(async (message: string) => {
    if (!orgId) return;
    try {
      const thread = await aegisApi.createThread(orgId);
      setThreads((prev) => [thread, ...prev]);
      navigate(`/organizations/${orgId}/aegis/${thread.id}`, { state: { initialMessage: message } });
    } catch (err: any) {
      toast({ title: 'Could not start chat', description: err?.message, variant: 'destructive' });
    }
  }, [orgId, navigate, toast]);

  if (!orgId) return null;
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
      <aside className="w-[260px] flex-shrink-0 border-r border-border bg-background">
        <ThreadList
          threads={threads}
          activeThreadId={activeThreadId ?? null}
          loading={loading}
          onCreate={handleCreate}
          onSelect={handleSelect}
          onRename={handleRename}
          onDelete={handleDelete}
          onSetPinned={handleSetPinned}
          onSetArchived={handleSetArchived}
          onLeave={handleLeave}
          onOpenJoinByCode={() => setJoinByCodeOpen(true)}
          onOpenSearch={() => setSearchOpen(true)}
        />
      </aside>
      <main className="flex-1 flex flex-col min-w-0">
        {activeThreadId ? (
          <ChatPane
            key={activeThreadId}
            threadId={activeThreadId}
            organizationId={orgId}
            thread={activeThread ?? undefined}
            currentUserId={user?.id ?? ''}
            initialMessage={initialMessageForThread}
            onThreadUpdated={() => void refreshThreads()}
          />
        ) : (
          <LandingHero
            name={displayName}
            onSubmit={(msg) => void startChatWithMessage(msg)}
          />
        )}
      </main>

      <JoinByCodeModal
        open={joinByCodeOpen}
        onOpenChange={setJoinByCodeOpen}
        onJoined={handleJoined}
      />

      <SearchChatsModal
        open={searchOpen}
        onOpenChange={setSearchOpen}
        threads={threads}
        onSelect={handleSelect}
      />
    </div>
  );
}
