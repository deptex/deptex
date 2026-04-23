import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useNavigate, useOutletContext, useParams } from 'react-router-dom';
import { aegisApi, type AegisThread } from '../../lib/aegis-api';
import type { Organization } from '../../lib/api';
import { ThreadList } from '../../components/aegis/ThreadList';
import { ChatPane } from '../../components/aegis/ChatPane';
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
  const [searchOpen, setSearchOpen] = useState(false);
  const [pendingTitleThreadId, setPendingTitleThreadId] = useState<string | null>(null);
  const pendingTitleTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

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
    await refreshThreads();
    setPendingTitleThreadId(null);
  }, [refreshThreads]);

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
          pendingTitleThreadId={pendingTitleThreadId}
          onCreate={handleCreate}
          onSelect={handleSelect}
          onRename={handleRename}
          onDelete={handleDelete}
          onSetPinned={handleSetPinned}
          onSetArchived={handleSetArchived}
          onOpenSearch={() => setSearchOpen(true)}
        />
      </aside>
      <main className="flex-1 flex flex-col min-w-0">
        <ChatPane
          key={chatKey}
          organizationId={orgId}
          threadId={activeThreadId}
          currentUserId={user?.id ?? ''}
          displayName={displayName}
          onThreadCreated={handleThreadCreated}
          onThreadUpdated={handleThreadUpdated}
        />
      </main>

      <SearchChatsModal
        open={searchOpen}
        onOpenChange={setSearchOpen}
        threads={threads}
        onSelect={handleSelect}
      />
    </div>
  );
}
