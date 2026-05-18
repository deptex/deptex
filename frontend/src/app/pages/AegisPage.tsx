import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useOutletContext, useParams, useSearchParams } from 'react-router-dom';
import { aegisApi, type AegisThread } from '../../lib/aegis-api';
import type { Organization, RolePermissions } from '../../lib/api';
import { ChatPane } from '../../components/aegis/ChatPane';
import { SearchChatsModal } from '../../components/aegis/SearchChatsModal';
import { PlanCard } from '../../components/aegis/PlanCard';
import { RoutinesPanel } from '../../components/aegis/RoutinesPanel';
import { FixPanelProvider } from '../../components/aegis/FixPanelContext';
import { FixPanelHost } from '../../components/aegis/FixPanelHost';
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
    const meta = user?.user_metadata;
    const id = user?.identities?.[0]?.identity_data as
      | { full_name?: string; name?: string }
      | undefined;
    const full = (meta?.custom_full_name || meta?.full_name || id?.full_name || id?.name) as
      | string
      | undefined;
    if (full) return full.split(' ')[0];
    if (user?.email) return user.email.split('@')[0];
    return 'there';
  })();

  const [threads, setThreads] = useState<AegisThread[]>([]);
  const [searchOpen, setSearchOpen] = useState(false);

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
    if (!orgId || !canUseAegis) return;
    void refreshThreads();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [orgId, canUseAegis]);

  const handleSelect = useCallback((threadId: string) => {
    if (!orgId) return;
    navigate(`/organizations/${orgId}/aegis/${threadId}`);
  }, [orgId, navigate]);

  // Called by ChatPane when it creates a thread from the landing state.
  // Updates the URL silently (no remount) and signals OrgSidebar to refresh.
  // The event payload carries the optimistic thread so OrgSidebar can insert
  // it immediately — without that, OrgSidebar's API refresh races the
  // server-side insert and returns the prior list, leaving the sidebar
  // empty until the first stream completes.
  const handleThreadCreated = useCallback((threadId: string) => {
    if (!orgId) return;
    silentUrlUpdateRef.current = true;
    const now = new Date().toISOString();
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
    setThreads((prev) => (prev.some((t) => t.id === threadId) ? prev : [optimistic, ...prev]));
    window.dispatchEvent(
      new CustomEvent('aegis:threadCreated', { detail: { thread: optimistic } }),
    );
    navigate(`/organizations/${orgId}/aegis/${threadId}`, { replace: true });
  }, [orgId, user, navigate]);

  const handleThreadUpdated = useCallback(async () => {
    await refreshThreads();
    window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
  }, [refreshThreads]);

  const handleSetArchived = useCallback(async (threadId: string, archived: boolean) => {
    const nowIso = new Date().toISOString();
    let snapshot: AegisThread[] = [];
    setThreads((prev) => {
      snapshot = prev;
      return prev.map((t) => (t.id === threadId ? { ...t, archivedAt: archived ? nowIso : null } : t));
    });
    try {
      await aegisApi.setThreadArchived(threadId, archived);
      window.dispatchEvent(new CustomEvent('aegis:threadListChanged'));
    } catch (err: any) {
      setThreads(snapshot);
      toast({ title: archived ? 'Archive failed' : 'Unarchive failed', description: err?.message, variant: 'destructive' });
    }
  }, [toast]);

  useEffect(() => {
    const handler = () => setSearchOpen(true);
    window.addEventListener('aegis:openSearch', handler);
    return () => window.removeEventListener('aegis:openSearch', handler);
  }, []);

  if (!orgId) return null;
  // While permissions resolve, render an empty shell rather than the denial
  // gate. The OrganizationLayout sidebar/header is already on screen, so a
  // blank main pane is the least jarring intermediate state.
  if (permissionsLoading) {
    return <div className="h-[100vh] bg-background" />;
  }
  if (!canUseAegis) {
    return (
      <div className="flex h-[100vh] items-center justify-center p-12">
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
    <FixPanelProvider threadId={routinesActive ? null : (activeThreadId ?? null)}>
      <div className="flex h-[100vh] bg-background">
        <div className="flex-1 flex flex-col min-w-0">
          {routinesActive ? (
            <RoutinesPanel />
          ) : (
            <>
              {fixIdParam && (
                <div className="px-4 pt-4">
                  <div className="mx-auto max-w-3xl">
                    <PlanCard fixId={fixIdParam} />
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
              />
            </>
          )}
        </div>
        <FixPanelHost />
      </div>
      <SearchChatsModal
        open={searchOpen}
        onOpenChange={setSearchOpen}
        threads={threads}
        onSelect={handleSelect}
        onSetArchived={handleSetArchived}
      />
    </FixPanelProvider>
  );
}
