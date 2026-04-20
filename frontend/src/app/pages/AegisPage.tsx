import { useCallback, useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate, useOutletContext, useParams } from 'react-router-dom';
import { aegisApi, type AegisThread } from '../../lib/aegis-api';
import type { Organization } from '../../lib/api';
import { ThreadList } from '../../components/aegis/ThreadList';
import { EmptyState } from '../../components/aegis/EmptyState';
import { ChatInput } from '../../components/aegis/ChatInput';
import { ChatPane } from '../../components/aegis/ChatPane';
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
  const { toast } = useToast();

  const [threads, setThreads] = useState<AegisThread[]>([]);
  const [loading, setLoading] = useState(true);

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
      if (!activeThreadId && list && list.length > 0) {
        navigate(`/organizations/${orgId}/aegis/${list[0].id}`, { replace: true });
      }
    });
    return () => { cancelled = true; };
  }, [orgId, canUseAegis, refreshThreads, activeThreadId, navigate]);

  const handleCreate = useCallback(async () => {
    if (!orgId) return;
    try {
      const thread = await aegisApi.createThread(orgId);
      setThreads((prev) => [thread, ...prev]);
      navigate(`/organizations/${orgId}/aegis/${thread.id}`);
    } catch (err: any) {
      toast({ title: 'Could not create chat', description: err?.message, variant: 'destructive' });
    }
  }, [orgId, navigate, toast]);

  const handleSelect = useCallback((threadId: string) => {
    if (!orgId) return;
    navigate(`/organizations/${orgId}/aegis/${threadId}`);
  }, [orgId, navigate]);

  const handleRename = useCallback(async (threadId: string, title: string) => {
    try {
      const updated = await aegisApi.renameThread(threadId, title);
      setThreads((prev) => prev.map((t) => (t.id === threadId ? updated : t)));
    } catch (err: any) {
      toast({ title: 'Rename failed', description: err?.message, variant: 'destructive' });
    }
  }, [toast]);

  const handleDelete = useCallback(async (threadId: string) => {
    try {
      await aegisApi.deleteThread(threadId);
      setThreads((prev) => prev.filter((t) => t.id !== threadId));
      if (activeThreadId === threadId && orgId) {
        navigate(`/organizations/${orgId}/aegis`, { replace: true });
      }
    } catch (err: any) {
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

  const handlePromptSelect = useCallback((prompt: string) => {
    void startChatWithMessage(prompt);
  }, [startChatWithMessage]);

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
        />
      </aside>
      <main className="flex-1 flex flex-col min-w-0">
        {activeThreadId ? (
          <ChatPane
            key={activeThreadId}
            threadId={activeThreadId}
            organizationId={orgId}
            initialMessage={initialMessageForThread}
            onThreadUpdated={() => void refreshThreads()}
          />
        ) : (
          <>
            <div className="flex-1 overflow-y-auto">
              <EmptyState onSelectPrompt={handlePromptSelect} />
            </div>
            <ChatInput onSubmit={(msg) => void startChatWithMessage(msg)} autoFocus />
          </>
        )}
      </main>
    </div>
  );
}
