import { useCallback, useEffect, useState } from 'react';
import { useNavigate, useOutletContext, useParams } from 'react-router-dom';
import { aegisApi, type AegisThread } from '../../lib/aegis-api';
import type { Organization } from '../../lib/api';
import { ThreadList } from '../../components/aegis/ThreadList';
import { EmptyState } from '../../components/aegis/EmptyState';
import { useToast } from '../../hooks/use-toast';

interface OrgOutlet {
  organization: Organization | null;
  reloadOrganization: () => Promise<void>;
}

export default function AegisPage() {
  const { id: orgId, threadId: activeThreadId } = useParams<{ id: string; threadId?: string }>();
  const navigate = useNavigate();
  const { organization } = useOutletContext<OrgOutlet>();
  const { toast } = useToast();

  const [threads, setThreads] = useState<AegisThread[]>([]);
  const [loading, setLoading] = useState(true);

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

  const handlePromptSelect = useCallback((_prompt: string) => {
    // Streaming is M5 — for now, create a fresh thread so the user has something.
    void handleCreate();
  }, [handleCreate]);

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
      <aside className="w-[260px] flex-shrink-0 border-r border-border bg-background-card">
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
          <div className="flex h-full items-center justify-center text-sm text-foreground/60">
            Chat pane lands in M5.
          </div>
        ) : (
          <EmptyState onSelectPrompt={handlePromptSelect} />
        )}
      </main>
    </div>
  );
}
