import { useState, useEffect, useRef, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { api } from '../lib/api';

interface RealtimeStatus {
  status: string;
  extractionStep: string | null;
  lastSynced: string | null;
  lastError: string | null;
  isLoading: boolean;
}

export function useRealtimeStatus(
  organizationId: string | undefined,
  projectId: string | undefined,
): RealtimeStatus {
  const [state, setState] = useState<RealtimeStatus>({
    status: 'loading',
    extractionStep: null,
    lastSynced: null,
    lastError: null,
    isLoading: true,
  });

  const fallbackRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const realtimeOk = useRef(true);

  const fetchStatus = useCallback(async () => {
    if (!organizationId || !projectId) return;
    // #region agent log
    fetch('http://127.0.0.1:7243/ingest/53e74682-68cf-45a2-9b9e-de506b5f8b18',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'df7584'},body:JSON.stringify({sessionId:'df7584',location:'useRealtimeStatus.ts:fetchStatus:entry',message:'fetchStatus called',data:{organizationId,projectId},timestamp:Date.now(),hypothesisId:'H3'})}).catch(()=>{});
    // #endregion
    // Always fetch fresh extraction status so Overview shows "still extracting" correctly (no stale cache)
    api.invalidateProjectRepositoriesCache(organizationId, projectId);
    try {
      const data = await api.getProjectRepositories(organizationId, projectId);
      const repo = data.connectedRepository;
      // #region agent log
      const repoStatus = repo ? (repo as any).status : null;
      fetch('http://127.0.0.1:7243/ingest/53e74682-68cf-45a2-9b9e-de506b5f8b18',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'df7584'},body:JSON.stringify({sessionId:'df7584',location:'useRealtimeStatus.ts:fetchStatus:result',message:'fetchStatus result',data:{hasRepo:!!repo,repoStatus,projectId},timestamp:Date.now(),hypothesisId:'H2'})}).catch(()=>{});
      // #endregion
      if (repo) {
        setState({
          status: repo.status ?? 'not_connected',
          extractionStep: repo.extraction_step ?? null,
          lastSynced: repo.status === 'ready' ? repo.updated_at ?? null : null,
          lastError: null,
          isLoading: false,
        });
      } else {
        setState(prev => ({ ...prev, status: 'not_connected', isLoading: false }));
      }
    } catch {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  }, [organizationId, projectId]);

  // When status is not 'ready', refetch every 10s so we pick up 'ready' even if Realtime doesn't fire
  const pollIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  useEffect(() => {
    if (!organizationId || !projectId || state.status === 'ready' || state.status === 'not_connected' || state.isLoading) {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
      return;
    }
    pollIntervalRef.current = setInterval(fetchStatus, 10000);
    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
        pollIntervalRef.current = null;
      }
    };
  }, [organizationId, projectId, state.status, state.isLoading, fetchStatus]);

  useEffect(() => {
    if (!projectId) return;

    fetchStatus();

    const channel = supabase
      .channel(`project-repo-status-${projectId}`)
      .on(
        'postgres_changes',
        {
          event: 'UPDATE',
          schema: 'public',
          table: 'project_repositories',
          filter: `project_id=eq.${projectId}`,
        },
        (payload) => {
          const row = payload.new as any;
          // #region agent log
          fetch('http://127.0.0.1:7243/ingest/53e74682-68cf-45a2-9b9e-de506b5f8b18',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'df7584'},body:JSON.stringify({sessionId:'df7584',location:'useRealtimeStatus.ts:realtime:UPDATE',message:'Realtime UPDATE received',data:{rowStatus:row?.status,projectId:row?.project_id},timestamp:Date.now(),hypothesisId:'H1'})}).catch(()=>{});
          // #endregion
          setState({
            status: row.status ?? 'unknown',
            extractionStep: row.extraction_step ?? null,
            lastSynced: row.status === 'ready' ? row.updated_at : null,
            lastError: null,
            isLoading: false,
          });
        },
      )
      .subscribe((status) => {
        // #region agent log
        fetch('http://127.0.0.1:7243/ingest/53e74682-68cf-45a2-9b9e-de506b5f8b18',{method:'POST',headers:{'Content-Type':'application/json','X-Debug-Session-Id':'df7584'},body:JSON.stringify({sessionId:'df7584',location:'useRealtimeStatus.ts:subscribe',message:'Realtime subscribe status',data:{status,projectId},timestamp:Date.now(),hypothesisId:'H5'})}).catch(()=>{});
        // #endregion
        if (status === 'SUBSCRIBED') {
          realtimeOk.current = true;
        } else if (status === 'TIMED_OUT' || status === 'CHANNEL_ERROR') {
          realtimeOk.current = false;
          if (!fallbackRef.current) {
            fallbackRef.current = setInterval(fetchStatus, 5000);
          }
        }
      });

    const timeout = setTimeout(() => {
      if (!realtimeOk.current && !fallbackRef.current) {
        fallbackRef.current = setInterval(fetchStatus, 5000);
      }
    }, 5000);

    return () => {
      clearTimeout(timeout);
      supabase.removeChannel(channel);
      if (fallbackRef.current) {
        clearInterval(fallbackRef.current);
        fallbackRef.current = null;
      }
    };
  }, [projectId, fetchStatus]);

  return state;
}
