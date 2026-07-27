import { useState, useEffect, useRef, useCallback } from 'react';
import { supabase } from '../lib/supabase';
import { api } from '../lib/api';

interface RealtimeStatus {
  status: string;
  extractionStep: string | null;
  lastSynced: string | null;
  lastError: string | null;
  lastExtractedAt: string | null;
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
    lastExtractedAt: null,
    isLoading: true,
  });

  // Reset state DURING render the moment projectId changes — not in the effect
  // below, which only runs after this render commits. Without this, the hook
  // returns the PREVIOUS project's status for the render where projectId has
  // already switched, so a consumer attributes the old project's
  // "extracting / no lastExtractedAt" to the newly-selected one (e.g. clicking
  // an extracting project then another flashes "creating" on the second). This
  // is React's sanctioned "adjust state when a prop changes" pattern; the guard
  // makes it converge in one extra render with no loop.
  const [trackedProjectId, setTrackedProjectId] = useState(projectId);
  if (projectId !== trackedProjectId) {
    setTrackedProjectId(projectId);
    setState({
      status: 'loading',
      extractionStep: null,
      lastSynced: null,
      lastError: null,
      lastExtractedAt: null,
      isLoading: true,
    });
  }

  const fallbackRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const realtimeOk = useRef(true);

  const fetchStatus = useCallback(async () => {
    if (!organizationId || !projectId) return;
    // Status-only read: the connected-repo row WITHOUT the slow listRepositories()
    // GitHub call. Always fresh (the endpoint isn't cached) so the pill shows
    // "still extracting" correctly; the realtime subscription pushes later updates.
    try {
      const data = await api.getProjectRepositoryStatus(organizationId, projectId);
      const repo = data.connectedRepository;
      if (repo) {
        setState({
          status: repo.status ?? 'not_connected',
          extractionStep: repo.extraction_step ?? null,
          lastSynced: repo.status === 'ready' ? repo.updated_at ?? null : null,
          lastError: null,
          lastExtractedAt: repo.last_extracted_at ?? null,
          isLoading: false,
        });
      } else {
        setState(prev => ({ ...prev, status: 'not_connected', lastExtractedAt: null, isLoading: false }));
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

    // Reset to loading immediately so stale state from a previous project doesn't flash
    setState({
      status: 'loading',
      extractionStep: null,
      lastSynced: null,
      lastError: null,
      lastExtractedAt: null,
      isLoading: true,
    });

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
          setState({
            status: row.status ?? 'unknown',
            extractionStep: row.extraction_step ?? null,
            lastSynced: row.status === 'ready' ? row.updated_at : null,
            lastError: null,
            lastExtractedAt: row.last_extracted_at ?? null,
            isLoading: false,
          });
        },
      )
      .subscribe((status) => {
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
