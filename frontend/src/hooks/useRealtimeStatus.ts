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
    try {
      const data = await api.getProjectRepositories(organizationId, projectId);
      const repo = data.connectedRepository;
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
