import { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';
import { api, type ExtractionLog } from '../lib/api';

export type { ExtractionLog };

// ─── Pure formatting helpers (also used by SyncDetailSidebar, InlineExtractionLogs) ───

export function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

export function levelColor(level: string): string {
  switch (level) {
    case 'success': return 'text-emerald-400';
    case 'warning': return 'text-amber-400';
    case 'error': return 'text-red-400';
    default: return 'text-zinc-100';
  }
}

export function levelDotClass(level: string): string {
  switch (level) {
    case 'success': return 'bg-emerald-400';
    case 'warning': return 'bg-amber-400';
    case 'error': return 'bg-red-400';
    default: return 'bg-blue-400';
  }
}

export function filterLog(log: ExtractionLog): boolean {
  const msg = (log.message || '').toLowerCase();
  if (/atom analysis in progress/i.test(msg)) return false;
  if (/\d+\s*minute?\s*elapsed|elapsed\s*:\s*\d+/i.test(msg)) return false;
  if (/scan still running.*dep-?scan is quiet/i.test(msg)) return false;
  return true;
}

// ─── Hook ───

export interface UseExtractionLogsOptions {
  projectId: string | undefined;
  organizationId: string | undefined;
  runId?: string | null;
}

export interface UseExtractionLogsResult {
  logs: ExtractionLog[];
  filteredLogs: ExtractionLog[];
  isLoading: boolean;
  isComplete: boolean;
  hasError: boolean;
  isActive: boolean;
}

export function useExtractionLogs({
  projectId,
  organizationId,
  runId,
}: UseExtractionLogsOptions): UseExtractionLogsResult {
  const [logs, setLogs] = useState<ExtractionLog[]>([]);
  const [isLoading, setIsLoading] = useState(true);

  // Fetch logs when projectId / runId changes
  useEffect(() => {
    if (!organizationId || !projectId) {
      setIsLoading(false);
      return;
    }
    setIsLoading(true);
    setLogs([]);
    api
      .getExtractionLogs(organizationId, projectId, runId ?? undefined)
      .then((data) => {
        setLogs(data);
        setIsLoading(false);
      })
      .catch(() => {
        setLogs([]);
        setIsLoading(false);
      });
  }, [organizationId, projectId, runId]);

  // Real-time subscription
  useEffect(() => {
    if (!projectId) return;
    const channel = supabase
      .channel(`extraction-logs-${projectId}`)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'extraction_logs',
          filter: `project_id=eq.${projectId}`,
        },
        (payload) => {
          const newLog = payload.new as ExtractionLog;
          if (runId && newLog.run_id !== runId) return;
          setLogs((prev) => [...prev, newLog]);
        }
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [projectId, runId]);

  const filteredLogs = logs.filter(filterLog);
  const lastLog = logs[logs.length - 1];
  const isComplete = Boolean(lastLog?.step === 'complete' && (lastLog.level === 'success' || lastLog.level === 'error'));
  const hasError = Boolean(isComplete && lastLog?.level === 'error');
  const isActive = !isComplete && logs.length > 0;

  return { logs, filteredLogs, isLoading, isComplete, hasError, isActive };
}
