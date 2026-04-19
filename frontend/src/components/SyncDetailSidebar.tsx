import { useState, useEffect, useCallback, useRef } from 'react';
import { Check, X, Copy, Download, ChevronDown, Loader2, Ban } from 'lucide-react';
import { cn } from '../lib/utils';
import { Button } from './ui/button';
import { useToast } from '../hooks/use-toast';
import { supabase } from '../lib/supabase';
import { api, type ExtractionLog, type ExtractionRun } from '../lib/api';

export interface SyncLogEntry {
  id: number;
  shortId: string;
  commit: string;
  commitMessage?: string;
  time: string;
  duration: string;
  status: 'success' | 'error';
  trigger: string;
}

interface SyncDetailSidebarProps {
  entry?: SyncLogEntry;
  projectId: string;
  organizationId: string;
  onClose: () => void;
  onCancelled?: () => void;
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function levelColor(level: string): string {
  switch (level) {
    case 'success': return 'text-emerald-400';
    case 'warning': return 'text-amber-400';
    case 'error': return 'text-red-400';
    default: return 'text-zinc-400';
  }
}

function levelDot(level: string): string {
  switch (level) {
    case 'success': return 'bg-emerald-400';
    case 'warning': return 'bg-amber-400';
    case 'error': return 'bg-red-400';
    default: return 'bg-blue-400';
  }
}

export function SyncDetailSidebar({ projectId, organizationId, onClose, onCancelled }: SyncDetailSidebarProps) {
  const [panelVisible, setPanelVisible] = useState(false);
  const [logs, setLogs] = useState<ExtractionLog[]>([]);
  const [runs, setRuns] = useState<ExtractionRun[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<string | null>(null);
  const [showRunSelector, setShowRunSelector] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const { toast } = useToast();

  useEffect(() => {
    setPanelVisible(false);
    const raf = requestAnimationFrame(() => {
      requestAnimationFrame(() => setPanelVisible(true));
    });
    return () => cancelAnimationFrame(raf);
  }, []);

  useEffect(() => {
    api.getExtractionRuns(organizationId, projectId).then(setRuns).catch(() => {});
  }, [organizationId, projectId]);

  useEffect(() => {
    const runId = selectedRunId || undefined;
    api.getExtractionLogs(organizationId, projectId, runId).then(setLogs).catch(() => {});
  }, [organizationId, projectId, selectedRunId]);

  useEffect(() => {
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
          if (selectedRunId && newLog.run_id !== selectedRunId) return;
          setLogs((prev) => [...prev, newLog]);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [projectId, selectedRunId]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  const handleClose = useCallback(() => {
    setPanelVisible(false);
    setTimeout(onClose, 150);
  }, [onClose]);

  const handleCancel = useCallback(async () => {
    setCancelling(true);
    try {
      await api.cancelExtraction(organizationId, projectId);
      toast({ title: 'Extraction cancelled' });
      onCancelled?.();
    } catch (e: any) {
      toast({ title: 'Failed to cancel', description: e.message, variant: 'destructive' });
    } finally {
      setCancelling(false);
    }
  }, [organizationId, projectId, toast, onCancelled]);

  const logText = logs.map((l) => `${formatTimestamp(l.created_at)}  [${l.level}] ${l.message}`).join('\n');

  const handleCopyLogs = useCallback(() => {
    navigator.clipboard.writeText(logText);
    toast({ title: 'Logs copied to clipboard' });
  }, [logText, toast]);

  const handleDownloadLogs = useCallback(() => {
    const blob = new Blob([logText], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `extraction-${projectId}.log`;
    a.click();
    URL.revokeObjectURL(url);
    toast({ title: 'Logs downloaded' });
  }, [logText, projectId, toast]);

  const lastLog = logs[logs.length - 1];
  const isComplete = lastLog?.step === 'complete' && (lastLog.level === 'success' || lastLog.level === 'error');
  const hasError = lastLog?.level === 'error';
  const isActive = !isComplete && logs.length > 0;

  const currentRun = runs.find((r) => selectedRunId ? r.run_id === selectedRunId : true);

  return (
    <div className="fixed inset-0 z-50">
      <div
        className={cn(
          'fixed inset-0 bg-black/50 backdrop-blur-sm transition-opacity duration-150',
          panelVisible ? 'opacity-100' : 'opacity-0'
        )}
        onClick={handleClose}
      />

      <div
        className={cn(
          'fixed right-4 top-4 bottom-4 w-full max-w-[600px] bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl flex flex-col overflow-hidden transition-transform duration-150 ease-out',
          panelVisible ? 'translate-x-0' : 'translate-x-full'
        )}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="px-6 pt-5 pb-4 flex-shrink-0 border-b border-zinc-800">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-zinc-100">Extraction Logs</h2>
            <div className="flex items-center gap-2">
              {isActive && (
                <Button
                  variant="outline"
                  size="sm"
                  className="h-8 text-xs border-zinc-700 text-zinc-300 hover:text-zinc-100 hover:bg-zinc-800"
                  onClick={handleCancel}
                  disabled={cancelling}
                >
                  {cancelling ? (
                    <Loader2 className="h-3.5 w-3.5 mr-1.5 animate-spin" />
                  ) : (
                    <Ban className="h-3.5 w-3.5 mr-1.5" />
                  )}
                  Cancel
                </Button>
              )}
              <button
                onClick={handleClose}
                className="h-8 w-8 rounded-md flex items-center justify-center text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </div>

          {/* Status + Run selector */}
          <div className="flex items-center gap-3 mt-3">
            <div className="flex items-center gap-2 text-sm">
              {isComplete && !hasError && (
                <span className="flex items-center gap-1.5 text-emerald-400">
                  <Check className="h-4 w-4" />
                  Complete
                </span>
              )}
              {isComplete && hasError && (
                <span className="flex items-center gap-1.5 text-red-400">
                  <X className="h-4 w-4" />
                  Failed
                </span>
              )}
              {isActive && (
                <span className="flex items-center gap-1.5 text-blue-400">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  In progress
                </span>
              )}
              {!isActive && logs.length === 0 && (
                <span className="text-zinc-500">No logs yet</span>
              )}
            </div>

            {runs.length > 1 && (
              <div className="relative ml-auto">
                <button
                  onClick={() => setShowRunSelector(!showRunSelector)}
                  className="flex items-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
                >
                  {currentRun ? `Attempt ${currentRun.attempts}` : 'Latest'}
                  <ChevronDown className="h-3 w-3" />
                </button>
                {showRunSelector && (
                  <div className="absolute right-0 top-full mt-1 w-48 bg-zinc-900 border border-zinc-700 rounded-lg shadow-xl z-10 py-1">
                    <button
                      onClick={() => { setSelectedRunId(null); setShowRunSelector(false); }}
                      className={cn(
                        'w-full text-left px-3 py-1.5 text-xs hover:bg-zinc-800 transition-colors',
                        !selectedRunId ? 'text-zinc-100' : 'text-zinc-400'
                      )}
                    >
                      Latest
                    </button>
                    {runs.map((run) => (
                      <button
                        key={run.run_id}
                        onClick={() => { setSelectedRunId(run.run_id); setShowRunSelector(false); }}
                        className={cn(
                          'w-full text-left px-3 py-1.5 text-xs hover:bg-zinc-800 transition-colors',
                          selectedRunId === run.run_id ? 'text-zinc-100' : 'text-zinc-400'
                        )}
                      >
                        <span>{new Date(run.created_at).toLocaleString()}</span>
                        <span className={cn(
                          'ml-2',
                          run.status === 'completed' && 'text-emerald-500',
                          run.status === 'failed' && 'text-red-500',
                          run.status === 'cancelled' && 'text-amber-500'
                        )}>
                          {run.status}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Log stream */}
        <div className="flex-1 flex flex-col min-h-0 px-6 py-4">
          <div className="flex items-center justify-between gap-4 mb-3 flex-shrink-0">
            <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider">Output</h3>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                className="h-7 text-xs border-zinc-700 text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800"
                onClick={handleDownloadLogs}
                disabled={logs.length === 0}
              >
                <Download className="h-3 w-3 mr-1.5" />
                Download
              </Button>
              <button
                type="button"
                onClick={handleCopyLogs}
                disabled={logs.length === 0}
                className="h-7 w-7 rounded-md flex items-center justify-center text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800 transition-colors disabled:opacity-50"
                aria-label="Copy logs"
              >
                <Copy className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          <div ref={scrollRef} className="flex-1 min-h-0 overflow-auto custom-scrollbar">
            <div className="font-mono text-xs leading-relaxed space-y-0.5">
              {logs.map((line) => (
                <div key={line.id}>
                  <div
                    className="flex items-start gap-3 py-0.5 cursor-pointer hover:bg-zinc-900/50 rounded px-1 -mx-1"
                    onClick={() => setExpandedLogId(expandedLogId === line.id ? null : line.id)}
                  >
                    <span className="text-zinc-600 shrink-0 tabular-nums select-none">
                      {formatTimestamp(line.created_at)}
                    </span>
                    <span className={cn('h-2 w-2 rounded-full shrink-0 mt-1.5', levelDot(line.level))} />
                    <span className={cn('break-all', levelColor(line.level))}>
                      {line.message}
                    </span>
                    {line.duration_ms != null && (
                      <span className="text-zinc-600 shrink-0 ml-auto tabular-nums">
                        {formatDuration(line.duration_ms)}
                      </span>
                    )}
                  </div>
                  {expandedLogId === line.id && line.metadata && (
                    <div className="ml-14 mb-1 px-3 py-2 bg-zinc-900 border border-zinc-800 rounded text-zinc-500 text-[11px] whitespace-pre-wrap">
                      {JSON.stringify(line.metadata, null, 2)}
                    </div>
                  )}
                </div>
              ))}
              {isActive && (
                <div className="flex items-center gap-3 py-0.5 px-1">
                  <span className="text-zinc-600 shrink-0 tabular-nums select-none">
                    {formatTimestamp(new Date().toISOString())}
                  </span>
                  <span className="h-2 w-2 rounded-full shrink-0 mt-1.5 bg-blue-400 animate-pulse" />
                  <span className="text-zinc-500 animate-pulse">Waiting for next step...</span>
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-4 mt-3 text-[11px] text-zinc-600 flex-shrink-0 border-t border-zinc-800 pt-3">
            <span>Machine: {logs[0]?.metadata && typeof logs[0].metadata === 'object' ? 'Fly.io' : 'Worker'}</span>
            {currentRun?.attempts && <span>Attempt {currentRun.attempts}</span>}
          </div>
        </div>
      </div>
    </div>
  );
}
