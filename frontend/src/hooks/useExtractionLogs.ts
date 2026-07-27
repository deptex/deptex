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
  const msg = (log.message || '').trim();
  const lower = msg.toLowerCase();
  // Pre-existing noise filters.
  if (/atom analysis in progress/.test(lower)) return false;
  if (/\d+\s*minute?\s*elapsed|elapsed\s*:\s*\d+/.test(lower)) return false;
  if (/scan still running.*dep-?scan is quiet/.test(lower)) return false;
  // Per-package malicious-scan progress ("Scanned 450/1000 packages…"). The worker
  // emits one per package as a throttled watchdog-liveness ping; it's pure churn in the
  // user-facing log. The "Scanning packages…" kickoff + the completion line still show.
  if (/^scanned\s+\d+\s*\/\s*\d+\s+packages/.test(lower)) return false;
  // Per-language parser setup ("js setup complete", "go setup complete", "other setup
  // complete") — the tree-sitter usage-extractor initialising each language's grammar.
  // Internal plumbing, not a user milestone; drop it (it ends in "complete" so the
  // clean-success rule below would otherwise keep it).
  if (/\bsetup complete$/i.test(msg)) return false;

  // Same terminal look as before — we just drop the internal detail chatter and
  // keep the high-level milestones. The full logs still live in extraction_logs.
  // Always surface failures.
  if (log.level === 'error') return true;
  // Stage marker.
  if (lower === 'extraction started') return true;
  // "Doing X…" lines (announce a step — end with an ellipsis).
  if (/(?:\.\.\.|…)$/.test(msg)) return true;
  // Clean "X done" lines (drop the verbose stat-dump successes like
  // "Emitted 15 flows…" / "71/71 scanned, 0 feed + 0 GuardDog hits…").
  if (log.level === 'success' && /(?:successfully|complete|generated)$/i.test(msg)) return true;
  // The malicious-package scan's completion is a verbose stat dump ending in
  // "(complete)"/"(partial)", so it misses the clean-success rule above. Keep it —
  // it's a real milestone like SBOM / SAST — and rewriteLogMessage collapses it to a
  // clean "Malicious packages scan complete" line.
  if (log.level === 'success' && /new findings \((?:complete|partial)\)\s*$/i.test(msg)) return true;
  // Infra/IaC scan resolution — the result of the "Scanning workspace for infra files…"
  // kickoff. "IaC scan complete — N findings written" ends in "written", and the skip
  // line is prose, so both miss the rules above. Keep them so the infra step shows a
  // completion like the other scanners.
  if (/^iac scan complete\b/i.test(msg)) return true;
  if (/^no infra files detected\b/i.test(msg)) return true;
  // Everything else (framework-entry counts, OSV/PURL lines, EPD passes,
  // container reachability, native bindings, composition summaries, …) is noise.
  return false;
}

/**
 * Display-time message rewrites: trim noisy specifics the worker logs but the user
 * doesn't need. Currently drops the live package count from the malicious-scan kickoff
 * line ("Scanning 1000 packages for malicious indicators…" → "Scanning packages for
 * malicious indicators…") — the exact count is churn and can read as alarming.
 */
export function rewriteLogMessage(message: string): string {
  // Collapse the verbose malicious-scan completion ("71/71 scanned …, 3 new findings
  // (complete)") to a clean milestone line matching the other scanners ("SBOM
  // generated", "SAST complete", …).
  if (/new findings \((?:complete|partial)\)\s*$/i.test(message)) {
    return 'Malicious packages scan complete';
  }
  return message.replace(
    /^Scanning\s+\d+\s+packages\s+for\s+malicious\s+indicators/i,
    'Scanning packages for malicious indicators',
  );
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
          setLogs((prev) => prev.some((l) => l.id === newLog.id) ? prev : [...prev, newLog]);
        }
      )
      .subscribe();
    return () => {
      supabase.removeChannel(channel);
    };
  }, [projectId, runId]);

  const filteredLogs = logs.filter(filterLog).map((l) => {
    if (!l.message) return l;
    const message = rewriteLogMessage(l.message);
    return message === l.message ? l : { ...l, message };
  });
  const lastLog = logs[logs.length - 1];
  const isComplete = Boolean(lastLog?.step === 'complete' && (lastLog.level === 'success' || lastLog.level === 'error'));
  const hasError = Boolean(isComplete && lastLog?.level === 'error');
  const isActive = !isComplete && logs.length > 0;

  return { logs, filteredLogs, isLoading, isComplete, hasError, isActive };
}
