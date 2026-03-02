import React, { useState, useEffect } from 'react';
import {
  Sparkles,
  Loader2,
  CheckCircle2,
  XCircle,
  ExternalLink,
  X,
  Clock,
  GitPullRequest,
} from 'lucide-react';
import { supabase } from '../../lib/supabase';
import { api, FixJob } from '../../lib/api';

interface FixProgressCardProps {
  fix: FixJob;
  orgId: string;
  projectId: string;
  onCancel?: () => void;
}

const STEPS = ['Cloning', 'Analyzing', 'Fixing', 'Validating', 'Creating PR'] as const;

function getStepIndex(logs: LogEntry[]): number {
  const lastStep = [...logs].reverse().find(l => l.step)?.step;
  if (!lastStep) return 0;
  const stepMap: Record<string, number> = {
    init: 0, clone: 0, aider: 2, validate: 3, push: 4, pr: 4, complete: 4,
  };
  return stepMap[lastStep] ?? 1;
}

interface LogEntry {
  id: string;
  step: string;
  level: string;
  message: string;
  created_at: string;
}

export function FixProgressCard({ fix, orgId, projectId, onCancel }: FixProgressCardProps) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [showLogs, setShowLogs] = useState(false);
  const [cancelling, setCancelling] = useState(false);

  const isActive = fix.status === 'queued' || fix.status === 'running';
  const isCompleted = fix.status === 'completed';
  const isFailed = fix.status === 'failed';

  useEffect(() => {
    if (!isActive || !fix.run_id) return;

    supabase
      .from('extraction_logs')
      .select('id, step, level, message, created_at')
      .eq('run_id', fix.run_id)
      .order('created_at', { ascending: true })
      .then(({ data }) => { if (data) setLogs(data as LogEntry[]); });

    const channel = supabase
      .channel(`fix-logs:${fix.run_id}`)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'extraction_logs',
          filter: `run_id=eq.${fix.run_id}`,
        },
        (payload) => {
          const row = payload.new as LogEntry;
          setLogs(prev => [...prev, row]);
        },
      )
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [isActive, fix.run_id]);

  const handleCancel = async () => {
    setCancelling(true);
    try {
      await api.cancelFix(orgId, projectId, fix.id);
      onCancel?.();
    } catch { /* silent */ }
    setCancelling(false);
  };

  const currentStep = getStepIndex(logs);

  if (isCompleted && fix.pr_url) {
    return (
      <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-3 space-y-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="h-4 w-4 text-green-500" />
            <span className="text-sm font-medium text-green-400">Fix PR Created</span>
          </div>
          <a
            href={fix.pr_url}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1 text-xs text-green-500 hover:text-green-400 transition-colors"
          >
            PR #{fix.pr_number} <ExternalLink className="h-3 w-3" />
          </a>
        </div>
        <p className="text-xs text-foreground-secondary">
          Strategy: <span className="text-foreground">{formatStrategy(fix.strategy)}</span>
        </p>
      </div>
    );
  }

  if (isFailed) {
    return (
      <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 space-y-2">
        <div className="flex items-center gap-2">
          <XCircle className="h-4 w-4 text-amber-500" />
          <span className="text-sm font-medium text-amber-400">Fix Failed</span>
        </div>
        {fix.error_message && (
          <p className="text-xs text-foreground-secondary line-clamp-2">{fix.error_message}</p>
        )}
      </div>
    );
  }

  if (!isActive) return null;

  return (
    <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-3 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {fix.status === 'queued' ? (
            <Clock className="h-4 w-4 text-foreground-muted" />
          ) : (
            <Loader2 className="h-4 w-4 text-green-500 animate-spin" />
          )}
          <span className="text-sm font-medium text-foreground">
            {fix.status === 'queued' ? 'Fix Queued' : 'Fix in Progress'}
          </span>
        </div>
        <button
          onClick={handleCancel}
          disabled={cancelling}
          className="text-xs text-foreground-muted hover:text-destructive transition-colors disabled:opacity-50"
        >
          {cancelling ? <Loader2 className="h-3 w-3 animate-spin" /> : <X className="h-3.5 w-3.5" />}
        </button>
      </div>

      {fix.status === 'running' && (
        <div className="flex items-center gap-1">
          {STEPS.map((step, i) => (
            <div key={step} className="flex items-center gap-1 flex-1">
              <div
                className={`h-1 flex-1 rounded-full transition-colors ${
                  i <= currentStep ? 'bg-green-500' : 'bg-border'
                }`}
              />
            </div>
          ))}
        </div>
      )}

      {fix.status === 'running' && (
        <p className="text-xs text-foreground-secondary">{STEPS[currentStep] || 'Processing'}...</p>
      )}

      {logs.length > 0 && (
        <button
          onClick={() => setShowLogs(!showLogs)}
          className="text-xs text-foreground-muted hover:text-foreground-secondary transition-colors"
        >
          {showLogs ? 'Hide logs' : `View logs (${logs.length})`}
        </button>
      )}

      {showLogs && (
        <div className="max-h-40 overflow-y-auto rounded bg-background-card p-2 font-mono text-[10px] space-y-0.5">
          {logs.map(log => (
            <div key={log.id} className={`${getLogColor(log.level)}`}>
              [{log.step}] {log.message}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatStrategy(strategy: string): string {
  const map: Record<string, string> = {
    bump_version: 'Version Bump',
    code_patch: 'Code Patch',
    add_wrapper: 'Safe Wrapper',
    pin_transitive: 'Pin Transitive',
    remove_unused: 'Remove Unused',
    fix_semgrep: 'Semgrep Fix',
    remediate_secret: 'Secret Remediation',
  };
  return map[strategy] ?? strategy;
}

function getLogColor(level: string): string {
  switch (level) {
    case 'error': return 'text-destructive';
    case 'warning': return 'text-yellow-500';
    case 'success': return 'text-green-500';
    default: return 'text-foreground-muted';
  }
}

// ---------- "Fix with AI" button ----------

interface FixWithAIButtonProps {
  fix: FixJob | null;
  recentFixes: FixJob[];
  canStartNewFix: boolean;
  blockReason?: string;
  hasByokProvider: boolean;
  hasAegisPermission: boolean;
  onTriggerFix: () => void;
}

export function FixWithAIButton({
  fix,
  recentFixes,
  canStartNewFix,
  blockReason,
  hasByokProvider,
  hasAegisPermission,
  onTriggerFix,
}: FixWithAIButtonProps) {
  if (!hasAegisPermission) return null;

  if (!hasByokProvider) {
    return (
      <button
        disabled
        className="w-full py-2 rounded-lg text-sm font-medium bg-zinc-800 text-zinc-500 cursor-not-allowed flex items-center justify-center gap-2"
        title="Configure AI in Organization Settings"
      >
        <Sparkles className="h-4 w-4" /> Fix with AI
      </button>
    );
  }

  if (fix?.status === 'queued') {
    return (
      <button
        disabled
        className="w-full py-2 rounded-lg text-sm font-medium bg-zinc-800 text-zinc-400 cursor-not-allowed flex items-center justify-center gap-2"
      >
        <Loader2 className="h-4 w-4 animate-spin" /> Fix Queued...
      </button>
    );
  }

  if (fix?.status === 'running') {
    return (
      <button
        disabled
        className="w-full py-2 rounded-lg text-sm font-medium bg-green-500/10 text-green-400 border border-green-500/20 cursor-not-allowed flex items-center justify-center gap-2 animate-pulse"
      >
        <Loader2 className="h-4 w-4 animate-spin" /> Fix in Progress
      </button>
    );
  }

  if (fix?.status === 'completed' && fix.pr_url) {
    return (
      <div className="space-y-1.5">
        <a
          href={fix.pr_url}
          target="_blank"
          rel="noopener noreferrer"
          className="w-full py-2 rounded-lg text-sm font-medium bg-green-500/10 text-green-400 border border-green-500/20 flex items-center justify-center gap-2 hover:bg-green-500/20 transition-colors"
        >
          <GitPullRequest className="h-4 w-4" /> Fix PR #{fix.pr_number}
          <ExternalLink className="h-3 w-3" />
        </a>
        <button
          onClick={onTriggerFix}
          className="w-full py-1.5 text-xs text-foreground-muted hover:text-foreground-secondary transition-colors"
        >
          Try a different approach
        </button>
      </div>
    );
  }

  const recentFailures = recentFixes.filter(f => f.status === 'failed');

  if (!canStartNewFix && blockReason) {
    return (
      <button
        disabled
        className="w-full py-2 rounded-lg text-sm font-medium bg-zinc-800 text-zinc-500 cursor-not-allowed flex items-center justify-center gap-2"
        title={blockReason}
      >
        <Sparkles className="h-4 w-4" /> Fix with AI
      </button>
    );
  }

  return (
    <div className="space-y-1.5">
      <button
        onClick={onTriggerFix}
        className="w-full py-2 rounded-lg text-sm font-medium bg-green-600 hover:bg-green-500 text-white flex items-center justify-center gap-2 transition-colors"
      >
        <Sparkles className="h-4 w-4" /> Fix with AI
      </button>
      {recentFailures.length > 0 && (
        <p className="text-xs text-amber-400 text-center">
          Previous attempt failed. Try a different approach?
        </p>
      )}
    </div>
  );
}
