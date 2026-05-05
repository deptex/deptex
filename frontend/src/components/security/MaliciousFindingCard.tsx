import { useState } from 'react';
import { Sparkles, ShieldAlert, Loader2 } from 'lucide-react';
import { api, type MaliciousFinding } from '../../lib/api';
import { Button } from '../ui/button';
import { cn } from '../../lib/utils';
import { ReachabilityBadge, type MaliciousReachabilityLevel } from './ReachabilityBadge';

interface MaliciousFindingCardProps {
  organizationId: string;
  projectId: string;
  finding: MaliciousFinding;
  canManage: boolean;
  onStatusChange?: () => void;
  /**
   * When provided, the package name renders as a clickable button that
   * fires this callback. Hosting pages typically use it to open a drawer
   * showing the package's capability tags + other metadata.
   */
  onPackageClick?: (info: {
    package_name: string;
    package_version: string | null | undefined;
    ecosystem: string | null | undefined;
    project_dependency_id: string;
  }) => void;
}

export function MaliciousFindingCard({
  organizationId,
  projectId,
  finding,
  canManage,
  onStatusChange,
  onPackageClick,
}: MaliciousFindingCardProps) {
  const [explainState, setExplainState] = useState<
    | { kind: 'idle' }
    | { kind: 'loading' }
    | { kind: 'loaded'; narrative: string; cached: boolean }
    | { kind: 'error'; message: string }
  >(finding.ai_narrative
    ? { kind: 'loaded', narrative: finding.ai_narrative, cached: true }
    : { kind: 'idle' });

  const [actionPending, setActionPending] = useState<'suppress' | 'risk' | null>(null);

  async function handleExplain() {
    setExplainState({ kind: 'loading' });
    try {
      const result = await api.maliciousFindings.explain(organizationId, projectId, finding.id);
      setExplainState({ kind: 'loaded', narrative: result.narrative, cached: result.cached });
    } catch (e: any) {
      setExplainState({ kind: 'error', message: e?.message ?? 'Explainer unavailable' });
    }
  }

  async function handleSuppress() {
    setActionPending('suppress');
    try {
      await api.maliciousFindings.updateStatus(organizationId, projectId, finding.id, {
        suppressed: !finding.suppressed,
      });
      onStatusChange?.();
    } finally {
      setActionPending(null);
    }
  }

  async function handleAcceptRisk() {
    setActionPending('risk');
    try {
      await api.maliciousFindings.updateStatus(organizationId, projectId, finding.id, {
        risk_accepted: !finding.risk_accepted,
      });
      onStatusChange?.();
    } finally {
      setActionPending(null);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className={cn(
            'inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-semibold border',
            finding.severity === 'critical' ? 'bg-red-500/15 text-red-300 border-red-500/30'
              : finding.severity === 'high' ? 'bg-red-500/10 text-red-400 border-red-500/20'
              : finding.severity === 'medium' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20'
              : 'bg-zinc-500/10 text-zinc-400 border-zinc-500/20'
          )}>
            <ShieldAlert className="h-3 w-3 mr-1" />
            {finding.severity.toUpperCase()}
          </span>
          <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-purple-500/10 text-purple-300 border border-purple-500/20">
            {finding.scanner === 'feed' ? 'Feed match' : finding.scanner === 'maintainer' ? 'Maintainer signal' : 'GuardDog'}
          </span>
          <ReachabilityBadge
            level={(finding.reachability_level ?? null) as MaliciousReachabilityLevel | null}
            details={finding.reachability_details}
          />
          {finding.package_name && (
            onPackageClick ? (
              <button
                type="button"
                onClick={() =>
                  onPackageClick({
                    package_name: finding.package_name!,
                    package_version: finding.package_version,
                    ecosystem: finding.ecosystem,
                    project_dependency_id: finding.project_dependency_id,
                  })
                }
                className="text-[11px] text-foreground-secondary font-mono hover:text-foreground hover:underline underline-offset-2 transition-colors"
              >
                {finding.package_name}@{finding.package_version} ({finding.ecosystem})
              </button>
            ) : (
              <span className="text-[11px] text-foreground-secondary font-mono">
                {finding.package_name}@{finding.package_version} ({finding.ecosystem})
              </span>
            )
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1.5"
            disabled={actionPending === 'suppress' || !canManage}
            title={canManage ? undefined : 'Requires project-manage permission.'}
            onClick={handleSuppress}
          >
            {actionPending === 'suppress' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {finding.suppressed ? 'Unsuppress' : 'Suppress'}
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
            className="h-7 text-xs gap-1.5"
            disabled={actionPending === 'risk' || !canManage}
            title={canManage ? undefined : 'Requires project-manage permission.'}
            onClick={handleAcceptRisk}
          >
            {actionPending === 'risk' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : null}
            {finding.risk_accepted ? 'Cancel risk acceptance' : 'Accept risk'}
          </Button>
        </div>
      </div>

      {finding.message && (
        <div className="text-xs text-foreground-secondary leading-relaxed">
          {finding.message}
        </div>
      )}

      {finding.evidence && finding.evidence.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-3 py-1.5 bg-[#0a0a0b] border-b border-zinc-800/50">
            <span className="text-[11px] text-foreground font-mono">
              {finding.evidence[0].file_path}:{finding.evidence[0].lines[0]}
            </span>
          </div>
          <pre className="bg-[#0a0a0b] px-3 py-2 text-[11px] text-zinc-300 overflow-auto whitespace-pre-wrap">
            {finding.evidence[0].snippet}
          </pre>
        </div>
      )}

      <div className="rounded-md border border-border bg-background-card p-3 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="text-[10px] uppercase tracking-wider font-semibold text-foreground-secondary">
            Why this is malicious
          </div>
          {explainState.kind === 'loaded' && explainState.cached && (
            <span className="text-[10px] text-foreground-muted">
              Cached
              {finding.ai_narrative_cached_at ? ` • ${new Date(finding.ai_narrative_cached_at).toLocaleDateString()}` : null}
            </span>
          )}
        </div>
        {explainState.kind === 'idle' && (
          <Button type="button" variant="outline" size="sm" className="h-7 text-xs gap-1.5" onClick={handleExplain}>
            <Sparkles className="h-3.5 w-3.5" />
            Explain this finding
          </Button>
        )}
        {explainState.kind === 'loading' && (
          <div className="text-xs text-foreground-secondary inline-flex items-center gap-1.5">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Generating explanation...
          </div>
        )}
        {explainState.kind === 'loaded' && (
          <div className="text-xs text-foreground-secondary leading-relaxed whitespace-pre-wrap">
            {explainState.narrative}
          </div>
        )}
        {explainState.kind === 'error' && (
          <div className="text-xs text-red-400">
            Explainer temporarily unavailable — try again later.
          </div>
        )}
      </div>
    </div>
  );
}
