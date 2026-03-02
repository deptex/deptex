import { memo, useState, useEffect, useCallback } from 'react';
import {
  Package, ShieldAlert, Shield, FileCode, Eye, AlertTriangle, ChevronDown,
  ChevronRight, ExternalLink, CheckCircle, Ban, Activity
} from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, DependencySecuritySummary, VersionCandidate } from '../../lib/api';

interface DependencySecurityContentProps {
  organizationId: string;
  projectId: string;
  depId: string;
  onNavigateToVuln?: (osvId: string) => void;
  onNavigateToFullDetail?: () => void;
}

function getDepscoreBadgeClass(score: number | null | undefined): string {
  if (score == null) return 'bg-zinc-800 text-zinc-400';
  if (score >= 75) return 'bg-red-500/15 text-red-400 border border-red-500/30';
  if (score >= 40) return 'bg-amber-500/15 text-amber-400 border border-amber-500/30';
  return 'bg-zinc-700/50 text-zinc-400 border border-zinc-600/30';
}

function getSeverityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-500/15 text-red-400';
    case 'high': return 'bg-orange-500/15 text-orange-400';
    case 'medium': return 'bg-yellow-500/15 text-yellow-400';
    case 'low': return 'bg-zinc-700/50 text-zinc-400';
    default: return 'bg-zinc-700/50 text-zinc-400';
  }
}

function CollapsibleSection({ title, icon: Icon, defaultOpen = false, badge, children }: {
  title: string;
  icon?: any;
  defaultOpen?: boolean;
  badge?: React.ReactNode;
  children: React.ReactNode;
}) {
  const [isOpen, setIsOpen] = useState(defaultOpen);
  return (
    <div className="border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setIsOpen(!isOpen)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-zinc-800/50 transition-colors"
      >
        <div className="flex items-center gap-2">
          {Icon && <Icon className="h-4 w-4 text-zinc-400" />}
          <span className="text-sm font-medium text-foreground">{title}</span>
          {badge}
        </div>
        {isOpen ? <ChevronDown className="h-4 w-4 text-zinc-500" /> : <ChevronRight className="h-4 w-4 text-zinc-500" />}
      </button>
      {isOpen && <div className="px-4 pb-4 border-t border-border">{children}</div>}
    </div>
  );
}

function DependencySecurityContent({ organizationId, projectId, depId, onNavigateToVuln, onNavigateToFullDetail }: DependencySecurityContentProps) {
  const [data, setData] = useState<DependencySecuritySummary | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const result = await api.getDependencySecuritySummary(organizationId, projectId, depId);
      setData(result);
    } catch (e) {
      console.error('Failed to load dependency security summary:', e);
    } finally {
      setLoading(false);
    }
  }, [organizationId, projectId, depId]);

  useEffect(() => { loadData(); }, [loadData]);

  if (loading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-16 bg-zinc-800/50 rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  if (!data) {
    return <div className="text-sm text-zinc-400">Dependency not found.</div>;
  }

  const { dependency: dep, files, vulnerabilities: vulns, version_candidates: candidates, watchtower } = data;
  const activeVulns = vulns.filter(v => !v.suppressed && !v.risk_accepted);
  const isZombie = dep.files_importing_count === 0;

  return (
    <div className="space-y-4">
      {/* Header badges */}
      <div className="flex items-center gap-2 flex-wrap">
        <span className="px-2 py-0.5 rounded text-xs font-mono bg-zinc-800 text-zinc-300">
          {dep.version}
        </span>
        {dep.license && (
          <span className="px-2 py-0.5 rounded text-xs bg-zinc-800 text-zinc-400">{dep.license}</span>
        )}
        <span className={cn('px-2 py-0.5 rounded text-xs', dep.is_direct ? 'bg-blue-500/15 text-blue-400' : 'bg-zinc-700 text-zinc-400')}>
          {dep.is_direct ? 'direct' : 'transitive'}
        </span>
        {isZombie && (
          <span className="px-2 py-0.5 rounded text-xs bg-amber-500/15 text-amber-400">
            Not imported in your code
          </span>
        )}
      </div>

      {/* Remove suggestion for zombie deps */}
      {isZombie && activeVulns.length > 0 && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-amber-500/10 border border-amber-500/20">
          <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0 mt-0.5" />
          <span className="text-xs text-amber-300">
            This package is not used in your code. Remove it to eliminate {activeVulns.length} vulnerabilit{activeVulns.length !== 1 ? 'ies' : 'y'}.
          </span>
        </div>
      )}

      {/* Usage */}
      <CollapsibleSection title="Usage in Your Project" icon={FileCode} defaultOpen>
        <div className="pt-3 space-y-2">
          <div className="text-xs text-zinc-400">
            Imported in <span className="text-foreground font-medium">{dep.files_importing_count}</span> file{dep.files_importing_count !== 1 ? 's' : ''}
          </div>
          {files.length > 0 && (
            <div className="space-y-1 mt-2">
              {files.slice(0, 8).map((f, i) => (
                <div key={i} className="text-xs text-zinc-500 font-mono truncate">{f}</div>
              ))}
              {files.length > 8 && (
                <div className="text-xs text-zinc-500">+{files.length - 8} more files</div>
              )}
            </div>
          )}
        </div>
      </CollapsibleSection>

      {/* Current Vulnerabilities */}
      <CollapsibleSection
        title="Current Vulnerabilities"
        icon={ShieldAlert}
        defaultOpen
        badge={
          activeVulns.length > 0 ? (
            <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/15 text-red-400">{activeVulns.length}</span>
          ) : undefined
        }
      >
        <div className="pt-3 space-y-2">
          {activeVulns.length === 0 && (
            <div className="text-xs text-zinc-500 flex items-center gap-1">
              <Shield className="h-3 w-3" /> No active vulnerabilities
            </div>
          )}
          {activeVulns.map((v) => (
            <button
              key={v.osv_id}
              onClick={() => onNavigateToVuln?.(v.osv_id)}
              className="w-full flex items-center justify-between px-3 py-2 rounded-lg border border-border hover:bg-zinc-800/50 transition-colors text-left"
            >
              <div className="flex items-center gap-2">
                {v.depscore != null && (
                  <span className={cn('px-1.5 py-0.5 rounded text-[10px] font-mono', getDepscoreBadgeClass(v.depscore))}>
                    {v.depscore}
                  </span>
                )}
                <span className={cn('px-1.5 py-0.5 rounded text-[10px]', getSeverityBadgeClass(v.severity))}>
                  {v.severity}
                </span>
                <span className="text-xs font-mono text-zinc-300">{v.osv_id}</span>
              </div>
              <div className="flex items-center gap-1">
                {v.fixed_versions && v.fixed_versions.length > 0 && (
                  <CheckCircle className="h-3 w-3 text-green-400" />
                )}
                {v.cisa_kev && <span className="text-[10px] text-red-400">KEV</span>}
              </div>
            </button>
          ))}
        </div>
      </CollapsibleSection>

      {/* Recommended Versions */}
      {candidates.length > 0 && (
        <CollapsibleSection title="Recommended Versions" icon={Package}>
          <div className="pt-3 space-y-2">
            {candidates.map((c: VersionCandidate) => (
              <div key={c.id} className="border border-border rounded-lg p-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-zinc-500 capitalize">{c.candidate_type.replace(/_/g, ' ')}</span>
                    <span className="text-sm font-mono text-foreground">{c.candidate_version}</span>
                    {c.is_major_bump && (
                      <span className="px-1 py-0.5 rounded text-[10px] bg-amber-500/15 text-amber-400">major</span>
                    )}
                  </div>
                  {c.is_org_banned && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-red-500/15 text-red-400 flex items-center gap-0.5">
                      <Ban className="h-2.5 w-2.5" /> Banned
                    </span>
                  )}
                </div>
                <div className="mt-1 text-xs text-zinc-400">
                  Fixes {c.fixes_cve_count}/{c.total_current_cves} CVEs
                  {c.known_new_cves > 0 ? ` · ${c.known_new_cves} new CVEs` : ' · 0 new CVEs'}
                </div>
              </div>
            ))}
          </div>
        </CollapsibleSection>
      )}

      {/* Watchtower Signals */}
      {watchtower && (
        <CollapsibleSection title="Watchtower Signals" icon={Activity}>
          <div className="pt-3 space-y-2">
            <div className="flex items-center gap-2">
              <span className={cn(
                'h-2 w-2 rounded-full',
                watchtower.status === 'ready' ? 'bg-green-500' : watchtower.status === 'analyzing' ? 'bg-amber-500' : 'bg-zinc-500'
              )} />
              <span className="text-xs text-zinc-300 capitalize">{watchtower.status}</span>
            </div>
          </div>
        </CollapsibleSection>
      )}

      {/* Actions */}
      <div className="pt-2">
        <button
          onClick={onNavigateToFullDetail}
          className="w-full py-2 rounded-lg text-xs font-medium bg-zinc-800 text-zinc-300 hover:bg-zinc-700 transition-colors flex items-center justify-center gap-2"
        >
          <ExternalLink className="h-3 w-3" /> View Full Detail
        </button>
      </div>
    </div>
  );
}

export default memo(DependencySecurityContent);
