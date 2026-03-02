import { memo, useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert, Shield, FileCode, Key, ChevronDown, ChevronRight,
  AlertTriangle, Sparkles, CheckCircle, RotateCcw
} from 'lucide-react';
import { cn } from '../../lib/utils';
import { api, SemgrepFinding, SecretFinding, ProjectVulnerability } from '../../lib/api';

interface ProjectSecurityContentProps {
  organizationId: string;
  projectId: string;
  canManage: boolean;
  onNavigateToVuln?: (osvId: string) => void;
}

function getSeverityBadgeClass(severity: string): string {
  switch (severity?.toUpperCase()) {
    case 'ERROR':
    case 'CRITICAL': return 'bg-red-500/15 text-red-400';
    case 'WARNING':
    case 'HIGH': return 'bg-orange-500/15 text-orange-400';
    case 'MEDIUM':
    case 'INFO': return 'bg-yellow-500/15 text-yellow-400';
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

function ProjectSecurityContent({ organizationId, projectId, canManage, onNavigateToVuln }: ProjectSecurityContentProps) {
  const [vulns, setVulns] = useState<ProjectVulnerability[]>([]);
  const [semgrepFindings, setSemgrepFindings] = useState<SemgrepFinding[]>([]);
  const [secretFindings, setSecretFindings] = useState<SecretFinding[]>([]);
  const [semgrepTotal, setSemgrepTotal] = useState(0);
  const [secretTotal, setSecretTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [secretPermissionDenied, setSecretPermissionDenied] = useState(false);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const [vulnData, semgrepData] = await Promise.all([
        api.getProjectVulnerabilities(organizationId, projectId),
        api.getProjectSemgrepFindings(organizationId, projectId, 1, 10),
      ]);
      setVulns(vulnData);
      setSemgrepFindings(semgrepData.data);
      setSemgrepTotal(semgrepData.total);

      try {
        const secretData = await api.getProjectSecretFindings(organizationId, projectId, 1, 10);
        setSecretFindings(secretData.data);
        setSecretTotal(secretData.total);
      } catch (e: any) {
        if (e?.message?.includes('403') || e?.status === 403) {
          setSecretPermissionDenied(true);
        }
      }
    } catch (e) {
      console.error('Failed to load project security data:', e);
    } finally {
      setLoading(false);
    }
  }, [organizationId, projectId]);

  useEffect(() => { loadData(); }, [loadData]);

  if (loading) {
    return (
      <div className="space-y-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-20 bg-zinc-800/50 rounded-lg animate-pulse" />
        ))}
      </div>
    );
  }

  const criticalCount = vulns.filter(v => v.severity === 'critical').length;
  const highCount = vulns.filter(v => v.severity === 'high').length;
  const mediumCount = vulns.filter(v => v.severity === 'medium').length;
  const lowCount = vulns.filter(v => v.severity === 'low').length;
  const reachableCount = vulns.filter(v => v.is_reachable).length;
  const verifiedSecrets = secretFindings.filter(s => s.is_verified).length;

  const urgentDepscore = vulns.filter(v => (v.depscore ?? 0) >= 75).length;
  const moderateDepscore = vulns.filter(v => (v.depscore ?? 0) >= 40 && (v.depscore ?? 0) < 75).length;
  const lowDepscore = vulns.filter(v => (v.depscore ?? 0) < 40).length;

  return (
    <div className="space-y-4">
      {/* Vulnerability Summary */}
      <div className="border border-border rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <ShieldAlert className="h-4 w-4 text-zinc-400" />
          <span className="text-sm font-medium text-foreground">Vulnerability Summary</span>
        </div>
        <div className="grid grid-cols-4 gap-3">
          <div className="text-center">
            <div className="text-lg font-semibold text-red-400">{criticalCount}</div>
            <div className="text-[10px] text-zinc-500 uppercase">Critical</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-orange-400">{highCount}</div>
            <div className="text-[10px] text-zinc-500 uppercase">High</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-yellow-400">{mediumCount}</div>
            <div className="text-[10px] text-zinc-500 uppercase">Medium</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-zinc-400">{lowCount}</div>
            <div className="text-[10px] text-zinc-500 uppercase">Low</div>
          </div>
        </div>
        <div className="mt-3 pt-3 border-t border-border flex items-center justify-between">
          <span className="text-xs text-zinc-400">Total: {vulns.length}</span>
          <span className="text-xs text-zinc-400">{reachableCount} reachable</span>
        </div>
      </div>

      {/* Depscore Distribution */}
      <div className="border border-border rounded-lg p-4">
        <div className="flex items-center gap-2 mb-3">
          <Shield className="h-4 w-4 text-zinc-400" />
          <span className="text-sm font-medium text-foreground">Depscore Distribution</span>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center">
            <div className="text-lg font-semibold text-red-400">{urgentDepscore}</div>
            <div className="text-[10px] text-zinc-500">75-100 urgent</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-amber-400">{moderateDepscore}</div>
            <div className="text-[10px] text-zinc-500">40-74 moderate</div>
          </div>
          <div className="text-center">
            <div className="text-lg font-semibold text-zinc-400">{lowDepscore}</div>
            <div className="text-[10px] text-zinc-500">0-39 low</div>
          </div>
        </div>
      </div>

      {/* Code Issues (Semgrep) */}
      <CollapsibleSection
        title="Code Issues (Semgrep)"
        icon={FileCode}
        defaultOpen={semgrepTotal > 0}
        badge={
          semgrepTotal > 0 ? (
            <span className={cn(
              'px-1.5 py-0.5 rounded text-[10px]',
              semgrepFindings.some(f => f.severity === 'ERROR') ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700 text-zinc-400'
            )}>
              {semgrepTotal}
            </span>
          ) : undefined
        }
      >
        <div className="pt-3 space-y-2">
          {semgrepFindings.length === 0 && (
            <div className="text-xs text-zinc-500 flex items-center gap-1">
              <CheckCircle className="h-3 w-3" /> No code issues found
            </div>
          )}
          {semgrepFindings.map((f) => (
            <div key={f.id} className="border border-border rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn('px-1.5 py-0.5 rounded text-[10px]', getSeverityBadgeClass(f.severity))}>
                  {f.severity}
                </span>
                <span className="text-xs text-zinc-500">{f.category}</span>
              </div>
              <div className="text-xs text-zinc-300 font-mono truncate">{f.file_path}:{f.start_line}</div>
              {f.message && (
                <div className="mt-1 text-xs text-zinc-400 line-clamp-2">{f.message}</div>
              )}
              <button
                disabled
                className="mt-1 text-[10px] text-zinc-500 flex items-center gap-0.5 cursor-not-allowed"
                title="Configure AI in Organization Settings"
              >
                <Sparkles className="h-2.5 w-2.5" /> Ask Aegis
              </button>
            </div>
          ))}
          {semgrepTotal > semgrepFindings.length && (
            <div className="text-xs text-zinc-500 text-center pt-1">
              +{semgrepTotal - semgrepFindings.length} more findings
            </div>
          )}
        </div>
      </CollapsibleSection>

      {/* Exposed Secrets (TruffleHog) */}
      <CollapsibleSection
        title="Exposed Secrets"
        icon={Key}
        defaultOpen={secretTotal > 0}
        badge={
          secretTotal > 0 ? (
            <span className={cn(
              'px-1.5 py-0.5 rounded text-[10px]',
              verifiedSecrets > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700 text-zinc-400'
            )}>
              {secretTotal}
            </span>
          ) : undefined
        }
      >
        <div className="pt-3 space-y-2">
          {secretPermissionDenied && (
            <div className="text-xs text-zinc-500 flex items-center gap-1">
              <AlertTriangle className="h-3 w-3" /> Requires project management permission
            </div>
          )}
          {!secretPermissionDenied && secretFindings.length === 0 && (
            <div className="text-xs text-zinc-500 flex items-center gap-1">
              <CheckCircle className="h-3 w-3" /> No exposed secrets found
            </div>
          )}
          {secretFindings.map((s) => (
            <div key={s.id} className="border border-border rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className={cn(
                  'px-1.5 py-0.5 rounded text-[10px]',
                  s.is_verified ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700 text-zinc-400'
                )}>
                  {s.detector_type}
                </span>
                {s.is_verified && (
                  <span className="px-1 py-0.5 rounded text-[10px] bg-red-500/15 text-red-400">Active</span>
                )}
              </div>
              <div className="text-xs text-zinc-300 font-mono truncate">{s.file_path}:{s.start_line ?? '?'}</div>
              {!s.is_current && (
                <div className="mt-2 flex items-center gap-1 text-[10px] text-amber-400">
                  <RotateCcw className="h-2.5 w-2.5" />
                  This credential was exposed in a previous commit. Rotate immediately.
                </div>
              )}
              {s.is_current && (
                <button
                  disabled
                  className="mt-1 text-[10px] text-zinc-500 flex items-center gap-0.5 cursor-not-allowed"
                  title="Configure AI in Organization Settings"
                >
                  <Sparkles className="h-2.5 w-2.5" /> Ask Aegis
                </button>
              )}
            </div>
          ))}
        </div>
      </CollapsibleSection>

      {/* Priority Actions */}
      {(criticalCount > 0 || verifiedSecrets > 0 || semgrepFindings.some(f => f.severity === 'ERROR')) && (
        <div className="border border-border rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            <span className="text-sm font-medium text-foreground">Priority Actions</span>
          </div>
          <div className="space-y-2">
            {criticalCount > 0 && (
              <div className="text-xs text-zinc-300 flex items-center gap-2 cursor-pointer hover:text-primary transition-colors">
                <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                Fix {criticalCount} critical reachable vulnerabilit{criticalCount !== 1 ? 'ies' : 'y'}
              </div>
            )}
            {verifiedSecrets > 0 && (
              <div className="text-xs text-zinc-300 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                Rotate {verifiedSecrets} verified exposed secret{verifiedSecrets !== 1 ? 's' : ''}
              </div>
            )}
            {semgrepFindings.some(f => f.severity === 'ERROR') && (
              <div className="text-xs text-zinc-300 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-orange-500" />
                Address {semgrepFindings.filter(f => f.severity === 'ERROR').length} high-severity code issues
              </div>
            )}
          </div>
        </div>
      )}

      {/* Actions */}
      <div className="pt-2">
        <button
          disabled
          className="w-full py-2 rounded-lg text-xs font-medium bg-zinc-800 text-zinc-500 cursor-not-allowed flex items-center justify-center gap-2"
          title="Configure AI in Organization Settings"
        >
          <Sparkles className="h-4 w-4" /> Ask Aegis
        </button>
      </div>
    </div>
  );
}

export default memo(ProjectSecurityContent);
