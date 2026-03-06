import { useState, useEffect, useMemo, useCallback, useRef } from 'react';
import { useParams } from 'react-router-dom';
import {
  TowerControl,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Loader2,
  Check,
  X,
  Minus,
  RotateCcw,
  ChevronDown,
  ChevronRight,
  Search,
  BookOpen,
  Lock,
  Fingerprint,
  FileCode,
  GitCommit,
} from 'lucide-react';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { api } from '../../lib/api';
import { cn } from '../../lib/utils';

interface WatchtowerStats {
  enabled: boolean;
  enabled_at?: string;
  total_direct: number;
  analyzed: number;
  alerts: number;
  blocked: number;
  errored: number;
}

interface WatchtowerPackage {
  watchlist_id: string | null;
  dependency_id: string;
  name: string;
  version: string;
  registry_integrity_status: string | null;
  install_scripts_status: string | null;
  entropy_analysis_status: string | null;
  max_anomaly_score: number | null;
  latest_version: string | null;
  next_version_status: string | null;
  quarantine_next_release: boolean;
  quarantine_until: string | null;
  import_count: number;
  analysis_status: string;
  analysis_error: string | null;
  ecosystem: string;
}

function StatusDot({ status, ecosystem }: { status: string | null; ecosystem?: string }) {
  if (status === 'pass') return <Check className="h-4 w-4 text-green-500" />;
  if (status === 'fail') return <X className="h-4 w-4 text-red-500" />;
  if (status === 'warning') return <AlertTriangle className="h-4 w-4 text-yellow-500" />;
  if (status === null && ecosystem && ecosystem !== 'npm') return <Minus className="h-3.5 w-3.5 text-foreground-secondary" />;
  return <Minus className="h-3.5 w-3.5 text-foreground-secondary" />;
}

function NextVersionBadge({ status, version }: { status: string | null; version: string | null }) {
  if (!status) return <span className="text-foreground-secondary">—</span>;
  const v = version ? `v${version}` : '';
  switch (status) {
    case 'ready':
      return <span className="inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-400">{v} Ready</span>;
    case 'blocked':
      return <span className="inline-flex items-center gap-1 rounded-full bg-red-500/10 px-2 py-0.5 text-xs font-medium text-red-400">{v} Blocked</span>;
    case 'quarantined':
      return <span className="inline-flex items-center gap-1 rounded-full bg-yellow-500/10 px-2 py-0.5 text-xs font-medium text-yellow-400">{v} Quarantined</span>;
    case 'latest':
      return <span className="inline-flex items-center gap-1 rounded-full bg-zinc-500/10 px-2 py-0.5 text-xs font-medium text-foreground-secondary">Latest</span>;
    default:
      return <span className="text-foreground-secondary">—</span>;
  }
}

function AnomalyScore({ score }: { score: number | null }) {
  if (score == null) return <span className="text-foreground-secondary">—</span>;
  const color = score >= 60 ? 'text-red-400' : score >= 30 ? 'text-yellow-400' : 'text-green-400';
  return <span className={cn('text-sm font-mono tabular-nums', color)}>{score}</span>;
}

/** Skeleton matching Watchtower enabled layout: header, toolbar, table. */
function WatchtowerSkeleton() {
  const pulse = 'bg-muted animate-pulse rounded';
  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={cn('h-6 w-32', pulse)} />
            <div className={cn('h-5 w-20', pulse)} />
          </div>
          <div className={cn('h-8 w-16', pulse)} />
        </div>
        <div className="flex items-center justify-between gap-4">
          <div className={cn('h-9 w-80', pulse)} />
          <div className="flex gap-2">
            {[1, 2, 3, 4].map((i) => (
              <div key={i} className={cn('h-8 w-16', pulse)} />
            ))}
          </div>
        </div>
        <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                {['Package', 'Version', 'Registry', 'Scripts', 'Entropy', 'Anomaly', 'Next version'].map((label) => (
                  <th key={label} className="px-4 py-3 text-left">
                    <div className={cn('h-3 w-16', pulse)} />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {Array.from({ length: 8 }).map((_, i) => (
                <tr key={i}>
                  <td className="px-4 py-3"><div className={cn('h-4 w-36', pulse)} /></td>
                  <td className="px-4 py-3"><div className={cn('h-4 w-16', pulse)} /></td>
                  <td className="px-4 py-3"><div className={cn('h-4 w-8', pulse)} /></td>
                  <td className="px-4 py-3"><div className={cn('h-4 w-8', pulse)} /></td>
                  <td className="px-4 py-3"><div className={cn('h-4 w-8', pulse)} /></td>
                  <td className="px-4 py-3"><div className={cn('h-4 w-8', pulse)} /></td>
                  <td className="px-4 py-3"><div className={cn('h-4 w-20', pulse)} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default function ProjectWatchtowerPage() {
  const { orgId, projectId } = useParams<{ orgId: string; projectId: string }>();
  const [stats, setStats] = useState<WatchtowerStats | null>(null);
  const [packages, setPackages] = useState<WatchtowerPackage[]>([]);
  const [totalDirect, setTotalDirect] = useState(0);
  const [loading, setLoading] = useState(true);
  const [enabling, setEnabling] = useState(false);
  const [filter, setFilter] = useState<'all' | 'alerts' | 'blocked' | 'safe'>('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  const realtime = useRealtimeStatus(orgId, projectId);
  const isExtractionOngoing = !realtime.isLoading && realtime.status !== 'ready';

  const fetchData = useCallback(async () => {
    if (!orgId || !projectId) return;
    try {
      const [statsRes, pkgsRes] = await Promise.all([
        api.authenticatedGet<WatchtowerStats>(`/api/organizations/${orgId}/projects/${projectId}/watchtower/stats`),
        api.authenticatedGet<{ packages: WatchtowerPackage[]; total_direct_deps: number }>(`/api/organizations/${orgId}/projects/${projectId}/watchtower/packages`).catch(() => ({ packages: [], total_direct_deps: 0 })),
      ]);
      setStats(statsRes);
      setPackages(pkgsRes.packages || []);
      setTotalDirect(pkgsRes.total_direct_deps || 0);
    } catch {
      setStats({ enabled: false, total_direct: 0, analyzed: 0, alerts: 0, blocked: 0, errored: 0 });
    } finally {
      setLoading(false);
    }
  }, [orgId, projectId]);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleToggle = async (enabled: boolean) => {
    if (!orgId || !projectId) return;
    setEnabling(true);
    try {
      await api.authenticatedPost(`/api/organizations/${orgId}/projects/${projectId}/watchtower/toggle`, { enabled });
      await fetchData();
    } catch (e: any) {
      console.error('Toggle failed:', e);
    } finally {
      setEnabling(false);
    }
  };

  const handleReanalyze = async (watchlistId: string) => {
    if (!orgId || !projectId) return;
    try {
      await api.authenticatedPost(`/api/organizations/${orgId}/projects/${projectId}/watchtower/packages/${watchlistId}/reanalyze`, {});
      await fetchData();
    } catch (e: any) {
      console.error('Reanalyze failed:', e);
    }
  };

  // One row per (dependency_id, version); merge import_count for duplicates from API
  const deduplicatedPackages = useMemo(() => {
    const byKey = new Map<string, WatchtowerPackage>();
    for (const p of packages) {
      const key = `${p.dependency_id}-${p.version}`;
      const existing = byKey.get(key);
      if (!existing) {
        byKey.set(key, { ...p });
        continue;
      }
      existing.import_count = (existing.import_count || 0) + (p.import_count || 0);
    }
    return Array.from(byKey.values());
  }, [packages]);

  const filteredPackages = useMemo(() => {
    let filtered = deduplicatedPackages;
    if (filter === 'alerts') {
      filtered = filtered.filter(p =>
        p.registry_integrity_status === 'fail' ||
        p.install_scripts_status === 'fail' ||
        p.entropy_analysis_status === 'fail' ||
        p.analysis_status === 'error'
      );
    } else if (filter === 'blocked') {
      filtered = filtered.filter(p => p.next_version_status === 'blocked' || p.next_version_status === 'quarantined');
    } else if (filter === 'safe') {
      filtered = filtered.filter(p =>
        p.analysis_status === 'ready' &&
        p.registry_integrity_status !== 'fail' &&
        p.install_scripts_status !== 'fail' &&
        p.entropy_analysis_status !== 'fail'
      );
    }
    if (searchQuery.trim()) {
      const q = searchQuery.trim().toLowerCase();
      filtered = filtered.filter(p => p.name.toLowerCase().includes(q));
    }
    return filtered;
  }, [deduplicatedPackages, filter, searchQuery]);

  // Show skeleton until extraction status is known (avoids flash of "Enable Watchtower") or until data is loaded
  if (realtime.isLoading || loading) {
    return <WatchtowerSkeleton />;
  }

  if (isExtractionOngoing) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="max-w-2xl mx-auto">
          <div className="rounded-lg border border-border bg-background-card p-6">
            <div className="flex items-center gap-4">
              <div className="flex-1 space-y-2 min-w-0">
                <h3 className="text-sm font-semibold text-foreground">Project extraction still in progress</h3>
                <p className="text-sm text-foreground-secondary">
                  {!realtime.isLoading && realtime.status === 'not_connected'
                    ? 'Connect a repository in Project Settings to use Watchtower.'
                    : 'Watchtower will be available once extraction completes. You can enable supply chain monitoring from this tab then.'}
                </p>
              </div>
              <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border bg-background-subtle">
                <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" aria-hidden />
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  if (!stats?.enabled) {
    return (
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="max-w-2xl mx-auto text-center space-y-6">
          <div>
            <h2 className="text-2xl font-semibold text-foreground">Watchtower Supply Chain Monitoring</h2>
            <p className="mt-2 text-foreground-secondary max-w-md mx-auto">
              Enable Watchtower on this project to receive advanced security intelligence.
            </p>
          </div>
          <div className="flex items-center justify-center gap-3">
            <button
              type="button"
              onClick={() => handleToggle(true)}
              disabled={enabling || totalDirect === 0}
              title={totalDirect === 0 ? 'Connect a repository and run extraction to add dependencies first' : undefined}
              className="inline-flex items-center gap-2 h-9 px-5 py-2.5 rounded-lg text-sm font-semibold bg-primary text-primary-foreground hover:bg-primary/90 border border-primary-foreground/20 hover:border-primary-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/50 focus:ring-offset-2 disabled:pointer-events-none disabled:opacity-50"
            >
              {enabling ? <Loader2 className="h-4 w-4 animate-spin" /> : <TowerControl className="h-4 w-4" />}
              Enable Watchtower
            </button>
            <a
              href="/docs/watchtower"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 h-9 px-5 py-2.5 rounded-lg text-sm font-medium border border-border bg-background-card text-foreground hover:bg-background-subtle"
            >
              <BookOpen className="h-4 w-4" />
              Docs
            </a>
          </div>

          <div className="grid grid-cols-2 gap-4 mt-8 max-w-lg mx-auto text-left">
            {[
              { icon: Lock, title: 'Registry Integrity', desc: 'Detects tampered publishes where code differs between registry and source' },
              { icon: FileCode, title: 'Install Script Analysis', desc: 'Scans for dangerous preinstall/postinstall hooks' },
              { icon: Fingerprint, title: 'Entropy Analysis', desc: 'Identifies obfuscated or encoded malicious payloads' },
              { icon: GitCommit, title: 'Commit Anomaly Detection', desc: 'Flags unusual contributor activity patterns' },
            ].map(({ icon: Icon, title, desc }) => (
              <div key={title} className="p-4 rounded-lg border border-border bg-background-card">
                <Icon className="h-5 w-5 text-foreground-secondary mb-2" />
                <h3 className="text-sm font-medium text-foreground">{title}</h3>
                <p className="text-xs text-foreground-secondary mt-1">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-lg font-semibold text-foreground">Watchtower</h1>
          <span className="inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-400">
            <span className="h-1.5 w-1.5 rounded-full bg-green-400" />
            Active
          </span>
        </div>
        <div className="flex items-center gap-2">
          <a
            href="/docs/watchtower"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground"
          >
            <BookOpen className="h-3.5 w-3.5" />
            Docs
          </a>
          <button
            onClick={() => handleToggle(false)}
            disabled={enabling}
            className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-foreground-secondary hover:text-foreground hover:bg-background-subtle"
          >
            Disable
          </button>
        </div>
      </div>

      {/* Toolbar: search left, filters right */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative w-80">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary pointer-events-none" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search packages..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape' && searchQuery) {
                e.preventDefault();
                setSearchQuery('');
                searchInputRef.current?.blur();
              }
            }}
            className={`w-full pl-9 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent ${searchQuery ? 'pr-14' : 'pr-4'}`}
          />
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 px-2 py-0.5 rounded text-xs font-medium text-foreground-secondary hover:text-foreground bg-transparent border border-border/60 hover:border-border transition-colors"
              aria-label="Clear search (Esc)"
            >
              Esc
            </button>
          )}
        </div>
        <div className="flex items-center rounded-md border border-border bg-background">
          {(['all', 'alerts', 'blocked', 'safe'] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-2.5 py-1 text-xs font-medium capitalize transition-colors',
                filter === f
                  ? 'bg-background-card text-foreground'
                  : 'text-foreground-secondary hover:text-foreground'
              )}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      {/* Packages Table — same wrapper and row styling as Members / org tables */}
      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
          <table className="w-full">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Package
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Version
                </th>
                <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider" title="Registry Integrity">
                  Registry
                </th>
                <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider" title="Install Scripts">
                  Scripts
                </th>
                <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider" title="Entropy Analysis">
                  Entropy
                </th>
                <th className="text-center px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Anomaly
                </th>
                <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                  Next Version
                </th>
                <th className="w-20 px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredPackages.map((pkg) => {
                const rowId = `${pkg.dependency_id}-${pkg.version}`;
                const isExpanded = expandedRow === rowId;
                const isAnalyzing = pkg.analysis_status === 'analyzing' || pkg.analysis_status === 'pending';
                const hasError = pkg.analysis_status === 'error';

                return (
                  <tr key={rowId} className="hover:bg-table-hover transition-colors">
                    <td className="px-4 py-3 min-w-0 overflow-hidden">
                      <button
                        onClick={() => setExpandedRow(isExpanded ? null : rowId)}
                        className="flex items-center gap-2 text-left w-full min-w-0"
                      >
                        {isExpanded ? <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary flex-shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-foreground-secondary flex-shrink-0" />}
                        {pkg.ecosystem === 'npm' ? (
                          <img src="/images/npm_icon.png" alt="" className="h-4 w-4 shrink-0 object-contain" aria-hidden />
                        ) : (
                          <span className="inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium uppercase text-foreground-secondary bg-background-subtle border border-border shrink-0">
                            {pkg.ecosystem}
                          </span>
                        )}
                        <span className="text-sm font-medium text-foreground truncate">{pkg.name}</span>
                      </button>
                      {isExpanded && (
                        <div className="mt-2 ml-6 space-y-1 text-xs text-foreground-secondary">
                          {pkg.analysis_error && <p className="text-orange-400">{pkg.analysis_error}</p>}
                          <p>Used in {pkg.import_count} file{pkg.import_count !== 1 ? 's' : ''}</p>
                          {pkg.quarantine_until && new Date(pkg.quarantine_until) > new Date() && (
                            <p className="text-yellow-400">
                              Quarantined until {new Date(pkg.quarantine_until).toLocaleDateString()}
                            </p>
                          )}
                        </div>
                      )}
                    </td>
                    <td className="px-4 py-3 text-sm font-mono text-foreground-secondary">
                      {pkg.version}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {isAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary mx-auto" /> : <StatusDot status={pkg.registry_integrity_status} ecosystem={pkg.ecosystem} />}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {isAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary mx-auto" /> : <StatusDot status={pkg.install_scripts_status} ecosystem={pkg.ecosystem} />}
                    </td>
                    <td className="px-4 py-3 text-center">
                      {isAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary mx-auto" /> : <StatusDot status={pkg.entropy_analysis_status} />}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <AnomalyScore score={pkg.max_anomaly_score} />
                    </td>
                    <td className="px-4 py-3">
                      <NextVersionBadge status={pkg.next_version_status} version={pkg.latest_version} />
                    </td>
                    <td className="px-4 py-3">
                      {hasError && pkg.watchlist_id && (
                        <button
                          onClick={() => handleReanalyze(pkg.watchlist_id!)}
                          className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground"
                          title="Retry analysis"
                        >
                          <RotateCcw className="h-3.5 w-3.5" />
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
              {filteredPackages.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-8 text-center text-sm text-foreground-secondary min-w-0">
                    {searchQuery ? 'No packages match your search.' : 'No packages in this view.'}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
      </div>
      </div>
    </div>
  );
}
