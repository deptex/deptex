import { useState, useEffect, useMemo, useCallback } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  TowerControl,
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Loader2,
  ExternalLink,
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

  const fetchData = useCallback(async () => {
    if (!orgId || !projectId) return;
    try {
      const [statsRes, pkgsRes] = await Promise.all([
        api.authenticatedGet(`/api/organizations/${orgId}/projects/${projectId}/watchtower/stats`),
        api.authenticatedGet(`/api/organizations/${orgId}/projects/${projectId}/watchtower/packages`).catch(() => ({ packages: [], total_direct_deps: 0 })),
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

  const filteredPackages = useMemo(() => {
    let filtered = packages;
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
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      filtered = filtered.filter(p => p.name.toLowerCase().includes(q));
    }
    return filtered;
  }, [packages, filter, searchQuery]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Loader2 className="h-6 w-6 animate-spin text-foreground-secondary" />
      </div>
    );
  }

  if (!stats?.enabled) {
    return (
      <div className="px-6 py-8">
        <div className="max-w-2xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center justify-center h-16 w-16 rounded-2xl bg-background-card border border-border">
            <TowerControl className="h-8 w-8 text-foreground-secondary" />
          </div>
          <div>
            <h2 className="text-2xl font-semibold text-foreground">Watchtower Supply Chain Monitoring</h2>
            <p className="mt-2 text-foreground-secondary max-w-md mx-auto">
              Enable Watchtower to monitor all {totalDirect || 'your'} direct dependencies for supply chain threats.
            </p>
          </div>
          <div className="flex items-center justify-center gap-3">
            <button
              onClick={() => handleToggle(true)}
              disabled={enabling || totalDirect === 0}
              className="inline-flex items-center gap-2 rounded-md bg-brand px-4 py-2 text-sm font-medium text-white hover:bg-brand/90 disabled:opacity-50"
            >
              {enabling ? <Loader2 className="h-4 w-4 animate-spin" /> : <TowerControl className="h-4 w-4" />}
              Enable Watchtower
            </button>
            <Link
              to="/docs/watchtower"
              className="inline-flex items-center gap-1.5 rounded-md border border-border px-4 py-2 text-sm font-medium text-foreground-secondary hover:text-foreground hover:bg-background-subtle"
            >
              <BookOpen className="h-4 w-4" />
              Docs
            </Link>
          </div>
          {totalDirect === 0 && (
            <p className="text-sm text-foreground-secondary">No dependencies found. Run an extraction first.</p>
          )}

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
    <div className="px-6 py-6 space-y-6">
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
          {stats.enabled_at && (
            <span className="text-xs text-foreground-secondary">
              Since {new Date(stats.enabled_at).toLocaleDateString()}
            </span>
          )}
          <Link
            to="/docs/watchtower"
            className="inline-flex items-center gap-1 text-xs text-foreground-secondary hover:text-foreground"
          >
            <BookOpen className="h-3.5 w-3.5" />
            Docs
          </Link>
          <button
            onClick={() => handleToggle(false)}
            disabled={enabling}
            className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs font-medium text-foreground-secondary hover:text-foreground hover:bg-background-subtle"
          >
            Disable
          </button>
        </div>
      </div>

      {/* Stats Strip */}
      <div className="grid grid-cols-4 gap-4">
        <div className="rounded-lg border border-border bg-background-card p-4">
          <p className="text-xs text-foreground-secondary">Packages Monitored</p>
          <p className="text-xl font-semibold text-foreground mt-1">
            {stats.analyzed} <span className="text-sm text-foreground-secondary font-normal">/ {stats.total_direct}</span>
          </p>
          <div className="mt-2 h-1 rounded-full bg-background-subtle overflow-hidden">
            <div className="h-full bg-brand rounded-full" style={{ width: stats.total_direct > 0 ? `${(stats.analyzed / stats.total_direct) * 100}%` : '0%' }} />
          </div>
        </div>
        <div className="rounded-lg border border-border bg-background-card p-4">
          <p className="text-xs text-foreground-secondary">Security Alerts</p>
          <p className={cn('text-xl font-semibold mt-1', stats.alerts > 0 ? 'text-red-400' : 'text-foreground')}>{stats.alerts}</p>
        </div>
        <div className="rounded-lg border border-border bg-background-card p-4">
          <p className="text-xs text-foreground-secondary">Blocked Versions</p>
          <p className={cn('text-xl font-semibold mt-1', stats.blocked > 0 ? 'text-yellow-400' : 'text-foreground')}>{stats.blocked}</p>
        </div>
        {stats.errored > 0 && (
          <div className="rounded-lg border border-border bg-background-card p-4">
            <p className="text-xs text-foreground-secondary">Errored Packages</p>
            <p className="text-xl font-semibold text-orange-400 mt-1">{stats.errored}</p>
          </div>
        )}
      </div>

      {/* Packages Security Table */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-medium text-foreground">Packages</h2>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground-secondary" />
              <input
                type="text"
                placeholder="Search packages..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 w-48 rounded-md border border-border bg-background pl-8 pr-3 text-xs text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-1 focus:ring-brand"
              />
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
        </div>

        <p className="text-xs text-foreground-secondary">
          Monitoring {stats.total_direct} direct dependencies. Transitive dependencies are covered through their parent packages.
        </p>

        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-background-card-header border-b border-border text-left">
                <th className="px-4 py-2.5 text-xs font-medium text-foreground-secondary">Package</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary">Version</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary text-center" title="Registry Integrity">Registry</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary text-center" title="Install Scripts">Scripts</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary text-center" title="Entropy Analysis">Entropy</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary text-center">Anomaly</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary">Next Version</th>
                <th className="px-3 py-2.5 text-xs font-medium text-foreground-secondary w-20"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filteredPackages.map((pkg) => {
                const isExpanded = expandedRow === pkg.dependency_id;
                const isAnalyzing = pkg.analysis_status === 'analyzing' || pkg.analysis_status === 'pending';
                const hasError = pkg.analysis_status === 'error';

                return (
                  <tr key={pkg.dependency_id} className="hover:bg-table-hover/40 transition-colors">
                    <td className="px-4 py-2.5">
                      <button
                        onClick={() => setExpandedRow(isExpanded ? null : pkg.dependency_id)}
                        className="flex items-center gap-2 text-left"
                      >
                        {isExpanded ? <ChevronDown className="h-3.5 w-3.5 text-foreground-secondary flex-shrink-0" /> : <ChevronRight className="h-3.5 w-3.5 text-foreground-secondary flex-shrink-0" />}
                        <span className="font-medium text-foreground">{pkg.name}</span>
                        <span className="text-[10px] text-foreground-secondary uppercase">{pkg.ecosystem}</span>
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
                    <td className="px-3 py-2.5 text-foreground-secondary font-mono text-xs">{pkg.version}</td>
                    <td className="px-3 py-2.5 text-center">
                      {isAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary mx-auto" /> : <StatusDot status={pkg.registry_integrity_status} ecosystem={pkg.ecosystem} />}
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      {isAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary mx-auto" /> : <StatusDot status={pkg.install_scripts_status} ecosystem={pkg.ecosystem} />}
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      {isAnalyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary mx-auto" /> : <StatusDot status={pkg.entropy_analysis_status} />}
                    </td>
                    <td className="px-3 py-2.5 text-center">
                      <AnomalyScore score={pkg.max_anomaly_score} />
                    </td>
                    <td className="px-3 py-2.5">
                      <NextVersionBadge status={pkg.next_version_status} version={pkg.latest_version} />
                    </td>
                    <td className="px-3 py-2.5">
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
                  <td colSpan={8} className="px-4 py-8 text-center text-sm text-foreground-secondary">
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
