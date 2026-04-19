import { useEffect, useState, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate, useLocation, Link } from 'react-router-dom';
import {
  RefreshCw, AlertTriangle, ShieldCheck, Package, Shield, FileCode, GitBranch,
  Activity, Loader2, Github, GitlabIcon, ExternalLink,
} from 'lucide-react';
import { api, ProjectWithRole, ProjectPermissions, ProjectStats, ProjectActivityItem } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { Button } from '../../components/ui/button';
import { FrameworkIcon } from '../../components/framework-icon';
import { StatsStrip, type StatCardData } from '../../components/StatsStrip';
import { ActionableItems } from '../../components/ActionableItems';
import { ActivityFeed } from '../../components/ActivityFeed';
import { OverviewGraph } from '../../components/OverviewGraph';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

function extractionStepLabel(step: string | null | undefined): string {
  if (!step) return 'Starting extraction...';
  const labels: Record<string, string> = {
    queued: 'Job queued, waiting for worker...',
    cloning: 'Cloning repository...',
    sbom: 'Building SBOM...',
    deps_synced: 'Syncing dependencies...',
    ast_parsing: 'Analyzing imports...',
    scanning: 'Scanning for vulnerabilities...',
    uploading: 'Uploading results...',
    completed: 'Finishing up...',
  };
  return labels[step] ?? `Processing (${step})...`;
}

function relativeTime(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const diff = Date.now() - new Date(dateStr).getTime();
  const minutes = Math.floor(diff / 60000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

function HealthBadge({ score }: { score: number }) {
  const color = score >= 80 ? 'text-emerald-400 border-emerald-500/40 bg-emerald-500/10' :
                score >= 50 ? 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10' :
                'text-red-400 border-red-500/40 bg-red-500/10';
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-bold tabular-nums ${color}`}>
      {score}
    </span>
  );
}

function SeverityDots({ critical, high, medium, low }: { critical: number; high: number; medium: number; low: number }) {
  return (
    <span className="flex items-center gap-1">
      {critical > 0 && <span className="h-2 w-2 rounded-full bg-red-500" title={`${critical} critical`} />}
      {high > 0 && <span className="h-2 w-2 rounded-full bg-orange-500" title={`${high} high`} />}
      {medium > 0 && <span className="h-2 w-2 rounded-full bg-yellow-500" title={`${medium} medium`} />}
      {low > 0 && <span className="h-2 w-2 rounded-full bg-slate-500" title={`${low} low`} />}
    </span>
  );
}

export default function ProjectOverviewPage() {
  const { project, reloadProject, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId } = useParams<{ projectId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();

  const [stats, setStats] = useState<ProjectStats | null>(null);
  const [activity, setActivity] = useState<ProjectActivityItem[]>([]);
  const [statsLoading, setStatsLoading] = useState(true);
  const [activityLoading, setActivityLoading] = useState(true);
  const [statsError, setStatsError] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [permissionsChecked, setPermissionsChecked] = useState(false);
  const [errorBannerDismissed, setErrorBannerDismissed] = useState(false);

  const realtime = useRealtimeStatus(organizationId, projectId);

  // Permission check
  useEffect(() => {
    if (!project || !projectId || !userPermissions) return;
    if (userPermissions.view_overview === false) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies`, { replace: true });
      return;
    }
    setPermissionsChecked(true);
  }, [project, projectId, userPermissions, navigate, organizationId]);

  // Load stats + activity
  const loadData = useCallback(async () => {
    if (!organizationId || !projectId) return;
    try {
      setStatsLoading(true);
      setStatsError(false);
      const [s, a] = await Promise.all([
        api.getProjectStats(organizationId, projectId),
        api.getProjectRecentActivity(organizationId, projectId),
      ]);
      setStats(s);
      setActivity(a);
    } catch {
      setStatsError(true);
    } finally {
      setStatsLoading(false);
      setActivityLoading(false);
    }
  }, [organizationId, projectId]);

  useEffect(() => {
    if (permissionsChecked) loadData();
  }, [permissionsChecked, loadData]);

  // Reload on extraction complete
  useEffect(() => {
    if (realtime.status === 'ready' && !realtime.isLoading) {
      loadData();
      reloadProject();
    }
  }, [realtime.status]);

  const canManage = userPermissions?.edit_settings === true ||
    (userPermissions as any)?.manage_teams_and_projects === true;

  const handleSync = async () => {
    if (!organizationId || !projectId || syncing) return;
    try {
      setSyncing(true);
      await api.triggerProjectSync(organizationId, projectId);
      toast({ title: 'Sync started', description: 'Extraction has been queued.' });
      setErrorBannerDismissed(false);
    } catch (err: any) {
      const msg = err?.message ?? 'Failed to trigger sync';
      toast({ title: 'Sync failed', description: msg, variant: 'destructive' });
    } finally {
      setSyncing(false);
    }
  };

  // Loading skeleton
  if (!project || !permissionsChecked) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-muted rounded w-48" />
          <StatsStrip cards={[]} loading />
        </div>
      </main>
    );
  }

  const isExtracting = realtime.status === 'initializing' || realtime.status === 'extracting' ||
    realtime.status === 'analyzing' || realtime.status === 'finalizing';
  const hasFailed = (stats?.sync.last_error || realtime.status === 'error') && !errorBannerDismissed;
  const noRepo = realtime.status === 'not_connected' && !realtime.isLoading;

  // Stats strip cards
  const statsCards: StatCardData[] = stats ? [
    {
      icon: <Activity className="h-4 w-4" />,
      iconBg: stats.health_score >= 80 ? 'bg-emerald-500/15' : stats.health_score >= 50 ? 'bg-yellow-500/15' : 'bg-red-500/15',
      iconColor: stats.health_score >= 80 ? 'text-emerald-400' : stats.health_score >= 50 ? 'text-yellow-400' : 'text-red-400',
      label: 'Health',
      value: stats.health_score,
    },
    {
      icon: <ShieldCheck className="h-4 w-4" />,
      iconBg: stats.status?.is_passing ? 'bg-emerald-500/15' : stats.status ? 'bg-red-500/15' : 'bg-zinc-500/15',
      iconColor: stats.status?.is_passing ? 'text-emerald-400' : stats.status ? 'text-red-400' : 'text-zinc-400',
      label: 'Status',
      value: stats.status?.name ?? 'Not evaluated',
      badge: stats.status ? (
        stats.status.color ? (
          <span className="inline-block h-2 w-2 rounded-full" style={{ backgroundColor: stats.status.color }} />
        ) : (
          <span className="inline-block h-2 w-2 rounded-full bg-foreground/30" />
        )
      ) : undefined,
    },
    {
      icon: <FileCode className="h-4 w-4" />,
      iconBg: 'bg-blue-500/15',
      iconColor: 'text-blue-400',
      label: 'Compliance',
      value: `${stats.compliance.percent}%`,
      sub: stats.compliance.failing > 0 ? `${stats.compliance.failing} failing` : 'All compliant',
      onClick: () => navigate(`/organizations/${organizationId}/projects/${projectId}/compliance`),
    },
    {
      icon: <Shield className="h-4 w-4" />,
      iconBg: stats.vulnerabilities.total > 0 ? 'bg-orange-500/15' : 'bg-emerald-500/15',
      iconColor: stats.vulnerabilities.total > 0 ? 'text-orange-400' : 'text-emerald-400',
      label: 'Vulnerabilities',
      value: stats.vulnerabilities.total,
      sub: `${stats.code_findings.semgrep_count} code issues, ${stats.code_findings.secret_count} secrets`,
      badge: stats.vulnerabilities.total > 0 ? (
        <SeverityDots {...stats.vulnerabilities} />
      ) : undefined,
      onClick: () => navigate(`/organizations/${organizationId}/projects/${projectId}/security`),
    },
    {
      icon: <Package className="h-4 w-4" />,
      iconBg: 'bg-violet-500/15',
      iconColor: 'text-violet-400',
      label: 'Dependencies',
      value: stats.dependencies.total,
      sub: `${stats.dependencies.direct} direct, ${stats.dependencies.transitive} transitive${stats.dependencies.outdated > 0 ? `, ${stats.dependencies.outdated} outdated` : ''}`,
      onClick: () => navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies`),
    },
  ] : [];

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-6 flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-foreground">{project.name}</h1>
            {stats && <HealthBadge score={stats.health_score} />}
            {stats?.status && (
              stats.status.color ? (
                <span className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium"
                  style={{ borderColor: stats.status.color + '60', color: stats.status.color, backgroundColor: stats.status.color + '15' }}>
                  {stats.status.name}
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-foreground/20 px-2.5 py-0.5 text-xs font-medium bg-transparent text-foreground-secondary">
                  {stats.status.name}
                </span>
              )
            )}
            {stats?.asset_tier && (
              <span className="inline-flex items-center rounded-full border border-border px-2 py-0.5 text-xs text-foreground-secondary">
                {stats.asset_tier.name}
              </span>
            )}
          </div>
          {stats && (
            <div className="flex items-center gap-2 mt-1.5 text-sm text-foreground-secondary">
              {project.framework && <FrameworkIcon frameworkId={project.framework} />}
              <GitBranch className="h-3.5 w-3.5" />
              <span className="font-mono text-xs">{stats.sync.branch}</span>
              <span className="text-foreground-muted">·</span>
              <span>Last synced {relativeTime(stats.sync.last_synced)}</span>
            </div>
          )}
        </div>
        {canManage && !noRepo && (
          <Button variant="outline" size="sm" onClick={handleSync} disabled={syncing || isExtracting}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${syncing || isExtracting ? 'animate-spin' : ''}`} />
            Sync
          </Button>
        )}
      </div>

      {/* No repository CTA */}
      {noRepo && (
        <div className="mb-6 rounded-lg border border-border bg-background-card p-8 text-center">
          <Package className="h-10 w-10 text-foreground-secondary/40 mx-auto mb-3" />
          <h2 className="text-lg font-semibold text-foreground mb-1">Connect a repository to get started</h2>
          <p className="text-sm text-foreground-secondary mb-4">Link a GitHub, GitLab, or Bitbucket repository to analyze dependencies and vulnerabilities.</p>
          <Button onClick={() => navigate(`/organizations/${organizationId}/projects/${projectId}/settings`)}>
            Connect Repository
          </Button>
        </div>
      )}

      {/* Extraction in progress banner */}
      {isExtracting && (
        <div className="mb-6 flex items-center gap-3 px-4 py-3 rounded-lg border border-border bg-background-card text-sm">
          <Loader2 className="h-4 w-4 animate-spin text-foreground-secondary" />
          <div>
            <div className="font-medium text-foreground">Extraction in progress</div>
            <div className="text-xs text-foreground-secondary mt-0.5">
              {extractionStepLabel(realtime.extractionStep)}
            </div>
          </div>
        </div>
      )}

      {/* Error banner */}
      {hasFailed && !isExtracting && (
        <div className="mb-6 px-4 py-3 rounded-lg border border-amber-500/30 bg-amber-500/5 text-sm flex items-center gap-3">
          <AlertTriangle className="h-4 w-4 text-amber-400 flex-shrink-0" />
          <div className="flex-1">
            <div className="font-medium text-amber-400">Last sync failed</div>
            <div className="text-xs text-foreground-secondary mt-0.5">{stats?.sync.last_error ?? 'An error occurred during extraction.'}</div>
          </div>
          <div className="flex items-center gap-2">
            {canManage && (
              <Button variant="outline" size="sm" onClick={handleSync} disabled={syncing}>
                <RefreshCw className="h-3 w-3 mr-1" /> Retry
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={() => setErrorBannerDismissed(true)} className="text-xs">
              Dismiss
            </Button>
          </div>
        </div>
      )}

      {/* Stats error */}
      {statsError && !statsLoading && (
        <div className="mb-6 rounded-lg border border-border bg-background-card p-8 text-center">
          <p className="text-sm text-foreground-secondary mb-2">Unable to load dashboard.</p>
          <button onClick={loadData} className="text-sm text-primary hover:underline">Retry</button>
        </div>
      )}

      {/* Stats strip */}
      {!noRepo && <div className="mb-6"><StatsStrip cards={statsCards} loading={statsLoading} /></div>}

      {/* Two-column: Graph + Action Items */}
      {!noRepo && !statsError && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
          <OverviewGraph
            mode="project"
            organizationId={organizationId}
            graphDeps={stats?.graph_deps}
            projectName={project.name}
            frameworkName={project.framework ?? undefined}
            fullGraphLink={`/organizations/${organizationId}/projects/${projectId}/security`}
          />
          <ActionableItems items={stats?.action_items ?? []} loading={statsLoading} />
        </div>
      )}

      {/* Activity feed */}
      {!noRepo && (
        <ActivityFeed
          items={activity}
          loading={activityLoading}
          onRetrySync={canManage ? handleSync : undefined}
        />
      )}
    </main>
  );
}
