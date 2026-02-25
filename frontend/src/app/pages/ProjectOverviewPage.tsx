import { useEffect, useState, useRef, useCallback } from 'react';
import { useOutletContext, useParams, useNavigate, useLocation } from 'react-router-dom';
import { Search, FolderOpen, Copy, Check, Lock, ShieldCheck, Activity, GitBranch, TrendingUp, ArrowRight, RefreshCw, AlertTriangle, AlertCircle, Info, Clock, Package } from 'lucide-react';
import { api, ProjectWithRole, ProjectPermissions, ProjectRepository, ProjectImportStatus } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { Button } from '../../components/ui/button';
import { FrameworkIcon } from '../../components/framework-icon';

// Dummy data for the overview dashboard (replace with real data later)
const DUMMY_HEALTH = { score: 87, trend: '+2', status: 'good' as const };
const DUMMY_COMPLIANCE = { percent: 94, failing: 3, total: 48 };
const DUMMY_VULNS = { total: 12, critical: 3, high: 4, medium: 5, low: 0, reachablePct: 67 };
const DUMMY_SYNC = { lastSynced: '2 hours ago', branch: 'main', status: 'synced' as const };
const DUMMY_ACTIVITY = [
  { id: 1, pkg: 'lodash', from: '4.17.20', to: '4.17.21', type: 'patch' as const, time: '3h ago', severity: null },
  { id: 2, pkg: 'axios', from: '1.6.0', to: '1.7.2', type: 'minor' as const, time: '1d ago', severity: 'medium' as const },
  { id: 3, pkg: 'react', from: '18.2.0', to: '18.3.1', type: 'minor' as const, time: '2d ago', severity: null },
  { id: 4, pkg: 'typescript', from: '5.3.3', to: '5.4.5', type: 'minor' as const, time: '3d ago', severity: null },
  { id: 5, pkg: 'vite', from: '5.1.0', to: '5.2.8', type: 'minor' as const, time: '4d ago', severity: null },
  { id: 6, pkg: 'express', from: '4.18.2', to: '4.19.2', type: 'patch' as const, time: '5d ago', severity: 'high' as const },
];
const DUMMY_TOP_VULNS = [
  { id: 1, pkg: 'lodash', version: '4.17.20', severity: 'critical' as const, title: 'Prototype Pollution', reachable: true },
  { id: 2, pkg: 'axios', version: '1.6.0', severity: 'high' as const, title: 'SSRF via redirect', reachable: true },
  { id: 3, pkg: 'semver', version: '7.5.1', severity: 'high' as const, title: 'ReDoS vulnerability', reachable: false },
  { id: 4, pkg: 'minimatch', version: '3.0.4', severity: 'medium' as const, title: 'ReDoS vulnerability', reachable: false },
  { id: 5, pkg: 'tough-cookie', version: '4.1.2', severity: 'medium' as const, title: 'Prototype Pollution', reachable: true },
];

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

const allValidTabs = ['overview', 'dependencies', 'watchlist', 'members', 'settings'];

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

export default function ProjectOverviewPage() {
  const { project, reloadProject, organizationId, userPermissions } = useOutletContext<ProjectContextType>();
  const { projectId } = useParams<{ projectId: string; tab?: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const { toast } = useToast();
  const [permissionsChecked, setPermissionsChecked] = useState(false);

  // Repository state (kept for real-data polling and status banners)
  const [repositories, setRepositories] = useState<Array<{ id: number; full_name: string; default_branch: string; private: boolean; framework: string }>>([]);
  const [connectedRepository, setConnectedRepository] = useState<ProjectRepository | null>(null);
  const [repositoriesLoading, setRepositoriesLoading] = useState(false);
  const [detectedFramework, setDetectedFramework] = useState<string>('unknown');
  const [importStatus, setImportStatus] = useState<ProjectImportStatus | null>(null);
  const pollingIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // Permission check and invalid tab redirect
  useEffect(() => {
    if (!project || !projectId || !userPermissions) return;
    const pathParts = location.pathname.split('/');
    const currentTab = pathParts[pathParts.length - 1];
    const isOverviewPage = currentTab === projectId || currentTab === 'overview';
    if (currentTab !== projectId && !allValidTabs.includes(currentTab)) {
      navigate(`/organizations/${organizationId}/projects/${projectId}${userPermissions.view_overview ? '' : '/dependencies'}`, { replace: true });
      return;
    }
    if (isOverviewPage && !userPermissions.view_overview) {
      navigate(`/organizations/${organizationId}/projects/${projectId}/dependencies`, { replace: true });
      return;
    }
    setPermissionsChecked(true);
  }, [project, projectId, userPermissions, location.pathname, navigate, organizationId]);

  // Load repository info (for status banners)
  const loadProjectRepositories = async () => {
    if (!organizationId || !projectId) return;
    const cached = api.getCachedProjectRepositories(organizationId, projectId);
    try {
      if (!cached) setRepositoriesLoading(true);
      const data = await api.getProjectRepositories(organizationId, projectId);
      setConnectedRepository(data.connectedRepository);
      setRepositories(data.repositories);
    } catch {
      // silently fail for overview
    } finally {
      setRepositoriesLoading(false);
    }
  };

  useEffect(() => {
    if (permissionsChecked && organizationId && projectId) {
      const cached = api.getCachedProjectRepositories(organizationId, projectId);
      if (cached) {
        setConnectedRepository(cached.connectedRepository);
        setRepositories(cached.repositories);
      }
      loadProjectRepositories();
    }
  }, [permissionsChecked, organizationId, projectId]);

  const checkImportStatus = useCallback(async () => {
    if (!organizationId || !projectId) return false;
    try {
      const status = await api.getProjectImportStatus(organizationId, projectId);
      setImportStatus(status);
      const inProgress = connectedRepository?.status === 'initializing' || connectedRepository?.status === 'extracting' || connectedRepository?.status === 'analyzing' || connectedRepository?.status === 'finalizing';
      if (status.status === 'ready' && inProgress) {
        setConnectedRepository(prev => prev ? { ...prev, status: 'ready' } : null);
        await loadProjectRepositories();
        await reloadProject();
        toast({ title: 'Analysis complete', description: status.total > 0 ? `All ${status.total} dependencies have been analyzed.` : 'Extraction complete.' });
      }
      if (status.status === 'error') {
        setConnectedRepository(prev => prev ? { ...prev, status: 'error' } : null);
        await loadProjectRepositories();
      }
      return status.status === 'ready' || status.status === 'error';
    } catch {
      return false;
    }
  }, [organizationId, projectId, connectedRepository?.status, reloadProject, toast]);

  useEffect(() => {
    const repoStatus = connectedRepository?.status;
    const importStatusPoll = importStatus?.status;
    const shouldPoll = repoStatus === 'initializing' || repoStatus === 'extracting' || repoStatus === 'analyzing' || repoStatus === 'finalizing' || importStatusPoll === 'finalizing';
    if (!shouldPoll) return;
    checkImportStatus();
    const id = setInterval(() => {
      checkImportStatus().then(done => { if (done && pollingIntervalRef.current) clearInterval(pollingIntervalRef.current); });
    }, 3000);
    pollingIntervalRef.current = id;
    return () => { if (pollingIntervalRef.current) clearInterval(pollingIntervalRef.current); pollingIntervalRef.current = null; };
  }, [connectedRepository?.status, importStatus?.status, checkImportStatus]);

  useEffect(() => {
    if (!connectedRepository || repositories.length === 0) return;
    const match = repositories.find(r => r.full_name === connectedRepository.repo_full_name);
    setDetectedFramework(match ? match.framework : 'unknown');
  }, [connectedRepository, repositories]);

  // Loading skeleton
  if (!project || !permissionsChecked) {
    return (
      <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-muted rounded w-48" />
          <div className="grid grid-cols-2 md:grid-cols-4 gap-6 py-6 border-y border-border">
            {[1, 2, 3, 4].map((i) => <div key={i} className="h-16 bg-muted rounded" />)}
          </div>
        </div>
      </main>
    );
  }

  const pathParts = location.pathname.split('/');
  const currentTab = pathParts[pathParts.length - 1];
  const isOverviewPage = currentTab === projectId || currentTab === 'overview';
  if (isOverviewPage && !userPermissions?.view_overview) return null;

  const sevColor = (s: string) => s === 'critical' ? 'text-destructive' : s === 'high' ? 'text-orange-500' : s === 'medium' ? 'text-warning' : 'text-foreground-secondary';
  const sevDot = (s: string) => s === 'critical' ? 'bg-destructive' : s === 'high' ? 'bg-orange-500' : s === 'medium' ? 'bg-warning' : 'bg-foreground-secondary';
  const updateBadge = (t: string) => t === 'major' ? 'text-destructive border-destructive/30 bg-destructive/10' : t === 'minor' ? 'text-warning border-warning/30 bg-warning/10' : 'text-foreground-secondary border-border bg-foreground/5';

  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-8">

      {/* Page header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-foreground">Overview</h1>
        {connectedRepository && (
          <div className="flex items-center gap-2 mt-1.5 text-sm text-foreground-secondary">
            <FrameworkIcon frameworkId={detectedFramework} />
            <span>{connectedRepository.repo_full_name}</span>
            <span className="text-foreground-muted">·</span>
            <span className="font-mono text-xs">{connectedRepository.default_branch}</span>
            {connectedRepository.status === 'ready' && (
              <>
                <span className="text-foreground-muted">·</span>
                <span className="flex items-center gap-1 text-success text-xs">
                  <span className="h-1.5 w-1.5 rounded-full bg-success" />
                  Synced
                </span>
              </>
            )}
          </div>
        )}
      </div>

      {/* ── Compact status banners (only when active) ── */}

      {repositoriesLoading && (
        <div className="mb-6 flex items-center gap-2 text-sm text-foreground-secondary">
          <span className="animate-spin h-4 w-4 border-2 border-current border-t-transparent rounded-full flex-shrink-0" />
          Loading...
        </div>
      )}

      {connectedRepository && (connectedRepository.status === 'initializing' || connectedRepository.status === 'extracting') && (
        <div className="mb-6 flex items-center gap-3 px-4 py-3 rounded-lg border border-border bg-background-card text-sm">
          <span className="animate-spin h-4 w-4 border-2 border-foreground-secondary border-t-transparent rounded-full flex-shrink-0" />
          <div>
            <div className="font-medium text-foreground">Extraction in progress</div>
            <div className="text-xs text-foreground-secondary mt-0.5">
              {extractionStepLabel(importStatus?.extraction_step ?? connectedRepository.extraction_step ?? 'queued')}
            </div>
          </div>
          <span className="ml-auto text-xs text-foreground-secondary font-mono">{connectedRepository.repo_full_name}</span>
        </div>
      )}

      {connectedRepository?.status === 'error' && (
        <div className="mb-6 px-4 py-3 rounded-lg border border-destructive/30 bg-destructive/5 text-sm flex items-center gap-3">
          <AlertTriangle className="h-4 w-4 text-destructive flex-shrink-0" />
          <div>
            <div className="font-medium text-destructive">Extraction failed</div>
            <div className="text-xs text-foreground-secondary mt-0.5">
              {importStatus?.extraction_error ?? connectedRepository.extraction_error ?? 'An error occurred during extraction.'}
            </div>
          </div>
        </div>
      )}

      {connectedRepository && (connectedRepository.status === 'analyzing' || connectedRepository.status === 'finalizing' || importStatus?.status === 'finalizing') && (
        <div className="mb-6 px-4 py-3 rounded-lg border border-border bg-background-card text-sm">
          <div className="flex items-center gap-3">
            <span className="animate-spin h-4 w-4 border-2 border-foreground-secondary border-t-transparent rounded-full flex-shrink-0" />
            <div className="font-medium text-foreground">
              {importStatus?.status === 'finalizing' || connectedRepository.status === 'finalizing' ? 'Finalizing analysis...' : 'Analyzing dependencies...'}
            </div>
            {importStatus && importStatus.total > 0 && (
              <span className="ml-auto text-xs text-foreground-secondary">{importStatus.ready} / {importStatus.total}</span>
            )}
          </div>
          {importStatus && importStatus.total > 0 && connectedRepository.status === 'analyzing' && (
            <div className="mt-3 h-1 bg-border rounded-full overflow-hidden">
              <div className="h-full bg-primary transition-all duration-500" style={{ width: `${Math.round((importStatus.ready / importStatus.total) * 100)}%` }} />
            </div>
          )}
        </div>
      )}

      {/* ── Stats strip ── */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-6 py-6 border-y border-border mb-8">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">Health Score</div>
          <div className="text-3xl font-bold text-foreground tabular-nums">{DUMMY_HEALTH.score}</div>
          <div className="flex items-center gap-1 mt-1.5 text-sm text-success">
            <TrendingUp className="h-3.5 w-3.5" />
            {DUMMY_HEALTH.trend} this week
          </div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">Compliance</div>
          <div className="text-3xl font-bold text-foreground tabular-nums">{DUMMY_COMPLIANCE.percent}%</div>
          <div className="text-sm text-foreground-secondary mt-1.5">{DUMMY_COMPLIANCE.failing} policies failing</div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">Vulnerabilities</div>
          <div className="text-3xl font-bold text-foreground tabular-nums">{DUMMY_VULNS.total}</div>
          <div className="flex items-center gap-2 mt-1.5 text-sm">
            <span className="text-destructive font-medium">{DUMMY_VULNS.critical} critical</span>
            <span className="text-foreground-muted">·</span>
            <span className="text-foreground-secondary">{DUMMY_VULNS.reachablePct}% reachable</span>
          </div>
        </div>
        <div>
          <div className="text-xs font-semibold uppercase tracking-wider text-foreground-secondary mb-2">Sync Status</div>
          <div className="flex items-center gap-2 mt-1">
            <span className="h-2 w-2 rounded-full bg-success flex-shrink-0" />
            <span className="text-base font-semibold text-foreground">Synced</span>
          </div>
          <div className="flex items-center gap-1.5 mt-1.5 text-sm text-foreground-secondary">
            <Clock className="h-3.5 w-3.5" />
            {DUMMY_SYNC.lastSynced}
          </div>
        </div>
      </div>

      {/* ── Main content ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-10">

        {/* Top Vulnerabilities (3 cols) */}
        <div className="lg:col-span-3">
          <div className="flex items-center justify-between mb-5">
            <h2 className="text-sm font-semibold text-foreground">Top Vulnerabilities</h2>
            <span className="text-xs text-foreground-secondary">{DUMMY_VULNS.reachablePct}% reachable</span>
          </div>

          <div className="flex gap-8 mb-5">
            <div>
              <span className="text-2xl font-bold text-destructive tabular-nums">{DUMMY_VULNS.critical}</span>
              <span className="text-sm text-foreground-secondary ml-2">Critical</span>
            </div>
            <div>
              <span className="text-2xl font-bold text-orange-500 tabular-nums">{DUMMY_VULNS.high}</span>
              <span className="text-sm text-foreground-secondary ml-2">High</span>
            </div>
            <div>
              <span className="text-2xl font-bold text-warning tabular-nums">{DUMMY_VULNS.medium}</span>
              <span className="text-sm text-foreground-secondary ml-2">Medium</span>
            </div>
          </div>

          <div className="divide-y divide-border">
            {DUMMY_TOP_VULNS.map((vuln) => (
              <div key={vuln.id} className="py-3 flex items-center gap-3">
                <span className={`h-2 w-2 rounded-full flex-shrink-0 ${sevDot(vuln.severity)}`} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-mono font-medium text-foreground">{vuln.pkg}</span>
                    <span className="text-xs text-foreground-secondary">{vuln.version}</span>
                  </div>
                  <div className="text-xs text-foreground-secondary mt-0.5">{vuln.title}</div>
                </div>
                <div className="flex items-center gap-3 flex-shrink-0">
                  {vuln.reachable && <span className="text-xs text-foreground-secondary">reachable</span>}
                  <span className={`text-xs font-medium ${sevColor(vuln.severity)}`}>{vuln.severity}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Activity (2 cols) */}
        <div className="lg:col-span-2">
          <h2 className="text-sm font-semibold text-foreground mb-5">Recent Activity</h2>
          <div className="divide-y divide-border">
            {DUMMY_ACTIVITY.map((item) => (
              <div key={item.id} className="py-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-1.5 text-sm flex-wrap">
                      <span className="font-mono font-medium text-foreground">{item.pkg}</span>
                      <span className="text-foreground-secondary text-xs">{item.from}</span>
                      <ArrowRight className="h-3 w-3 text-foreground-muted flex-shrink-0" />
                      <span className="text-xs font-medium text-foreground">{item.to}</span>
                    </div>
                    <div className="flex items-center gap-2 mt-1.5">
                      <span className={`text-xs px-1.5 py-0.5 rounded border ${updateBadge(item.type)}`}>{item.type}</span>
                      {item.severity && (
                        <span className={`text-xs ${sevColor(item.severity)}`}>{item.severity} vuln fixed</span>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-foreground-muted flex-shrink-0 mt-0.5">{item.time}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </main>
  );
}
