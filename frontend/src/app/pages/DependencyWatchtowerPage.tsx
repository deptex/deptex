import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { useOutletContext } from 'react-router-dom';
import {
  Shield,
  ShieldOff,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Loader2,
  Terminal,
  Search,
  GitCompare,
  TowerControl,
  Timer,
  GitCommit,
  FileCode,
  Trash2,
  ArrowUpDown,
  Github,
  Check,
  PowerOff,
  ShieldCheck
} from 'lucide-react';
import { DependencyContextType } from './DependencyLayout';
import { Button } from '../../components/ui/button';
import { api, WatchtowerSummary, WatchtowerCommit, type ProjectDependency, type ProjectPermissions, type Organization } from '../../lib/api';
import { useToast } from '../../hooks/use-toast';
import { CommitSidebar } from '../../components/CommitSidebar';
import { getAnomalyColor, ANOMALY_HIGH_THRESHOLD } from '../../lib/watchtower-constants';
import { WatchtowerSkeleton } from '../../components/WatchtowerSkeleton';

// Feature card for not-watching state — step number, title, description
function FeatureCard({ step, title, description }: { step: number; title: string; description: string }) {
  return (
    <div className="flex flex-col rounded-lg border border-border bg-background-card p-4 shadow-sm h-full">
      <span className="inline-flex w-6 h-6 items-center justify-center rounded-md bg-background/80 text-xs font-medium text-foreground flex-shrink-0 mb-3">
        {step}
      </span>
      <h4 className="text-sm font-semibold text-foreground mb-1.5">{title}</h4>
      <p className="text-xs text-foreground-secondary leading-relaxed flex-1">{description}</p>
    </div>
  );
}

// Simple semver-style compare: true if versionA > versionB
function isNewerVersion(versionA: string | null | undefined, versionB: string | null | undefined): boolean {
  if (!versionA || !versionB) return false;
  const parse = (v: string) => v.replace(/^v/, '').split('.').map(p => parseInt(p, 10) || 0);
  const a = parse(versionA);
  const b = parse(versionB);
  const maxLen = Math.max(a.length, b.length);
  for (let i = 0; i < maxLen; i++) {
    const na = a[i] ?? 0;
    const nb = b[i] ?? 0;
    if (na > nb) return true;
    if (na < nb) return false;
  }
  return false;
}

function CommitTableRow({
  commit,
  onClick,
  onClearCommit,
  organizationId,
  projectId,
  dependencyId
}: {
  commit: WatchtowerCommit;
  onClick: (commit: WatchtowerCommit) => void;
  onClearCommit?: (commit: WatchtowerCommit) => void;
  organizationId?: string;
  projectId?: string;
  dependencyId?: string;
}) {
  const [isClearing, setIsClearing] = useState(false);
  const isHighRisk = commit.anomaly && commit.anomaly.score >= ANOMALY_HIGH_THRESHOLD;
  const canClear = onClearCommit && organizationId && projectId && dependencyId;
  const { toast } = useToast();

  const handleClearClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!canClear || isClearing) return;
    setIsClearing(true);
    api.clearWatchtowerCommit(organizationId!, projectId!, dependencyId!, commit.sha)
      .then(() => onClearCommit?.(commit))
      .catch((err: any) => {
        toast({ title: 'Error', description: err?.message ?? 'Failed to acknowledge commit', variant: 'destructive' });
        setIsClearing(false);
      });
  };

  return (
    <tr
      onClick={() => onClick(commit)}
      className={`group cursor-pointer transition-colors hover:bg-table-hover ${isHighRisk ? 'bg-error/5' : ''}`}
    >
      <td className="px-4 py-3 align-top">
        <div className="flex items-center gap-2">
          <div className="relative flex-shrink-0">
            <div className="w-8 h-8 rounded-full bg-background-subtle flex items-center justify-center border border-border">
              <Github className="h-4 w-4 text-foreground" />
            </div>
            {isHighRisk && (
              <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-error rounded-full animate-pulse border border-background-card" />
            )}
          </div>
          <div className="min-w-0">
            <span className="text-sm font-medium text-foreground block truncate">{commit.author}</span>
          </div>
        </div>
      </td>
      <td className="px-4 py-3 align-top min-w-0 max-w-md">
        <p className="text-sm text-foreground line-clamp-2">{commit.message}</p>
      </td>
      <td className="px-4 py-3 align-top text-xs whitespace-nowrap">
        <span className="text-success font-medium">+{commit.lines_added.toLocaleString()}</span>
        <span className="text-foreground-secondary mx-1">/</span>
        <span className="text-error font-medium">-{commit.lines_deleted.toLocaleString()}</span>
      </td>
      <td className="px-4 py-3 align-top text-xs text-foreground-secondary whitespace-nowrap">
        {commit.files_changed} files
      </td>
      <td className="px-4 py-3 align-top text-xs whitespace-nowrap">
        {commit.anomaly != null ? (
          <span className={`font-semibold tabular-nums ${getAnomalyColor(commit.anomaly.score)}`}>
            {commit.anomaly.score}
          </span>
        ) : (
          <span className="text-foreground-secondary">—</span>
        )}
      </td>
      <td className="px-4 py-3 align-top text-xs min-w-0 max-w-[12rem]">
        {commit.touches_imported_functions && commit.touches_imported_functions.length > 0 ? (
          <span className="text-foreground line-clamp-2" title={commit.touches_imported_functions.join(', ')}>
            {commit.touches_imported_functions.join(', ')}
          </span>
        ) : (
          <span className="text-foreground-secondary">—</span>
        )}
      </td>
      {canClear && (
        <td className="px-4 py-3 align-top w-10" onClick={(e) => e.stopPropagation()}>
          <Button
            variant="ghost"
            size="sm"
            className="opacity-0 group-hover:opacity-100 transition-opacity text-foreground-secondary hover:text-foreground hover:bg-background-subtle/30 h-7 w-7 p-0"
            onClick={handleClearClick}
            disabled={isClearing}
            title="Acknowledge"
          >
            {isClearing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Check className="h-3.5 w-3.5" />}
          </Button>
        </td>
      )}
    </tr>
  );
}

export interface WatchtowerContentProps {
  organizationId: string;
  projectId: string;
  dependency: ProjectDependency | null;
  userPermissions?: ProjectPermissions | null;
  organization?: Organization | null;
  /** Called when watching is toggled so the parent can update the dependencies list (e.g. sidebar icon). */
  onWatchingChange?: (dependencyId: string, is_watching: boolean) => void;
}

export function WatchtowerContent({
  organizationId,
  projectId,
  dependency,
  userPermissions = null,
  organization = null,
  onWatchingChange,
}: WatchtowerContentProps) {
  /** True when user has org manage_teams_and_projects or team manage_projects (owner team). Required for watchtower management actions. */
  const canManageWatchtower = Boolean(
    userPermissions?.can_manage_watchtower || organization?.permissions?.manage_teams_and_projects
  );
  const [isUpdating, setIsUpdating] = useState(false);
  const [localWatching, setLocalWatching] = useState<boolean | null>(null);
  const [summary, setSummary] = useState<WatchtowerSummary | null>(null);
  const [commits, setCommits] = useState<WatchtowerCommit[]>([]);
  const [commitsTotal, setCommitsTotal] = useState(0);
  const [loadingMoreCommits, setLoadingMoreCommits] = useState(false);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [loadingCommits, setLoadingCommits] = useState(false);
  const [sortBy, setSortBy] = useState<'recent' | 'anomaly'>('recent');
  const [commitsFilter, setCommitsFilter] = useState<'all' | 'touches_imported'>('all');
  const commitsFilterRef = useRef(commitsFilter);
  const [clearedAt, setClearedAt] = useState<Date | null>(null);
  const [clearingHistory, setClearingHistory] = useState(false);
  const [selectedCommit, setSelectedCommit] = useState<WatchtowerCommit | null>(null);
  const [repoFullName, setRepoFullName] = useState<string>('');
  const { toast } = useToast();

  const COMMITS_PAGE_SIZE = 50;
  /** Page size when sorting by anomaly (top 100, then next 100 on scroll) */
  const COMMITS_ANOMALY_PAGE_SIZE = 100;
  const hasMoreCommits = commits.length < commitsTotal;

  const isWatching = localWatching !== null ? localWatching : (dependency?.is_watching ?? false);

  /** Repo for commit/issue links: prefer dependency.github_url from dependencies table, else repoFullName from project. */
  const repoForCommitLink = useMemo(() => {
    if (dependency?.github_url) {
      const match = dependency.github_url.match(/github\.com\/([^/]+\/[^/]+?)(\.git)?$/);
      if (match) return match[1];
    }
    return repoFullName || 'owner/repo';
  }, [dependency?.github_url, repoFullName]);

  // Initialize clearedAt from dependency data
  useEffect(() => {
    if (dependency?.watchtower_cleared_at) {
      setClearedAt(new Date(dependency.watchtower_cleared_at));
    }
  }, [dependency?.watchtower_cleared_at]);

  // Fetch repository info
  useEffect(() => {
    // Priority 1: Use dependency's GitHub URL from database
    if (dependency?.github_url) {
      // Extract owner/repo from URL (e.g., https://github.com/owner/repo.git -> owner/repo)
      const match = dependency.github_url.match(/github\.com\/([^\/]+\/[^\/]+?)(\.git)?$/);
      if (match) {
        setRepoFullName(match[1]);
        return;
      }
    }

    // Priority 2: Fallback to project's repository (legacy behavior, mainly for monorepos/internal)
    if (organizationId && projectId) {
      api.getProjectRepositories(organizationId, projectId)
        .then(data => {
          if (data.connectedRepository) {
            setRepoFullName(data.connectedRepository.repo_full_name);
          }
        })
        .catch(console.error);
    }
  }, [organizationId, projectId, dependency?.github_url]);

  const refetchSummary = () => {
    if (isWatching && dependency?.name) {
      api.getWatchtowerSummary(dependency.name, dependency.id).catch(() => null).then(setSummary);
    }
  };

  // Keep ref in sync so in-flight request callbacks can ignore stale responses
  commitsFilterRef.current = commitsFilter;

  // Fetch watchtower data when watching or dependency changes: summary + commits. Does NOT run when only commitsFilter changes.
  useEffect(() => {
    if (!isWatching || !dependency?.name) return;
    const filterForThisRequest = commitsFilter;
    setLoadingSummary(true);
    setLoadingCommits(true);

    const prefetched = filterForThisRequest === 'all' && organizationId
      ? api.consumePrefetchedWatchtower(organizationId, dependency.id)
      : null;

    if (prefetched) {
      prefetched.then(([summaryData, commitsData]) => {
        setSummary(summaryData ?? null);
        if (commitsFilterRef.current === filterForThisRequest) {
          setCommits(commitsData?.commits ?? []);
          setCommitsTotal(commitsData?.total ?? 0);
        }
        if (commitsFilterRef.current === filterForThisRequest) {
          setLoadingSummary(false);
          setLoadingCommits(false);
        }
      });
      // Refresh from DB in background; backend updates Redis, frontend gets fresh data
      api.getWatchtowerSummary(dependency.name, dependency.id, { refresh: true })
        .catch(() => null)
        .then((freshSummary) => { if (freshSummary != null) setSummary(freshSummary); });
      return;
    }

    // Load summary (fast: cache or DB); then refresh from DB and replace if different (updates Redis on backend)
    api.getWatchtowerSummary(dependency.name, dependency.id)
      .catch(() => null)
      .then((summaryData) => {
        setSummary(summaryData ?? null);
        if (commitsFilterRef.current === filterForThisRequest) setLoadingSummary(false);
      });

    // Always fetch from DB in background; when it returns, update frontend (backend updates Redis)
    api.getWatchtowerSummary(dependency.name, dependency.id, { refresh: true })
      .catch(() => null)
      .then((freshSummary) => {
        if (freshSummary != null) setSummary(freshSummary);
      });

    // Load commits in parallel; they don't block the shell
    api.getWatchtowerCommits(
      dependency.name,
      COMMITS_PAGE_SIZE,
      0,
      organizationId || undefined,
      dependency.id,
      filterForThisRequest === 'touches_imported' ? 'touches_imported' : undefined
    ).catch(() => ({ commits: [], total: 0, limit: COMMITS_PAGE_SIZE, offset: 0 })).then((commitsData) => {
      if (commitsFilterRef.current === filterForThisRequest) {
        setCommits(commitsData.commits ?? []);
        setCommitsTotal(commitsData.total ?? 0);
        setLoadingCommits(false);
      }
    });
  }, [isWatching, dependency?.name, dependency?.id, organizationId]);

  // Poll summary + commits while status is pending/analyzing (from watched_packages) until ready or commits populated
  useEffect(() => {
    if (!isWatching || !dependency?.name || summary == null) return;
    const status = summary.status;
    if (status !== 'pending' && status !== 'analyzing') return;

    const poll = () => {
      const filterForThisRequest = commitsFilter;
      Promise.all([
        api.getWatchtowerSummary(dependency.name, dependency.id).catch(() => null),
        api.getWatchtowerCommits(
          dependency.name,
          COMMITS_PAGE_SIZE,
          0,
          organizationId || undefined,
          dependency.id,
          filterForThisRequest === 'touches_imported' ? 'touches_imported' : undefined
        ).catch(() => ({ commits: [], total: 0, limit: COMMITS_PAGE_SIZE, offset: 0 }))
      ]).then(([summaryData, commitsData]) => {
        if (summaryData) setSummary(summaryData);
        if (commitsFilterRef.current === filterForThisRequest) {
          setCommits(commitsData?.commits ?? []);
          setCommitsTotal(commitsData?.total ?? 0);
        }
      });
    };

    const intervalId = setInterval(poll, 3000);
    return () => clearInterval(intervalId);
  }, [isWatching, dependency?.name, dependency?.id, organizationId, summary?.status, commitsFilter]);

  // Clear watchtower data when disabling so re-enable doesn't flash old data
  useEffect(() => {
    if (!isWatching) {
      setSummary(null);
      setCommits([]);
      setCommitsTotal(0);
      setLoadingSummary(false);
      setLoadingCommits(false);
    }
  }, [isWatching]);

  // Refetch only the commits list when filter is toggled (keeps status/summary untouched).
  const refetchCommitsForFilter = useCallback((filter: 'all' | 'touches_imported', currentSortBy: 'recent' | 'anomaly') => {
    if (!dependency?.name || !dependency?.id) return;
    setLoadingCommits(true);
    const isAnomaly = currentSortBy === 'anomaly';
    const pageSize = isAnomaly ? COMMITS_ANOMALY_PAGE_SIZE : COMMITS_PAGE_SIZE;
    api.getWatchtowerCommits(
      dependency.name,
      pageSize,
      0,
      organizationId || undefined,
      dependency.id,
      filter === 'touches_imported' ? 'touches_imported' : undefined,
      isAnomaly ? 'anomaly' : undefined
    )
      .catch(() => ({ commits: [], total: 0, limit: pageSize, offset: 0 }))
      .then((data) => {
        setCommits(data.commits ?? []);
        setCommitsTotal(data.total ?? 0);
      })
      .finally(() => setLoadingCommits(false));
  }, [dependency?.name, dependency?.id, organizationId]);

  const loadMoreCommits = () => {
    if (!dependency?.name || loadingMoreCommits || !hasMoreCommits) return;
    setLoadingMoreCommits(true);
    const isAnomalySort = sortBy === 'anomaly';
    const pageSize = isAnomalySort ? COMMITS_ANOMALY_PAGE_SIZE : COMMITS_PAGE_SIZE;
    api.getWatchtowerCommits(
      dependency.name,
      pageSize,
      commits.length,
      organizationId || undefined,
      dependency.id,
      commitsFilter === 'touches_imported' ? 'touches_imported' : undefined,
      isAnomalySort ? 'anomaly' : undefined
    )
      .then((data) => {
        setCommits(prev => [...prev, ...(data.commits || [])]);
        setCommitsTotal(data.total ?? commitsTotal);
      })
      .catch(() => toast({ title: 'Error', description: 'Failed to load more commits' }))
      .finally(() => setLoadingMoreCommits(false));
  };

  const observerTarget = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const observer = new IntersectionObserver(
      entries => {
        if (entries[0].isIntersecting && hasMoreCommits && !loadingMoreCommits) {
          loadMoreCommits();
        }
      },
      { threshold: 0.1 }
    );

    if (observerTarget.current) {
      observer.observe(observerTarget.current);
    }

    return () => {
      if (observerTarget.current) {
        observer.unobserve(observerTarget.current);
      }
    };
  }, [hasMoreCommits, loadingMoreCommits, loadMoreCommits]);

  const handleToggleWatching = async () => {
    if (!dependency || !organizationId || !projectId) return;
    if (!canManageWatchtower) {
      toast({ title: 'Permission denied', description: 'You do not have permission to do this.', variant: 'destructive' });
      return;
    }

    setIsUpdating(true);
    try {
      const result = await api.updateDependencyWatching(
        organizationId,
        projectId,
        dependency.id,
        !isWatching
      );
      setLocalWatching(result.is_watching);
      toast({
        title: result.is_watching ? 'Watchtower Enabled' : 'Watchtower Disabled',
        description: result.is_watching
          ? `Now monitoring ${dependency.name} for supply chain threats.`
          : `Stopped monitoring ${dependency.name}.`,
      });
      onWatchingChange?.(dependency.id, result.is_watching);
      // Refetch dependencies so list/cache stay in sync (org-level watching)
      const deps = await api.getProjectDependencies(organizationId, projectId);
      const updated = deps.find(d => d.id === dependency.id);
      if (updated) api.cacheDependency(projectId, updated);
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to update watching status',
      });
    } finally {
      setIsUpdating(false);
    }
  };


  // Filtered and sorted commits (backend filters by cleared_at + cleared commits when organizationId is passed)
  const filteredCommits = useMemo(() => {
    let result = commits;
    if (sortBy === 'anomaly') {
      result = [...result].sort((a, b) => (b.anomaly?.score || 0) - (a.anomaly?.score || 0));
    } else {
      result = [...result].sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
    }
    return result;
  }, [commits, sortBy]);

  const handleClearCommit = (commit: WatchtowerCommit) => {
    setCommits(prev => prev.filter(c => c.sha !== commit.sha));
    if (selectedCommit?.sha === commit.sha) setSelectedCommit(null);
    toast({ title: 'Commit acknowledged', description: 'Removed from the list.' });
  };

  // Handle clear commits
  const handleClearCommits = async () => {
    if (!dependency || !organizationId || !projectId) return;

    setClearingHistory(true);
    try {
      const result = await api.clearWatchtowerCommits(organizationId, projectId, dependency.id);
      setClearedAt(new Date(result.watchtower_cleared_at));
      toast({
        title: 'Commits Cleared',
        description: 'All current commits have been marked as reviewed. Only new commits will appear.',
      });
      // Refetch dependencies so cache has latest watchtower_cleared_at (org-level)
      const deps = await api.getProjectDependencies(organizationId, projectId);
      const updated = deps.find(d => d.id === dependency.id);
      if (updated) api.cacheDependency(projectId, updated);
      // Refetch commits so list reflects cleared state
      api.getWatchtowerCommits(
        dependency.name,
        COMMITS_PAGE_SIZE,
        0,
        organizationId,
        dependency.id,
        commitsFilter === 'touches_imported' ? 'touches_imported' : undefined
      ).then((data) => {
        setCommits(data.commits?.length > 0 ? data.commits : []);
        setCommitsTotal(data.total ?? 0);
      }).catch(() => { });
    } catch (error: any) {
      toast({
        title: 'Error',
        description: error.message || 'Failed to clear commits',
      });
    } finally {
      setClearingHistory(false);
    }
  };

  // Status: version policy (above_allowed, outdated), security checks (unsafe/safe), quarantine (not-good), or fine
  type StatusState = 'fine' | 'safe' | 'unsafe' | 'not-good' | 'above_allowed' | 'outdated' | 'new_version_quarantine';
  const statusState = useMemo((): StatusState => {
    if (!summary || summary.status !== 'ready') return 'fine';

    const cur = dependency?.version;
    const latestAllowed = summary.latest_allowed_version ?? null;
    const latestVersion = summary.latest_version ?? null;

    // Version policy: project version above org's latest allowed
    if (cur && latestAllowed && isNewerVersion(cur, latestAllowed)) return 'above_allowed';

    // Current version in quarantine
    if (summary.is_current_version_quarantined) return 'not-good';

    // Security checks failed
    const checks = [
      summary.registry_integrity_status,
      summary.install_scripts_status,
      summary.entropy_analysis_status
    ];
    if (checks.some(s => s === 'fail')) return 'unsafe';
    if (checks.every(s => s === 'pass')) return 'safe';

    // Newer safe version available (outdated)
    if (cur && latestVersion && isNewerVersion(latestVersion, cur)) return 'outdated';

    return 'fine';
  }, [summary, dependency?.version]);

  // Days until current version exits quarantine (for subtext when is_current_version_quarantined)
  const currentQuarantineDaysRemaining = useMemo(() => {
    if (!summary?.is_current_version_quarantined || !summary?.quarantine_until) return null;
    const until = new Date(summary.quarantine_until);
    const now = Date.now();
    if (until.getTime() <= now) return 0;
    return Math.ceil((until.getTime() - now) / 86400000);
  }, [summary?.is_current_version_quarantined, summary?.quarantine_until]);

  const versionsInQuarantine = useMemo(() => {
    const out: string[] = [];
    if (summary?.is_current_version_quarantined && dependency?.version) out.push(dependency.version);
    return out;
  }, [summary?.is_current_version_quarantined, dependency?.version]);

  const allowedVersion = summary?.latest_allowed_version ?? null;
  const quarantineDaysRemaining = summary?.quarantine_next_release ? currentQuarantineDaysRemaining : null;

  const [quarantineUpdating, setQuarantineUpdating] = useState(false);
  const handleToggleQuarantineNext = async () => {
    if (!organizationId || !projectId || !dependency?.id) return;
    setQuarantineUpdating(true);
    try {
      const next = !(summary?.quarantine_next_release ?? false);
      await api.patchWatchlistQuarantine(organizationId, projectId, dependency.id, next);
      setSummary(prev => prev ? { ...prev, quarantine_next_release: next } : null);
      refetchSummary();
      toast({
        title: next ? 'Quarantining next version' : 'No longer quarantining next version',
        description: next ? 'The next release will be in quarantine for 7 days.' : undefined,
      });
    } catch (e: any) {
      toast({ title: 'Error', description: e.message ?? 'Failed to update quarantine', variant: 'destructive' });
    } finally {
      setQuarantineUpdating(false);
    }
  };

  const [bumpLoading, setBumpLoading] = useState(false);
  const [decreaseLoading, setDecreaseLoading] = useState(false);

  const handleDecreaseVersion = async () => {
    if (!organizationId || !projectId || !dependency?.id) return;
    setDecreaseLoading(true);
    try {
      const { pr_url, already_exists } = await api.createWatchtowerDecreasePR(organizationId, projectId, dependency.id);
      toast({
        title: already_exists ? 'PR already exists' : 'Pull request created',
        description: already_exists ? 'Opening existing decrease PR.' : 'Open the PR to review and merge the version decrease.',
      });
      window.open(pr_url, '_blank');
      const next = await api.getWatchtowerSummary(dependency.name, dependency.id).catch(() => null);
      if (next) setSummary(next);
    } catch (e: any) {
      toast({ title: 'Error', description: e.message ?? 'Failed to create decrease PR', variant: 'destructive' });
    } finally {
      setDecreaseLoading(false);
    }
  };

  const handleBumpVersion = async () => {
    if (!organizationId || !projectId || !dependency?.id) return;
    setBumpLoading(true);
    try {
      const { pr_url, already_exists } = await api.createWatchtowerBumpPR(organizationId, projectId, dependency.id);
      toast({
        title: already_exists ? 'PR already exists' : 'Pull request created',
        description: already_exists ? 'Opening existing bump PR.' : 'Open the PR to review and merge the version bump.',
      });
      window.open(pr_url, '_blank');
      const next = await api.getWatchtowerSummary(dependency.name, dependency.id).catch(() => null);
      if (next) setSummary(next);
    } catch (e: any) {
      toast({ title: 'Error', description: e.message ?? 'Failed to create bump PR', variant: 'destructive' });
    } finally {
      setBumpLoading(false);
    }
  };

  // Only block on dependency; show shell immediately when watching (progressive loading)
  if (!dependency) {
    return <WatchtowerSkeleton />;
  }

  // Not watching state — minimal hero + step cards (reference-style)
  if (!isWatching) {
    return (
      <main className="relative min-h-[calc(100vh-3rem)] overflow-hidden bg-background-content">
        {/* Subtle dashboard preview image — no overlay */}
        <div
          className="absolute inset-0 bg-cover bg-center bg-no-repeat opacity-25"
          style={{ backgroundImage: 'url(/images/watchtower-dashboard-preview.png)', filter: 'blur(3px)' }}
        />
        <div className="relative z-10 mx-auto max-w-4xl px-4 sm:px-6 lg:px-8 py-12 flex flex-col items-center">
          <div className="text-center mb-10">
            <h1 className="text-xl font-semibold text-foreground mb-2">
              Watchtower Forensics
            </h1>
            <p className="text-sm text-foreground-secondary max-w-md mx-auto mb-6">
              Proactive supply chain defense. Analyze commits, detect anomalies, and catch threats before CVEs exist.
            </p>
            <div className="flex flex-wrap items-center justify-center gap-2">
              <Button
                onClick={handleToggleWatching}
                disabled={isUpdating}
                size="sm"
                variant="secondary"
                className="gap-2 bg-background-subtle border border-border hover:bg-background-subtle/80 text-foreground-secondary hover:text-foreground"
              >
                {isUpdating ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <ShieldCheck className="h-4 w-4 text-green-600" />
                )}
                Enable Watchtower
              </Button>
              <Button
                variant="outline"
                size="sm"
                className="gap-2 border-border text-foreground-secondary hover:text-foreground hover:bg-background-subtle/50"
                asChild
              >
                <a href="/docs/watchtower" target="_blank" rel="noopener noreferrer">Read our study</a>
              </Button>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
            <FeatureCard
              step={1}
              title="Registry Integrity"
              description="Compares registry tarball against git source for 100% integrity."
            />
            <FeatureCard
              step={2}
              title="Install Script Analysis"
              description="Flags dangerous capabilities like network calls or shell execution."
            />
            <FeatureCard
              step={3}
              title="Entropy Analysis"
              description="Detects hidden payloads and obfuscated malicious code."
            />
            <FeatureCard
              step={4}
              title="Commit Anomaly Detection"
              description="Detection of suspicious contributor behavior patterns."
            />
          </div>
        </div>
      </main>
    );
  }

  // Status card component for the three checks (showSkeleton = loading from API; otherwise Pending = analyzing)
  const StatusCard = ({
    icon: Icon,
    title,
    status,
    description,
    reason,
    showSkeleton
  }: {
    icon: React.ElementType;
    title: string;
    status: 'pass' | 'warning' | 'fail' | null | undefined;
    description: string;
    reason?: string | null;
    showSkeleton?: boolean;
  }) => {
    const statusConfig = {
      pass: { color: 'text-success', barBg: 'bg-success', label: 'Pass', width: '100%' },
      warning: { color: 'text-warning', barBg: 'bg-warning', label: 'Warning', width: '50%' },
      fail: { color: 'text-error', barBg: 'bg-error', label: 'Fail', width: '15%' },
    };
    const config = status ? statusConfig[status] : { color: 'text-foreground-secondary', barBg: 'bg-foreground-secondary/30', label: 'Pending', width: '30%' };

    if (showSkeleton) {
      return (
        <div className="bg-background-card border border-border rounded-lg pt-4 px-4 pb-0 flex flex-col">
          <div className="flex items-start justify-between mb-3">
            <div className="w-10 h-10 flex items-center justify-start">
              <Icon className="h-6 w-6 text-foreground-secondary/50" />
            </div>
            <div className="h-4 w-16 bg-muted rounded animate-pulse" />
          </div>
          <h4 className="text-sm font-medium text-foreground mb-1">{title}</h4>
          <p className="text-xs text-foreground-secondary leading-relaxed flex-1">{description}</p>
          <div className="mt-3 -mx-4 px-4 pt-3 pb-3 border-t border-border bg-background-card-header rounded-b-lg">
            <div className="h-1 w-full bg-background-subtle rounded-full overflow-hidden">
              <div className="h-full bg-muted rounded-full animate-pulse" style={{ width: '33%' }} />
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="bg-background-card border border-border rounded-lg pt-4 px-4 pb-0 flex flex-col">
        <div className="flex items-start justify-between mb-3">
          <div className="w-10 h-10 flex items-center justify-start">
            <Icon className="h-6 w-6 text-foreground-secondary" />
          </div>
          <span className={`text-xs font-medium ${config.color}`}>
            {status ? (
              <>
                {status === 'pass' && <CheckCircle2 className="h-3 w-3 inline mr-1" />}
                {status === 'warning' && <AlertTriangle className="h-3 w-3 inline mr-1" />}
                {status === 'fail' && <XCircle className="h-3 w-3 inline mr-1" />}
                {config.label}
              </>
            ) : (
              <>
                <Loader2 className="h-3 w-3 inline mr-1 animate-spin" />
                Pending
              </>
            )}
          </span>
        </div>
        <h4 className="text-sm font-medium text-foreground mb-1">{title}</h4>
        <p className="text-xs text-foreground-secondary leading-relaxed flex-1">{description}</p>
        {/* Show reason for warning/fail statuses */}
        {reason && (status === 'warning' || status === 'fail') && (
          <div className={`mt-2 px-2 py-1.5 rounded text-xs leading-relaxed ${status === 'fail'
            ? 'bg-error/10 text-error border border-error/20'
            : 'bg-warning/10 text-warning border border-warning/20'
          }`}>
            {reason}
          </div>
        )}
        {/* Progress bar in table-header-colour strip, full-width separator */}
        <div className="mt-3 -mx-4 px-4 pt-3 pb-3 border-t border-border bg-background-card-header rounded-b-lg">
          <div className="h-1 w-full bg-background-subtle rounded-full overflow-hidden">
            <div className={`h-full ${config.barBg} rounded-full`} style={{ width: config.width }} />
          </div>
        </div>
      </div>
    );
  };

  // Watching state - show dashboard
  return (
    <main className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 py-6 bg-background-content min-h-[calc(100vh-3rem)]">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <img src="/images/npm_icon.png" alt="NPM" className="w-10 h-10" />
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <h2 className="text-lg font-semibold text-foreground">{dependency?.name}</h2>
              <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-primary/15 text-green-600 border border-primary/30 text-xs font-medium">
                <Shield className="h-3 w-3" />
                Watching
              </span>
              {canManageWatchtower && (
                <Button
                  variant="outline"
                  size="sm"
                  className={summary?.quarantine_next_release
                    ? 'gap-1.5 border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-400 hover:bg-amber-500/25 hover:border-amber-500/50'
                    : 'gap-1.5 border-warning/20 bg-warning/5 text-warning hover:bg-warning/10 hover:border-warning/30'
                  }
                  onClick={handleToggleQuarantineNext}
                  disabled={quarantineUpdating || loadingSummary}
                >
                  {(quarantineUpdating || loadingSummary) ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldOff className="h-3.5 w-3.5" />}
                  {summary?.quarantine_next_release ? 'Quarantining next version' : 'Quarantine next version'}
                </Button>
              )}
            </div>
            <span className="text-sm text-foreground-secondary">v{dependency?.version}</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {canManageWatchtower && (
            <Button
              variant="outline"
              size="sm"
              className="gap-2"
              onClick={handleToggleWatching}
              disabled={isUpdating}
            >
              {isUpdating ? <Loader2 className="h-4 w-4 animate-spin" /> : <PowerOff className="h-4 w-4" />}
              Disable
            </Button>
          )}
        </div>
      </div>

      {/* Status Banner: skeleton when loading (no summary / not analyzing); keep "Analysis in progress" text when analyzing. */}
      {loadingSummary && !(summary?.status === 'pending' || summary?.status === 'analyzing') ? (
        <div className="rounded-xl p-5 mb-6 bg-background-card border border-border">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex-shrink-0 bg-muted animate-pulse" />
            <div className="flex-1 min-w-0 space-y-2">
              <div className="h-5 w-48 bg-muted rounded animate-pulse" />
              <div className="h-4 w-72 max-w-full bg-muted rounded animate-pulse" />
            </div>
          </div>
        </div>
      ) : (summary?.status === 'pending' || summary?.status === 'analyzing') ? (
        <div className="rounded-xl p-5 mb-6 bg-gradient-to-r from-foreground-secondary/15 via-foreground-secondary/10 to-foreground-secondary/5 border border-border">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 bg-foreground-secondary/20">
              <Loader2 className="h-6 w-6 text-foreground-secondary animate-spin" />
            </div>
            <div className="flex-1 min-w-0">
              <h3 className="text-lg font-bold mb-1 text-foreground-secondary">Loading status</h3>
              <p className="text-sm text-foreground-secondary">Analysis in progress. Status and checks will appear when ready.</p>
            </div>
          </div>
        </div>
      ) : (
        <div className={`rounded-xl p-5 mb-6 ${statusState === 'above_allowed' || statusState === 'unsafe' || statusState === 'not-good'
          ? 'bg-gradient-to-r from-error/15 via-error/8 to-error/5 border-2 border-error/45'
          : statusState === 'outdated'
            ? 'bg-gradient-to-r from-foreground-secondary/15 via-foreground-secondary/10 to-foreground-secondary/5 border border-border'
            : 'bg-gradient-to-r from-success/15 via-success/8 to-success/5 border-2 border-success/45'
          }`}>
          <div className="flex items-center gap-4">
            <div className={`w-12 h-12 rounded-xl flex items-center justify-center flex-shrink-0 ${statusState === 'above_allowed' || statusState === 'unsafe' || statusState === 'not-good' ? 'bg-error/15' : statusState === 'outdated' ? 'bg-foreground-secondary/20' : 'bg-success/15'
              }`}>
              {statusState === 'above_allowed' || statusState === 'unsafe' || statusState === 'not-good' ? (
                <XCircle className="h-6 w-6 text-error" />
              ) : statusState === 'outdated' ? (
                <AlertTriangle className="h-6 w-6 text-foreground-secondary" />
              ) : (
                <CheckCircle2 className="h-6 w-6 text-success" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <h3 className={`text-lg font-bold mb-1 ${statusState === 'above_allowed' || statusState === 'unsafe' || statusState === 'not-good' ? 'text-error' : statusState === 'outdated' ? 'text-foreground-secondary' : 'text-success'
                }`}>
                {statusState === 'above_allowed'
                  ? 'STATUS: NOT GOOD'
                  : statusState === 'unsafe' || statusState === 'not-good'
                    ? 'STATUS: NOT GOOD'
                    : statusState === 'outdated'
                      ? 'NEWER SAFE VERSION AVAILABLE'
                      : 'STATUS: FINE'}
              </h3>
              <p className="text-sm text-foreground-secondary">
                {statusState === 'above_allowed'
                  ? `Project version is higher than the organization's latest allowed version (v${allowedVersion ?? '—'}). Decrease version to comply.`
                  : statusState === 'unsafe' || statusState === 'not-good'
                    ? 'One or more security checks failed. See the cards below for details.'
                    : statusState === 'outdated'
                      ? `A newer safe version (v${allowedVersion ?? summary?.latest_version}) is available. Bump when ready.`
                      : statusState === 'new_version_quarantine'
                        ? `New version in quarantine for ${quarantineDaysRemaining !== null ? quarantineDaysRemaining : 0} more day${quarantineDaysRemaining === 1 ? '' : 's'}.`
                        : 'Package has passed all security checks. No immediate threats detected in the current analysis.'}
                {summary?.is_current_version_quarantined && currentQuarantineDaysRemaining !== null && (
                  <> Next version will be out of quarantine in {currentQuarantineDaysRemaining} day{currentQuarantineDaysRemaining === 1 ? '' : 's'}.</>
                )}
              </p>
            </div>
            {(statusState === 'above_allowed' || statusState === 'outdated') && (
              <div className="flex-shrink-0 flex items-center">
                {statusState === 'above_allowed' ? (
                  summary?.decrease_pr_url ? (
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-1.5 border-error/30 bg-error/10 text-error hover:bg-error/20"
                      onClick={() => window.open(summary.decrease_pr_url!, '_blank')}
                      title="Open existing decrease PR"
                    >
                      View PR
                    </Button>
                  ) : (
                    <Button
                      variant="outline"
                      size="sm"
                      className="gap-1.5 border-error/30 bg-error/10 text-error hover:bg-error/20"
                      onClick={handleDecreaseVersion}
                      disabled={decreaseLoading || !allowedVersion}
                      title={!allowedVersion ? 'No latest allowed version set for this package' : undefined}
                    >
                      {decreaseLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Decrease version'}
                    </Button>
                  )
                ) : loadingSummary ? (
                  <Button variant="outline" size="sm" disabled className="gap-1.5">
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Loading
                  </Button>
                ) : summary?.bump_pr_url ? (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => window.open(summary.bump_pr_url!, '_blank')}
                    title="Open existing bump PR"
                  >
                    View PR
                  </Button>
                ) : (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleBumpVersion}
                    disabled={bumpLoading || !allowedVersion}
                    title={!allowedVersion ? 'No latest allowed version set for this package' : undefined}
                  >
                    {bumpLoading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Bump'}
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Three Status Cards: skeletons when loading (not analyzing); Pending + spinner when analyzing */}
      {(() => {
        const isAnalyzing = summary?.status === 'pending' || summary?.status === 'analyzing';
        const showCardSkeleton = loadingSummary && !isAnalyzing;
        return (
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <StatusCard
              icon={GitCompare}
              title="Registry Integrity"
              status={loadingSummary ? undefined : summary?.registry_integrity_status}
              description="Compares registry tarball against git source to verify 100% code integrity."
              reason={summary?.registry_integrity_reason}
              showSkeleton={showCardSkeleton}
            />
            <StatusCard
              icon={Terminal}
              title="Install Scripts"
              status={loadingSummary ? undefined : summary?.install_scripts_status}
              description="Analyzes install scripts for dangerous capabilities like network calls or shell execution."
              reason={summary?.install_scripts_reason}
              showSkeleton={showCardSkeleton}
            />
            <StatusCard
              icon={Search}
              title="Entropy Analysis"
              status={loadingSummary ? undefined : summary?.entropy_analysis_status}
              description="Detects hidden payloads and obfuscated malicious code through entropy scanning."
              reason={summary?.entropy_analysis_reason}
              showSkeleton={showCardSkeleton}
            />
          </div>
        );
      })()}

      {/* Commits Section */}
      <div className="mt-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <TowerControl className="h-5 w-5 text-foreground-secondary" />
            <h3 className="text-base font-semibold text-foreground">Recent Commits</h3>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            {/* Filter: All / Touches my imports */}
            {organizationId && dependency?.id && (
              <Button
                variant="outline"
                size="sm"
                onClick={() => {
                  const next = commitsFilter === 'all' ? 'touches_imported' : 'all';
                  setCommitsFilter(next);
                  refetchCommitsForFilter(next, sortBy);
                }}
                className="h-8 gap-2 px-3 pl-2.5"
              >
                <FileCode className="h-3.5 w-3.5 text-foreground-secondary" />
                <span className="text-foreground-secondary">Filter:</span>
                <span className="font-medium">{commitsFilter === 'all' ? 'All commits' : 'Touches my imports'}</span>
              </Button>
            )}

            {/* Sort Toggle Button — anomaly sort: top 100 by score from API, then next 100 on scroll */}
            <Button
              variant="outline"
              size="sm"
              onClick={async () => {
                if (!dependency?.name || !dependency?.id) return;
                if (sortBy === 'recent') {
                  setSortBy('anomaly');
                  setLoadingCommits(true);
                  const data = await api.getWatchtowerCommits(
                    dependency.name,
                    COMMITS_ANOMALY_PAGE_SIZE,
                    0,
                    organizationId || undefined,
                    dependency.id,
                    commitsFilter === 'touches_imported' ? 'touches_imported' : undefined,
                    'anomaly'
                  ).catch(() => ({ commits: [], total: 0, limit: COMMITS_ANOMALY_PAGE_SIZE, offset: 0 }));
                  setCommits(data.commits ?? []);
                  setCommitsTotal(data.total ?? 0);
                  setLoadingCommits(false);
                } else {
                  setSortBy('recent');
                  setLoadingCommits(true);
                  const data = await api.getWatchtowerCommits(
                    dependency.name,
                    COMMITS_PAGE_SIZE,
                    0,
                    organizationId || undefined,
                    dependency.id,
                    commitsFilter === 'touches_imported' ? 'touches_imported' : undefined
                  ).catch(() => ({ commits: [], total: 0, limit: COMMITS_PAGE_SIZE, offset: 0 }));
                  setCommits(data.commits ?? []);
                  setCommitsTotal(data.total ?? 0);
                  setLoadingCommits(false);
                }
              }}
              className="h-8 gap-2 px-3 pl-2.5"
            >
              <ArrowUpDown className="h-3.5 w-3.5 text-foreground-secondary" />
              <span className="text-foreground-secondary">Sort:</span>
              <span className="font-medium">{sortBy === 'recent' ? 'Most Recent' : 'Anomaly Score'}</span>
            </Button>

            {/* Clear Button - only for users with watchtower management permission */}
            {canManageWatchtower && (
              <Button
                variant="outline"
                size="sm"
                onClick={handleClearCommits}
                disabled={clearingHistory}
                className="group h-8 gap-2 px-3 pl-2.5 hover:bg-destructive/5 hover:text-destructive hover:border-destructive/30 transition-colors"
              >
                {clearingHistory ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-foreground-secondary" />
                ) : (
                  <Trash2 className="h-3.5 w-3.5 text-foreground-secondary group-hover:text-destructive transition-colors" />
                )}
                <span>Clear Commits</span>
              </Button>
            )}
          </div>
        </div>

        {/* Commits - each day has its own table, no card wrapper */}
        <div className="max-h-[600px] overflow-y-auto custom-scrollbar">
          {loadingCommits ? (
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-background-card-header">
                  <tr className="border-b border-border">
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Author
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider max-w-md">
                      Message
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      + / −
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Files
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Anomaly
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      My imported functions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <tr key={i} className="animate-pulse">
                      <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-4 max-w-md bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-16 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-12 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-8 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-32 bg-muted rounded" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (summary?.status === 'pending' || summary?.status === 'analyzing') && commits.length === 0 ? (
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-background-card-header">
                  <tr className="border-b border-border">
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Author
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider max-w-md">
                      Message
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      + / −
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Files
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Anomaly
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      My imported functions
                    </th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {[1, 2, 3, 4, 5].map((i) => (
                    <tr key={i} className="animate-pulse">
                      <td className="px-4 py-3"><div className="h-4 w-24 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-4 max-w-md bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-16 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-12 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-8 bg-muted rounded" /></td>
                      <td className="px-4 py-3"><div className="h-3 w-32 bg-muted rounded" /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : filteredCommits.length === 0 ? (
            <div className="px-6 py-12 text-center">
              <CheckCircle2 className="h-10 w-10 text-success/50 mx-auto mb-3" />
              <p className="text-sm font-medium text-foreground mb-1">
                {commitsFilter === 'touches_imported' ? 'No commits touch your imports' : 'No new commits since last review'}
              </p>
              <p className="text-xs text-foreground-secondary">
                {commitsFilter === 'touches_imported' ? 'No commits in this range touch functions your project imports.' : 'All commits have been cleared. New commits will appear here.'}
              </p>
            </div>
          ) : sortBy === 'anomaly' ? (
            <div className="bg-background-card border border-border rounded-lg overflow-hidden">
              <table className="w-full">
                <thead className="bg-background-card-header">
                  <tr className="border-b border-border">
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Author
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider max-w-md">
                      Message
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      + / −
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Files
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      Anomaly
                    </th>
                    <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                      My imported functions
                    </th>
                    {canManageWatchtower && <th className="w-10 px-4 py-3" aria-label="Actions" />}
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {filteredCommits.map((commit) => (
                    <CommitTableRow
                      key={commit.id}
                      commit={commit}
                      onClick={setSelectedCommit}
                      onClearCommit={canManageWatchtower ? handleClearCommit : undefined}
                      organizationId={organizationId ?? undefined}
                      projectId={projectId ?? undefined}
                      dependencyId={dependency?.id}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            (() => {
              const groupedByDate: Record<string, WatchtowerCommit[]> = {};
              filteredCommits.forEach((commit) => {
                const dateKey = new Date(commit.timestamp).toLocaleDateString('en-US', {
                  month: 'short',
                  day: 'numeric',
                  year: 'numeric'
                });
                if (!groupedByDate[dateKey]) groupedByDate[dateKey] = [];
                groupedByDate[dateKey].push(commit);
              });
              const sortedDates = Object.keys(groupedByDate).sort(
                (a, b) => new Date(b).getTime() - new Date(a).getTime()
              );

              return (
                <div className="space-y-6">
                  {sortedDates.map((date) => (
                    <div key={date}>
                      <div className="flex items-center gap-3 mb-3">
                        <GitCommit className="h-4 w-4 text-foreground-secondary flex-shrink-0" />
                        <h3 className="text-sm font-medium text-foreground-secondary">
                          Commits on {date}
                        </h3>
                      </div>
                      <div className="bg-background-card border border-border rounded-lg overflow-hidden">
                        <table className="w-full">
                          <thead className="bg-background-card-header">
                            <tr className="border-b border-border">
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                Author
                              </th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider max-w-md">
                                Message
                              </th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                + / −
                              </th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                Files
                              </th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                Anomaly
                              </th>
                              <th className="text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider">
                                My imported functions
                              </th>
                              {canManageWatchtower && <th className="w-10 px-4 py-3" aria-label="Actions" />}
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-border">
                            {groupedByDate[date].map((commit) => (
                              <CommitTableRow
                                key={commit.id}
                                commit={commit}
                                onClick={setSelectedCommit}
                                onClearCommit={canManageWatchtower ? handleClearCommit : undefined}
                                organizationId={organizationId ?? undefined}
                                projectId={projectId ?? undefined}
                                dependencyId={dependency?.id}
                              />
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  ))}
                </div>
              );
            })()
          )}
          {!loadingCommits && filteredCommits.length > 0 && hasMoreCommits && (
            <div ref={observerTarget} className="flex justify-center py-4 min-h-[50px] border-t border-border">
              {loadingMoreCommits && (
                <div className="flex items-center gap-2 text-foreground-secondary text-sm">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  <span>Loading more commits...</span>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Commit Sidebar */}
      {selectedCommit && dependency && (
          <CommitSidebar
            commit={selectedCommit}
            packageName={dependency.name}
            repoFullName={repoForCommitLink}
            githubUrl={dependency.github_url}
            onClose={() => setSelectedCommit(null)}
            organizationId={organizationId}
            projectId={projectId}
            dependencyId={dependency.id}
            quarantineNextRelease={summary?.quarantine_next_release}
            onQuarantineToggle={refetchSummary}
            onClearCommit={canManageWatchtower ? handleClearCommit : undefined}
            canManageWatchtower={canManageWatchtower}
          />
      )}
    </main>
  );
}

export default function DependencyWatchtowerPage() {
  const { dependency, organizationId, projectId, userPermissions, organization } = useOutletContext<DependencyContextType>();
  return (
    <WatchtowerContent
      organizationId={organizationId ?? ''}
      projectId={projectId ?? ''}
      dependency={dependency}
      userPermissions={userPermissions}
      organization={organization}
    />
  );
}
