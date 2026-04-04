import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useOutletContext, useNavigate, useParams, useLocation } from 'react-router-dom';
import { Search, SlidersHorizontal, TowerControl, Loader2, PanelLeftClose, PanelLeftOpen, Package, LayoutDashboard, GitBranch, MessageSquareText, RefreshCw, ShieldAlert } from 'lucide-react';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { isExtractionOngoing as checkExtractionOngoing } from '../../lib/extractionStatus';
import { ExtractionProgressCard } from '../../components/ExtractionProgressCard';
import { api, ProjectWithRole, ProjectPermissions, ProjectDependency, ProjectEffectivePolicies, ProjectImportStatus } from '../../lib/api';
import { Tooltip, TooltipTrigger, TooltipContent } from '../../components/ui/tooltip';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
  DropdownMenuLabel,
} from '../../components/ui/dropdown-menu';
import { Checkbox } from '../../components/ui/checkbox';
import { cn } from '../../lib/utils';
import PackageOverview from '../../components/PackageOverview';
import { PackageOverviewSkeleton } from '../../components/PackageOverviewSkeleton';
import { SupplyChainContent } from './DependencySupplyChainPage';
import DependencyNotesSidebar from '../../components/DependencyNotesSidebar';

interface ProjectContextType {
  project: ProjectWithRole | null;
  reloadProject: () => Promise<void>;
  setProjectAutoBump: (value: boolean) => void;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
}

/** Props for standalone use (e.g. org overview project sidebar). When embedInSidebar is true, selection is internal state. */
export interface ProjectDependenciesContentProps {
  project: ProjectWithRole | null;
  organizationId: string;
  userPermissions: ProjectPermissions | null;
  reloadProject: () => Promise<void>;
  embedInSidebar?: boolean;
}

function getVulnSeverityInfo(dep: ProjectDependency): { maxSeverity: 'critical' | 'high' | 'medium' | 'low'; total: number; colorClass: string; label: string } | null {
  const a = dep.analysis;
  if (!a) return null;
  const critical = a.critical_vulns ?? 0;
  const high = a.high_vulns ?? 0;
  const medium = a.medium_vulns ?? 0;
  const low = a.low_vulns ?? 0;
  const total = critical + high + medium + low;
  if (total === 0) return null;
  const maxSeverity: 'critical' | 'high' | 'medium' | 'low' =
    critical > 0 ? 'critical' : high > 0 ? 'high' : medium > 0 ? 'medium' : 'low';
  const colorClass =
    maxSeverity === 'critical'
      ? 'text-destructive'
      : maxSeverity === 'high'
        ? 'text-orange-600 dark:text-orange-400'
        : maxSeverity === 'medium'
          ? 'text-warning'
          : 'text-foreground-secondary';
  const parts: string[] = [];
  if (critical) parts.push(`${critical} critical`);
  if (high) parts.push(`${high} high`);
  if (medium) parts.push(`${medium} medium`);
  if (low) parts.push(`${low} low`);
  const label = `${total} ${total === 1 ? 'vulnerability' : 'vulnerabilities'} (${parts.join(', ')})`;
  return { maxSeverity, total, colorClass, label };
}

function normalizeLicenseForComparison(license: string): string {
  return license
    .toLowerCase()
    .replace(/[-_]/g, ' ')
    .replace(/['"()]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
}

function extractLicenseKey(license: string): string {
  const normalized = normalizeLicenseForComparison(license);
  const parts: string[] = [];
  if (normalized.includes('0bsd') || normalized.includes('0 bsd') || normalized.includes('zero clause')) parts.push('0bsd');
  else if (normalized.includes('bsd')) {
    parts.push('bsd');
    const clauseMatch = normalized.match(/(\d)\s*clause/);
    if (clauseMatch) parts.push(clauseMatch[1] + 'clause');
  }
  if (normalized.includes('apache')) parts.push('apache');
  if (normalized.includes('mit')) parts.push('mit');
  if (normalized.includes('isc')) parts.push('isc');
  if (normalized.includes('gpl') || normalized.includes('general public')) parts.push('gpl');
  if (normalized.includes('agpl') || normalized.includes('affero')) parts.push('agpl');
  if (normalized.includes('lgpl') || normalized.includes('lesser general')) parts.push('lgpl');
  if (normalized.includes('mpl') || normalized.includes('mozilla')) parts.push('mpl');
  if (normalized.includes('epl') || normalized.includes('eclipse')) parts.push('epl');
  if (normalized.includes('cc0') || normalized.includes('creative commons zero')) parts.push('cc0');
  if (normalized.includes('cc by') || normalized.includes('creative commons attribution')) parts.push('ccby');
  if (normalized.includes('unlicense')) parts.push('unlicense');
  if (normalized.includes('boost') || normalized.includes('bsl')) parts.push('boost');
  if (normalized.includes('python')) parts.push('python');
  if (!parts.includes('0bsd')) {
    const versionMatch = normalized.match(/(\d+\.?\d*)/);
    if (versionMatch) parts.push(versionMatch[1]);
  }
  return parts.join('-');
}

function checkSingleLicenseAllowed(singleLicense: string, policies: ProjectEffectivePolicies): boolean {
  const licenseKey = extractLicenseKey(singleLicense);
  const normalizedLicense = normalizeLicenseForComparison(singleLicense);
  return policies.effective.accepted_licenses.some(allowed => {
    const allowedKey = extractLicenseKey(allowed);
    const normalizedAllowed = normalizeLicenseForComparison(allowed);
    if (licenseKey && allowedKey && licenseKey === allowedKey) return true;
    return normalizedLicense.includes(normalizedAllowed) || normalizedAllowed.includes(normalizedLicense);
  });
}

function isLicenseAllowed(license: string | null, policies: ProjectEffectivePolicies | null): boolean | null {
  if (!policies || !license || license === 'Unknown' || license === 'Pending...') return null;
  const orParts = license.split(/\s+or\s+/i).map(part => part.replace(/[()]/g, '').trim());
  return orParts.some(part => checkSingleLicenseAllowed(part, policies));
}

type DependencyOverviewResponse = Awaited<ReturnType<typeof api.getDependencyOverview>>;

function buildDependencyFromOverview(
  projectId: string,
  projectDependencyId: string,
  overview: DependencyOverviewResponse | null,
  listItem?: ProjectDependency | null
): ProjectDependency {
  return {
    id: projectDependencyId,
    project_id: projectId,
    dependency_id: overview?.dependency_id ?? '',
    name: overview?.name ?? 'example-package',
    version: overview?.version ?? '9.9.9',
    license: overview?.license ?? 'MIT',
    github_url: overview?.github_url ?? null,
    is_direct: true,
    source: listItem?.source ?? 'dependencies',
    is_watching: listItem?.is_watching ?? false,
    files_importing_count: overview?.files_importing_count ?? 0,
    imported_functions: overview?.imported_functions ?? [],
    imported_file_paths: overview?.imported_file_paths ?? [],
    ai_usage_summary: overview?.ai_usage_summary ?? null,
    ai_usage_analyzed_at: overview?.ai_usage_analyzed_at ?? null,
    other_projects_using_count: overview?.other_projects_using_count ?? 0,
    other_projects_using_names: overview?.other_projects_using_names ?? [],
    description: overview?.description ?? null,
    created_at: new Date().toISOString(),
    policy_result: listItem?.policy_result ?? undefined,
    analysis: {
      status: 'ready',
      score: overview?.score ?? null,
      score_breakdown: {
        openssf_penalty: overview?.openssf_penalty ?? null,
        popularity_penalty: overview?.popularity_penalty ?? null,
        maintenance_penalty: overview?.maintenance_penalty ?? null,
      },
      critical_vulns: overview?.critical_vulns ?? 0,
      high_vulns: overview?.high_vulns ?? 0,
      medium_vulns: overview?.medium_vulns ?? 0,
      low_vulns: overview?.low_vulns ?? 0,
      openssf_score: overview?.openssf_score ?? null,
      openssf_data: undefined,
      weekly_downloads: overview?.weekly_downloads ?? null,
      last_published_at: overview?.last_published_at ?? null,
      latest_release_date: overview?.latest_release_date ?? null,
      releases_last_12_months: overview?.releases_last_12_months ?? null,
      analyzed_at: new Date().toISOString(),
    },
  };
}

const VALID_TABS = ['overview', 'supply-chain'] as const;
type UrlTab = (typeof VALID_TABS)[number];

function tabFromPathname(pathname: string): UrlTab {
  const segment = pathname.split('/').filter(Boolean).pop() ?? '';
  return VALID_TABS.includes(segment as UrlTab) ? (segment as UrlTab) : 'overview';
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

export function ProjectDependenciesContent(props: ProjectDependenciesContentProps) {
  const { project, organizationId, userPermissions, reloadProject, embedInSidebar } = props;
  /** Embedded: room under tabs + inset from drawer edge; full page keeps original spacing. */
  const listPad = embedInSidebar ? 'pl-3 pr-3' : 'pl-5 pr-3';
  const rowInset = embedInSidebar ? 'pl-3 pr-3 -ml-3 -mr-3' : 'pl-5 pr-3 -ml-5 -mr-3';
  const searchPad = embedInSidebar ? 'px-3 pt-3 pb-2' : 'px-3 pt-4 pb-2';
  const mainEmbedClass =
    embedInSidebar && '-mx-5 min-h-0 h-full w-[calc(100%+2.5rem)] max-w-none';
  /** Match org project drawer shell (#050505), not bg-background (#000) or content alone. */
  const embedShellBg = 'bg-background-card-header';

  const params = useParams<{ projectId: string; dependencyId?: string }>();
  const location = useLocation();
  const navigate = useNavigate();
  const projectId = project?.id ?? params.projectId ?? '';
  const [sidebarSelectedDepId, setSidebarSelectedDepId] = useState<string | null>(null);
  const selectedDepId = embedInSidebar ? sidebarSelectedDepId : (params.dependencyId ?? null);
  const setSelectedDepId = embedInSidebar
    ? setSidebarSelectedDepId
    : (id: string | null) => {
        const base = organizationId && projectId ? `/organizations/${organizationId}/projects/${projectId}/dependencies` : '';
        if (id) navigate(`${base}/${id}/overview`, { replace: true });
        else navigate(base ?? '', { replace: true });
      };
  const realtime = useRealtimeStatus(organizationId, projectId);
  const isExtractionOngoing = checkExtractionOngoing(realtime.status, realtime.extractionStep);

  const urlTab = tabFromPathname(location.pathname);
  const [sidebarSubTab, setSidebarSubTab] = useState<'overview' | 'supply-chain' | 'notes'>('overview');
  const selectedSubTab: 'overview' | 'supply-chain' | 'notes' = embedInSidebar ? sidebarSubTab : urlTab;

  const depsBase = organizationId && projectId ? `/organizations/${organizationId}/projects/${projectId}/dependencies` : '';

  const [searchQuery, setSearchQuery] = useState('');
  const [filterWatchtower, setFilterWatchtower] = useState(false);
  const [filterVulnerability, setFilterVulnerability] = useState(false);
  const [filterLicenseIssue, setFilterLicenseIssue] = useState(false);
  const [filterDeprecated, setFilterDeprecated] = useState(false);
  const [permissionsChecked, setPermissionsChecked] = useState(false);
  const [dependencies, setDependencies] = useState<ProjectDependency[]>([]);
  const [dependenciesLoading, setDependenciesLoading] = useState(false);
  const showListLoading = (realtime.isLoading || dependenciesLoading) && !isExtractionOngoing;
  const [dependenciesError, setDependenciesError] = useState<string | null>(null);
  const [refreshingDependencies, setRefreshingDependencies] = useState(false);
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [importStatus, setImportStatus] = useState<ProjectImportStatus | null>(null);
  const prefetchTabTimeoutsRef = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const prefetchRowTimeoutsRef = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const hasUserRefreshedRef = useRef(false);

  // Notes sidebar state (persists across tab switches when a dependency is selected)
  const [notesSidebarOpen, setNotesSidebarOpen] = useState(false);
  const [notesCount, setNotesCount] = useState(0);
  const handleNotesCountChange = useCallback((count: number) => setNotesCount(count), []);

  // Right panel overview (when a dependency is selected and sub-tab is Overview)
  const [panelOverview, setPanelOverview] = useState<DependencyOverviewResponse | null>(null);
  const [panelOverviewLoading, setPanelOverviewLoading] = useState(false);
  const [panelOverviewError, setPanelOverviewError] = useState<string | null>(null);
  const [panelDeprecation, setPanelDeprecation] = useState<{
    recommended_alternative: string;
    deprecated_by: string | null;
    created_at: string;
    scope?: 'organization' | 'team';
    team_id?: string;
  } | null>(null);
  const [panelBumpScope, setPanelBumpScope] = useState<'org' | 'team' | 'project'>('project');
  const [panelBumpTeamId, setPanelBumpTeamId] = useState<string | undefined>(undefined);

  // Resizable sidebar: width state (persisted), drag refs
  const SIDEBAR_MIN = 200;
  const SIDEBAR_MAX = 480;
  const SIDEBAR_COLLAPSED_WIDTH = 48;
  const SIDEBAR_STORAGE_KEY = 'deptex-deps-sidebar-width';
  const SIDEBAR_COLLAPSED_KEY = 'deptex-deps-sidebar-collapsed';
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      const stored = localStorage.getItem(SIDEBAR_COLLAPSED_KEY);
      return stored === 'true';
    } catch {}
    return false;
  });
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    try {
      const stored = localStorage.getItem(SIDEBAR_STORAGE_KEY);
      if (stored) {
        const w = Number(stored);
        if (!Number.isNaN(w)) return Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, w));
      }
    } catch {}
    return 320; // default width (was 288)
  });
  const resizeStartXRef = useRef(0);
  const resizeStartWidthRef = useRef(320);
  const sidebarWidthRef = useRef(sidebarWidth);
  sidebarWidthRef.current = sidebarWidth;

  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    resizeStartXRef.current = e.clientX;
    resizeStartWidthRef.current = sidebarWidth;
    const onMove = (moveEvent: MouseEvent) => {
      const delta = moveEvent.clientX - resizeStartXRef.current;
      setSidebarWidth(() => Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, resizeStartWidthRef.current + delta)));
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.removeProperty('user-select');
      document.body.style.removeProperty('cursor');
      try {
        localStorage.setItem(SIDEBAR_STORAGE_KEY, String(sidebarWidthRef.current));
      } catch {}
    };
    document.body.style.userSelect = 'none';
    document.body.style.cursor = 'col-resize';
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
  }, [sidebarWidth]);

  // Permission check - redirect if user doesn't have view_dependencies permission
  useEffect(() => {
    if (!project || !projectId || !userPermissions) return;
    
    if (!userPermissions.view_dependencies) {
      // Redirect to first available tab
      if (userPermissions.view_overview) {
        navigate(`/organizations/${organizationId}/projects/${projectId}`, { replace: true });
      } else if (userPermissions.view_watchlist) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/watchlist`, { replace: true });
      } else if (userPermissions.view_members) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/members`, { replace: true });
      } else if (userPermissions.view_settings) {
        navigate(`/organizations/${organizationId}/projects/${projectId}/settings`, { replace: true });
      }
      return;
    }
    
    setPermissionsChecked(true);
  }, [project, projectId, userPermissions, navigate, organizationId]);

  const handleRefreshDependencies = useCallback(async () => {
    if (!organizationId || !projectId) return;
    hasUserRefreshedRef.current = true;
    setRefreshingDependencies(true);
    try {
      const data = await api.getProjectDependencies(organizationId, projectId, { bypassCache: true });
      setDependencies(data);
      setDependenciesError(null);
      if (selectedDepId && selectedSubTab === 'overview') {
        api.clearDependencyOverviewPrefetch(organizationId, projectId, selectedDepId);
        const overview = await api.getDependencyOverview(organizationId, projectId, selectedDepId, { bypassCache: true });
        setPanelOverview(overview);
        setPanelDeprecation(overview.deprecation ?? null);
      }
    } catch (error: any) {
      setDependenciesError(error.message || 'Failed to load dependencies');
    } finally {
      // Keep spinner visible until React has committed and painted the new data
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setRefreshingDependencies(false);
        });
      });
    }
  }, [organizationId, projectId, selectedDepId, selectedSubTab]);

  // Load import status (for showing spinner in Imports column when AST not ready)
  const loadImportStatus = useCallback(async () => {
    if (!organizationId || !projectId) return;
    try {
      const status = await api.getProjectImportStatus(organizationId, projectId);
      setImportStatus(status);
    } catch {
      setImportStatus(null);
    }
  }, [organizationId, projectId]);

  // Initial load: dependencies first for fast list paint; policies and import status in parallel (don't block list)
  useEffect(() => {
    if (!project || !projectId || !organizationId || !userPermissions?.view_dependencies || !permissionsChecked) return;
    hasUserRefreshedRef.current = false;
    let cancelled = false;
    setDependenciesLoading(true);
    // Cached only — show immediately if we have data
    api.getProjectDependencies(organizationId, projectId, { cachedOnly: true }).then((cachedDeps) => {
      if (!cancelled && cachedDeps.length > 0) setDependencies(cachedDeps);
    });
    // Full DB — list is ready when this resolves; don't wait for policies/import
    api.getProjectDependencies(organizationId, projectId)
      .then((deps) => {
        if (cancelled || hasUserRefreshedRef.current) return;
        setDependencies(deps);
        setDependenciesError(null);
      })
      .catch((err: any) => {
        if (!cancelled) setDependenciesError(err.message || 'Failed to load dependencies');
      })
      .finally(() => {
        if (!cancelled) setDependenciesLoading(false);
      });
    // Load policies and import status in parallel (list already visible when deps resolve)
    api.getProjectPolicies(organizationId, projectId)
      .then((pols) => { if (!cancelled) setPolicies(pols ?? null); })
      .catch((e) => { console.error('Failed to load project policies:', e); });
    api.getProjectImportStatus(organizationId, projectId)
      .then((imp) => { if (!cancelled) setImportStatus(imp ?? null); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [project?.id, projectId, organizationId, userPermissions?.view_dependencies, permissionsChecked]);

  // Redirect to list when URL dependencyId is not in the loaded list (or clear sidebar selection)
  useEffect(() => {
    if (!selectedDepId || dependencies.length === 0 || dependenciesLoading) return;
    const found = dependencies.some((d) => d.id === selectedDepId);
    if (!found) {
      if (embedInSidebar) setSelectedDepId(null);
      else if (depsBase) navigate(depsBase, { replace: true });
    }
  }, [depsBase, selectedDepId, dependencies, dependenciesLoading, navigate, embedInSidebar]);

  // Poll import status when finalizing so Imports column updates when AST completes
  useEffect(() => {
    if (importStatus?.status !== 'finalizing' || !organizationId || !projectId) return;
    const id = setInterval(loadImportStatus, 4000);
    return () => clearInterval(id);
  }, [importStatus?.status, organizationId, projectId, loadImportStatus]);


  // Fetch overview for right panel when a dependency is selected and sub-tab is Overview (use prefetched if available)
  useEffect(() => {
    if (!organizationId || !projectId || !selectedDepId || selectedSubTab !== 'overview') {
      setPanelOverview(null);
      setPanelOverviewError(null);
      setPanelDeprecation(null);
      return;
    }
    let cancelled = false;
    setPanelOverviewLoading(true);
    setPanelOverviewError(null);
    const prefetched = api.consumePrefetchedOverview(organizationId, projectId, selectedDepId);
    const overviewPromise = prefetched
      ? prefetched.then(([res]) => res).catch(() => null)
      : api.getDependencyOverview(organizationId, projectId, selectedDepId);
    overviewPromise
      .then((res) => {
        if (cancelled) return;
        if (res) {
          setPanelOverview(res);
          setPanelDeprecation(res.deprecation ?? null);
        } else {
          setPanelOverviewError('Failed to load dependency');
        }
      })
      .catch((err) => {
        if (!cancelled) setPanelOverviewError(err?.message ?? 'Failed to load dependency');
      })
      .finally(() => {
        if (!cancelled) setPanelOverviewLoading(false);
      });
    return () => { cancelled = true; };
  }, [organizationId, projectId, selectedDepId, selectedSubTab]);

  // Pre-fetch notes count when a dependency is selected (try prefetched first)
  useEffect(() => {
    if (!organizationId || !projectId || !selectedDepId) {
      setNotesCount(0);
      return;
    }
    let cancelled = false;
    const prefetched = api.consumePrefetchedNotes(organizationId, projectId, selectedDepId);
    if (prefetched) {
      prefetched.then((res) => {
        if (!cancelled) setNotesCount(res.notes.length);
      }).catch(() => {});
      return;
    }
    api.getDependencyNotes(organizationId, projectId, selectedDepId)
      .then((res) => { if (!cancelled) setNotesCount(res.notes.length); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, [organizationId, projectId, selectedDepId]);

  // Prefetch supply chain when a package is selected so that tab opens instantly
  useEffect(() => {
    if (!organizationId || !projectId || !selectedDepId) return;
    api.prefetchDependencySupplyChain(organizationId, projectId, selectedDepId);
  }, [organizationId, projectId, selectedDepId]);

  // Bump scope for deprecation actions in panel
  useEffect(() => {
    if (!organizationId || !projectId || !selectedDepId || selectedSubTab !== 'overview') return;
    api.getBumpScope(organizationId, projectId)
      .then((res) => {
        setPanelBumpScope(res.scope);
        if (res.team_id) setPanelBumpTeamId(res.team_id);
      })
      .catch(() => setPanelBumpScope('project'));
  }, [organizationId, projectId, selectedDepId, selectedSubTab]);

  const panelCanManageDeprecations = panelBumpScope === 'org' || panelBumpScope === 'team';

  const handlePanelDeprecate = useCallback(async (alternativeName: string) => {
    if (!organizationId || !panelOverview?.dependency_id) return;
    if (panelBumpScope === 'org') {
      await api.deprecateDependency(organizationId, panelOverview.dependency_id, alternativeName);
      const newDeprecation = {
        recommended_alternative: alternativeName,
        deprecated_by: null,
        created_at: new Date().toISOString(),
        scope: 'organization' as const,
      };
      setPanelDeprecation(newDeprecation);
      setDependencies((prev) =>
        prev.map((d) => (d.id === selectedDepId ? { ...d, deprecation: newDeprecation } : d))
      );
    } else if (panelBumpScope === 'team' && panelBumpTeamId) {
      await api.deprecateDependencyTeam(organizationId, panelBumpTeamId, panelOverview.dependency_id, alternativeName);
      const newDeprecation = {
        recommended_alternative: alternativeName,
        deprecated_by: null,
        created_at: new Date().toISOString(),
        scope: 'team' as const,
        team_id: panelBumpTeamId,
      };
      setPanelDeprecation(newDeprecation);
      setDependencies((prev) =>
        prev.map((d) => (d.id === selectedDepId ? { ...d, deprecation: newDeprecation } : d))
      );
    }
  }, [organizationId, panelOverview?.dependency_id, panelBumpScope, panelBumpTeamId, selectedDepId]);

  const handlePanelRemoveDeprecation = useCallback(async () => {
    if (!organizationId || !panelOverview?.dependency_id) return;
    if (panelDeprecation?.scope === 'team' && panelDeprecation?.team_id) {
      await api.removeDeprecationTeam(organizationId, panelDeprecation.team_id, panelOverview.dependency_id);
    } else {
      await api.removeDeprecation(organizationId, panelOverview.dependency_id);
    }
    setPanelDeprecation(null);
    setDependencies((prev) =>
      prev.map((d) => (d.id === selectedDepId ? { ...d, deprecation: undefined } : d))
    );
  }, [organizationId, panelOverview?.dependency_id, panelDeprecation?.scope, panelDeprecation?.team_id, selectedDepId]);


  const selectedDepFromList = selectedDepId ? dependencies.find((d) => d.id === selectedDepId) : null;

  const panelDependency = useMemo(
    () => (projectId && selectedDepId ? buildDependencyFromOverview(projectId, selectedDepId, panelOverview, selectedDepFromList) : null),
    [projectId, selectedDepId, panelOverview, selectedDepFromList]
  );

  // Prefetch tab data on hover (100ms debounce)
  const handleTabHover = useCallback((tabId: string) => {
    if (tabId === selectedSubTab) return;
    if (!organizationId || !projectId || !selectedDepId) return;
    const existing = prefetchTabTimeoutsRef.current.get(tabId);
    if (existing) clearTimeout(existing);
    const timeout = setTimeout(() => {
      if (tabId === 'overview') {
        api.prefetchDependencyOverview(organizationId, projectId, selectedDepId);
      } else if (tabId === 'supply-chain') {
        api.prefetchDependencySupplyChain(organizationId, projectId, selectedDepId);
      } else if (tabId === 'notes') {
        api.prefetchDependencyNotes(organizationId, projectId, selectedDepId);
      }
      prefetchTabTimeoutsRef.current.delete(tabId);
    }, 100);
    prefetchTabTimeoutsRef.current.set(tabId, timeout);
  }, [selectedSubTab, organizationId, projectId, selectedDepId, selectedDepFromList?.name]);

  const handleTabHoverEnd = useCallback((tabId: string) => {
    const timeout = prefetchTabTimeoutsRef.current.get(tabId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchTabTimeoutsRef.current.delete(tabId);
    }
  }, []);

  // Prefetch overview + notes when hovering a package row (100ms debounce)
  const handleRowHover = useCallback((depId: string) => {
    if (!organizationId || !projectId) return;
    const existing = prefetchRowTimeoutsRef.current.get(depId);
    if (existing) clearTimeout(existing);
    const timeout = setTimeout(() => {
      api.prefetchDependencyOverview(organizationId, projectId, depId);
      api.prefetchDependencyNotes(organizationId, projectId, depId);
      prefetchRowTimeoutsRef.current.delete(depId);
    }, 100);
    prefetchRowTimeoutsRef.current.set(depId, timeout);
  }, [organizationId, projectId]);

  const handleRowHoverEnd = useCallback((depId: string) => {
    const timeout = prefetchRowTimeoutsRef.current.get(depId);
    if (timeout) {
      clearTimeout(timeout);
      prefetchRowTimeoutsRef.current.delete(depId);
    }
  }, []);

  // Skeleton row matching real package list item (icon + name bar). Optional opacity for fade-out effect.
  const PackageRowSkeleton = ({ nameWidth, opacityClass = 'opacity-100' }: { nameWidth: string; opacityClass?: string }) => (
    <div className={cn('flex items-center gap-1.5 py-1.5 transition-opacity', rowInset, opacityClass)}>
      <div className="h-4 w-4 shrink-0 rounded bg-muted/80" />
      <div className={cn('h-4 rounded-md bg-muted/80 min-w-[3rem]', nameWidth)} />
    </div>
  );

  // Six rows with progressive fade (Supabase-style): top opaque, bottom fades into background
  const skeletonRows = [
    { nameWidth: 'w-[78%]', opacityClass: 'opacity-100' },
    { nameWidth: 'w-[88%]', opacityClass: 'opacity-80' },
    { nameWidth: 'w-[65%]', opacityClass: 'opacity-60' },
    { nameWidth: 'w-[72%]', opacityClass: 'opacity-45' },
    { nameWidth: 'w-[82%]', opacityClass: 'opacity-30' },
    { nameWidth: 'w-[70%]', opacityClass: 'opacity-20' },
  ] as const;

  const dependencySubNavItems = [
    { id: 'overview', label: 'Overview', path: 'overview', icon: LayoutDashboard },
    { id: 'supply-chain', label: 'Supply chain', path: 'supply-chain', icon: GitBranch },
    { id: 'notes', label: 'Notes', path: 'notes', icon: MessageSquareText },
  ] as const;

  const effectiveSidebarWidth = sidebarCollapsed ? SIDEBAR_COLLAPSED_WIDTH : sidebarWidth;
  const toggleSidebarCollapsed = useCallback(() => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(next));
      } catch {}
      return next;
    });
  }, []);

  // Show loading until project and permissions are verified
  if (!project || !permissionsChecked) {
    return (
      <main
        className={cn(
          'flex min-h-0',
          embedInSidebar ? cn('h-full min-h-0 flex-1', embedShellBg) : 'h-[calc(100vh-3rem)]',
          mainEmbedClass
        )}
      >
        <aside
          style={{ width: effectiveSidebarWidth }}
          className={cn(
            'shrink-0 flex flex-col overflow-hidden transition-[width] duration-200 ease-out',
            embedInSidebar ? embedShellBg : 'bg-background-content'
          )}
        >
          <div className={cn('shrink-0 animate-pulse', searchPad)}>
            <div className="h-9 bg-muted/80 rounded-md w-full" />
          </div>
          <div className={cn('flex-1 min-h-0 pt-0.5 pb-4 space-y-0.5 animate-pulse', listPad)}>
            {skeletonRows.map((row, i) => (
              <PackageRowSkeleton key={i} nameWidth={row.nameWidth} opacityClass={row.opacityClass} />
            ))}
          </div>
        </aside>
        <div className="flex-1 min-w-0" />
      </main>
    );
  }
  
  // Double-check permission before rendering (safety check)
  if (!userPermissions?.view_dependencies) {
    return null; // Will redirect via useEffect
  }

  const filteredDependencies = dependencies
    .filter(dep => {
      const matchesSearch = dep.name.toLowerCase().includes(searchQuery.toLowerCase());
      if (!dep.is_direct || !matchesSearch) return false;
      return true;
    })
    .filter(dep => {
      if (filterWatchtower && !dep.is_watching) return false;
      if (filterVulnerability && !getVulnSeverityInfo(dep)) return false;
      // Only treat as license issue when policy was actually run and returned allowed: false.
      // When policy_result is null (policy not evaluated yet), don't show/filter as license issue.
      const hasLicenseIssue = dep.policy_result != null && dep.policy_result.allowed === false;
      if (filterLicenseIssue && !hasLicenseIssue) return false;
      if (filterDeprecated && !dep.deprecation) return false;
      return true;
    })
    .sort((a, b) => (b.files_importing_count || 0) - (a.files_importing_count || 0));

  return (
    <main
      className={cn(
        'flex min-h-0 relative',
        embedInSidebar ? cn('h-full min-h-0 flex-1', embedShellBg) : 'h-[calc(100vh-3rem)]',
        mainEmbedClass
      )}
    >
      {/* Left sidebar: in org project drawer use same surface as shell (card-header); full page uses content gray */}
      <aside
        style={{ width: sidebarCollapsed ? SIDEBAR_COLLAPSED_WIDTH : effectiveSidebarWidth }}
        className={cn(
          'flex flex-col overflow-hidden transition-all duration-200 ease-out',
          embedInSidebar ? embedShellBg : 'bg-background-content',
          sidebarCollapsed ? 'absolute left-0 top-0 bottom-0 z-20' : 'relative shrink-0 z-10'
        )}
      >
        {sidebarCollapsed ? (
          <div className="shrink-0 flex flex-col items-center pt-2">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  type="button"
                  onClick={toggleSidebarCollapsed}
                  aria-label="Open dependencies sidebar"
                  className="flex items-center justify-center w-9 h-9 rounded-md border border-border bg-background-card text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
                >
                  <PanelLeftOpen className="h-4 w-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="right">Open dependencies sidebar</TooltipContent>
            </Tooltip>
          </div>
        ) : (
        <>
        <div className="shrink-0">
          <div className={searchPad}>
            <div className="flex items-center gap-2">
              <div className="relative flex-1 min-w-0">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-foreground-secondary" />
                <input
                  type="text"
                  placeholder="Search dependencies..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-9 pr-4 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-primary focus:border-transparent"
                />
              </div>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <button
                    type="button"
                    aria-label="Filter packages"
                    className="shrink-0 flex items-center justify-center h-9 w-9 rounded-md border border-border bg-background-card text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
                  >
                    <SlidersHorizontal className="h-4 w-4" />
                  </button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56 rounded-lg border-border bg-background-card shadow-lg">
                  <DropdownMenuLabel className="text-foreground font-semibold px-2 pt-2 pb-1">
                    Filter by
                  </DropdownMenuLabel>
                  <div className="px-2 space-y-0">
                    <div
                      className="group flex items-center gap-2 py-1 px-0 rounded-md cursor-pointer"
                      onClick={() => setFilterWatchtower((v) => !v)}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setFilterWatchtower((v) => !v); } }}
                      role="option"
                      aria-selected={filterWatchtower}
                      tabIndex={0}
                    >
                      <Checkbox
                        id="filter-watchtower"
                        checked={filterWatchtower}
                        onCheckedChange={(checked) => setFilterWatchtower(checked === true)}
                        className="data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
                      />
                      <label htmlFor="filter-watchtower" className="text-sm font-normal cursor-pointer flex-1 text-foreground">
                        Watchtower
                      </label>
                      <button
                        type="button"
                        className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-xs font-medium px-2 py-1 rounded-md border border-foreground/40 bg-transparent text-foreground hover:bg-foreground/10 focus:opacity-100 focus:outline-none"
                        onClick={(e) => { e.stopPropagation(); setFilterWatchtower(true); setFilterVulnerability(false); setFilterLicenseIssue(false); setFilterDeprecated(false); }}
                      >
                        Select only
                      </button>
                    </div>
                    <div
                      className="group flex items-center gap-2 py-1 px-0 rounded-md cursor-pointer"
                      onClick={() => setFilterVulnerability((v) => !v)}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setFilterVulnerability((v) => !v); } }}
                      role="option"
                      aria-selected={filterVulnerability}
                      tabIndex={0}
                    >
                      <Checkbox
                        id="filter-vulnerability"
                        checked={filterVulnerability}
                        onCheckedChange={(checked) => setFilterVulnerability(checked === true)}
                        className="data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
                      />
                      <label htmlFor="filter-vulnerability" className="text-sm font-normal cursor-pointer flex-1 text-foreground">
                        Vulnerability
                      </label>
                      <button
                        type="button"
                        className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-xs font-medium px-2 py-1 rounded-md border border-foreground/40 bg-transparent text-foreground hover:bg-foreground/10 focus:opacity-100 focus:outline-none"
                        onClick={(e) => { e.stopPropagation(); setFilterVulnerability(true); setFilterWatchtower(false); setFilterLicenseIssue(false); setFilterDeprecated(false); }}
                      >
                        Select only
                      </button>
                    </div>
                    <div
                      className="group flex items-center gap-2 py-1 px-0 rounded-md cursor-pointer"
                      onClick={() => setFilterLicenseIssue((v) => !v)}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setFilterLicenseIssue((v) => !v); } }}
                      role="option"
                      aria-selected={filterLicenseIssue}
                      tabIndex={0}
                    >
                      <Checkbox
                        id="filter-license"
                        checked={filterLicenseIssue}
                        onCheckedChange={(checked) => setFilterLicenseIssue(checked === true)}
                        className="data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
                      />
                      <label htmlFor="filter-license" className="text-sm font-normal cursor-pointer flex-1 text-foreground">
                        License issue
                      </label>
                      <button
                        type="button"
                        className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-xs font-medium px-2 py-1 rounded-md border border-foreground/40 bg-transparent text-foreground hover:bg-foreground/10 focus:opacity-100 focus:outline-none"
                        onClick={(e) => { e.stopPropagation(); setFilterLicenseIssue(true); setFilterWatchtower(false); setFilterVulnerability(false); setFilterDeprecated(false); }}
                      >
                        Select only
                      </button>
                    </div>
                    <div
                      className="group flex items-center gap-2 py-1 px-0 rounded-md cursor-pointer"
                      onClick={() => setFilterDeprecated((v) => !v)}
                      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); setFilterDeprecated((v) => !v); } }}
                      role="option"
                      aria-selected={filterDeprecated}
                      tabIndex={0}
                    >
                      <Checkbox
                        id="filter-deprecated"
                        checked={filterDeprecated}
                        onCheckedChange={(checked) => setFilterDeprecated(checked === true)}
                        className="data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
                      />
                      <label htmlFor="filter-deprecated" className="text-sm font-normal cursor-pointer flex-1 text-foreground">
                        Deprecated
                      </label>
                      <button
                        type="button"
                        className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-xs font-medium px-2 py-1 rounded-md border border-foreground/40 bg-transparent text-foreground hover:bg-foreground/10 focus:opacity-100 focus:outline-none"
                        onClick={(e) => { e.stopPropagation(); setFilterDeprecated(true); setFilterWatchtower(false); setFilterVulnerability(false); setFilterLicenseIssue(false); }}
                      >
                        Select only
                      </button>
                    </div>
                  </div>
                </DropdownMenuContent>
              </DropdownMenu>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={handleRefreshDependencies}
                    disabled={refreshingDependencies}
                    aria-label="Refresh dependencies"
                    className="shrink-0 flex items-center justify-center h-9 w-9 rounded-md border border-border bg-background-card text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors disabled:opacity-50 disabled:pointer-events-none"
                  >
                    {refreshingDependencies ? (
                      <Loader2 className="h-4 w-4 animate-spin" />
                    ) : (
                      <RefreshCw className="h-4 w-4" />
                    )}
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right">Refresh dependencies</TooltipContent>
              </Tooltip>
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    type="button"
                    onClick={toggleSidebarCollapsed}
                    aria-label="Collapse dependencies sidebar"
                    className="shrink-0 flex items-center justify-center h-9 w-9 rounded-md border border-border bg-background-card text-foreground-secondary hover:text-foreground hover:bg-background-subtle transition-colors"
                  >
                    <PanelLeftClose className="h-4 w-4" />
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right">Collapse sidebar</TooltipContent>
              </Tooltip>
            </div>
          </div>
        </div>
        <div className={cn('flex-1 min-h-0 overflow-y-auto custom-scrollbar pt-0.5 pb-4', listPad)}>
          {isExtractionOngoing ? (
            <ExtractionProgressCard
              description={
                !realtime.isLoading && realtime.status === 'not_connected'
                  ? 'Connect a repository in Project Settings to see dependencies.'
                  : 'Dependencies will appear here once extraction completes.'
              }
              organizationId={organizationId}
              projectId={projectId}
            />
          ) : showListLoading ? (
            <div className="space-y-0.5 animate-pulse">
              {skeletonRows.map((row, i) => (
                <PackageRowSkeleton key={i} nameWidth={row.nameWidth} opacityClass={row.opacityClass} />
              ))}
            </div>
          ) : dependenciesError ? (
            <div className="bg-destructive/10 border border-destructive/30 rounded-lg p-3 text-sm text-destructive">
              {dependenciesError}
            </div>
          ) : filteredDependencies.length === 0 ? (
            <div className="py-8 px-4 text-center">
              <p className="text-base font-medium text-foreground">No results found</p>
              <p className="text-sm text-foreground-secondary mt-1">
                {searchQuery.trim()
                  ? `Your search for "${searchQuery.trim()}" did not return any results`
                  : filterWatchtower || filterVulnerability || filterLicenseIssue || filterDeprecated
                    ? 'Your filters did not return any results'
                    : 'No dependencies found yet.'}
              </p>
            </div>
          ) : (
            <ul className="space-y-0.5">
              {filteredDependencies.map((dep) => {
                const vulnInfo = getVulnSeverityInfo(dep);
                // Show "License" badge only when policy was evaluated and failed (allowed: false).
                // When policy_result is null, policy hasn't run yet — don't show license issue.
                const hasLicenseIssue = dep.policy_result != null && dep.policy_result.allowed === false;
                const isSelected = selectedDepId === dep.id;
                return (
                  <li key={dep.id} className="transition-[height] duration-200 ease-out">
                    <div
                      role="button"
                      tabIndex={0}
                      onClick={() => {
                        const next = selectedDepId === dep.id ? null : dep.id;
                        if (embedInSidebar) setSelectedDepId(next);
                        else {
                          if (!depsBase) return;
                          if (next !== null) navigate(`${depsBase}/${next}/overview`, { replace: true });
                          else navigate(depsBase, { replace: true });
                        }
                      }}
                      onMouseEnter={() => handleRowHover(dep.id)}
                      onMouseLeave={() => handleRowHoverEnd(dep.id)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter' || e.key === ' ') {
                          e.preventDefault();
                          const next = selectedDepId === dep.id ? null : dep.id;
                          if (embedInSidebar) setSelectedDepId(next);
                          else {
                            if (!depsBase) return;
                            if (next !== null) navigate(`${depsBase}/${next}/overview`, { replace: true });
                            else navigate(depsBase, { replace: true });
                          }
                        }
                      }}
                      className={cn(
                        'flex items-center gap-1.5 py-1.5 text-sm transition-colors duration-150 cursor-pointer hover:bg-background-subtle',
                        rowInset
                      )}
                    >
                      <img src="/images/npm_icon.png" alt="" className="h-4 w-4 shrink-0 object-contain" aria-hidden />
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="text-foreground truncate min-w-0">
                            {dep.name}<span className="text-foreground-secondary">@{dep.version}</span>
                          </span>
                        </TooltipTrigger>
                        <TooltipContent side="right" className="max-w-[min(20rem,80vw)]">
                          {dep.name}@{dep.version}
                        </TooltipContent>
                      </Tooltip>
                      {dep.is_watching && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="shrink-0 text-foreground-secondary cursor-default" aria-hidden>
                              <TowerControl className="h-3.5 w-3.5" />
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right">On org watchtower</TooltipContent>
                        </Tooltip>
                      )}
                      {hasLicenseIssue && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium bg-destructive/10 text-destructive border border-destructive/30 cursor-default">
                              License
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right">License doesn’t match project policy</TooltipContent>
                        </Tooltip>
                      )}
                      {dep.source === 'devDependencies' && (
                        <span className="shrink-0 inline-flex items-center rounded px-1 py-0.5 text-[10px] font-medium bg-foreground/5 text-foreground-secondary border border-foreground/10 cursor-default">
                          Dev
                        </span>
                      )}
                      {vulnInfo && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className={cn('shrink-0 inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium border cursor-default', vulnInfo.maxSeverity === 'critical' && 'bg-destructive/10 text-destructive border-destructive/30', vulnInfo.maxSeverity === 'high' && 'bg-orange-500/10 text-orange-600 dark:text-orange-400 border-orange-500/30', vulnInfo.maxSeverity === 'medium' && 'bg-warning/15 text-warning border-warning/30', vulnInfo.maxSeverity === 'low' && 'bg-foreground/5 text-foreground-secondary border-foreground/10')}>
                              <ShieldAlert className="h-2.5 w-2.5" />
                              {vulnInfo.total}
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right" className="max-w-[min(20rem,80vw)]">
                            {vulnInfo.label}
                          </TooltipContent>
                        </Tooltip>
                      )}
                      {(dep.files_importing_count ?? 0) === 0 && dep.is_direct && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-warning/15 text-warning border border-warning/30 cursor-default">
                              Unused
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right">Not imported in any file</TooltipContent>
                        </Tooltip>
                      )}
                      {dep.deprecation && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-warning/15 text-warning border border-warning/30 cursor-default">
                              Deprecated
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right">Package is deprecated</TooltipContent>
                        </Tooltip>
                      )}
                      {dep.is_current_version_banned && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-destructive/10 text-destructive border border-destructive/30 cursor-default">
                              Banned
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right">This version is banned by org policy</TooltipContent>
                        </Tooltip>
                      )}
                      {dep.is_outdated && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <span className="shrink-0 inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-medium bg-amber-500/10 text-amber-400 border border-amber-500/30 cursor-default">
                              {dep.versions_behind && dep.versions_behind > 0 ? `${dep.versions_behind} behind` : 'Outdated'}
                            </span>
                          </TooltipTrigger>
                          <TooltipContent side="right">
                            {dep.versions_behind && dep.versions_behind > 0
                              ? `${dep.versions_behind} version${dep.versions_behind > 1 ? 's' : ''} behind latest`
                              : 'A newer version is available'}
                          </TooltipContent>
                        </Tooltip>
                      )}
                    </div>
                    {/* Expandable sub-nav: Overview, Supply chain, Watchtower (tab selection only) */}
                    <div
                      className="grid transition-[grid-template-rows] duration-200 ease-out"
                      style={{ gridTemplateRows: isSelected ? '1fr' : '0fr' }}
                    >
                      <div className="min-h-0 overflow-hidden">
                        <div className="pb-1.5 pt-0.5 space-y-0.5 ml-2 pr-4 min-w-0">
                          {dependencySubNavItems.map((item) => {
                            const Icon = item.icon;
                            const isSubTabActive = item.id !== 'notes' && selectedSubTab === item.id;
                            return (
                              <button
                                key={item.id}
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  if (item.id === 'notes') {
                                    setNotesSidebarOpen(true);
                                  } else if (embedInSidebar) {
                                    setSidebarSubTab(item.id);
                                  } else if (depsBase && selectedDepId) {
                                    navigate(`${depsBase}/${selectedDepId}/${item.id}`, { replace: true });
                                  }
                                }}
                                onMouseEnter={() => handleTabHover(item.id)}
                                onMouseLeave={() => handleTabHoverEnd(item.id)}
                                className={cn(
                                  'w-full flex items-center gap-2.5 py-1.5 px-2 text-sm rounded-md transition-colors duration-150 text-left',
                                  isSubTabActive
                                    ? 'text-foreground'
                                    : 'text-foreground-secondary hover:text-foreground'
                                )}
                              >
                                <Icon className="h-4 w-4 shrink-0" aria-hidden />
                                <span className="truncate">{item.label}</span>
                                {item.id === 'notes' && notesCount > 0 && (
                                  <span className="shrink-0 flex h-4 min-w-4 items-center justify-center rounded-full bg-destructive px-1 text-[9px] font-bold text-white">
                                    {notesCount > 99 ? '99+' : notesCount}
                                  </span>
                                )}
                              </button>
                            );
                          })}
                        </div>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          )}
        </div>
        </>
        )}
      </aside>
      {/* Resize handle: only when sidebar is expanded */}
      {!sidebarCollapsed && (
      <div
        role="separator"
        aria-orientation="vertical"
        aria-label="Resize sidebar"
        onMouseDown={handleResizeStart}
        className="shrink-0 flex justify-center px-2 -mx-2 -ml-px cursor-col-resize"
        style={{ touchAction: 'none' }}
      >
        <div
          className="self-stretch bg-border min-h-full shrink-0"
          style={{ width: 1, minWidth: 1, maxWidth: 1 }}
        />
      </div>
      )}
      {/* Right area: overview panel when a dependency is selected and sub-tab is Overview */}
      <div
        className={cn(
          'flex-1 min-w-0 flex flex-col overflow-hidden',
          embedInSidebar ? embedShellBg : 'bg-background-content',
          sidebarCollapsed && selectedSubTab === 'supply-chain' && 'w-full'
        )}
      >
        {!selectedDepId ? (
          <div className="flex-1 flex items-center justify-center p-8">
            <div className="flex flex-col items-center gap-4 text-center max-w-md">
              <div className="rounded-full bg-background-card/80 border border-border p-5 shadow-sm ring-1 ring-foreground/[0.04]">
                <Package className="h-10 w-10 text-foreground-secondary" aria-hidden />
              </div>
              <div className="space-y-1">
                <p className="text-base font-medium text-foreground">
                  No package selected
                </p>
                <p className="text-sm text-foreground-secondary leading-relaxed">
                  Click a dependency in the list to see its version, vulnerabilities, license, and where it’s used in your code.
                </p>
              </div>
            </div>
          </div>
        ) : selectedSubTab === 'supply-chain' && selectedDepId && projectId && organizationId ? (
          <div className="flex-1 flex flex-col min-h-0 w-full">
            <SupplyChainContent
              orgId={organizationId}
              projectId={projectId}
              dependencyId={selectedDepId}
              dependencyName={selectedDepFromList?.name}
              dependencyVersion={selectedDepFromList?.version}
              onDependencyListBanChange={(version, isBanned) => {
                if (selectedDepFromList?.version === version) {
                  setDependencies((prev) =>
                    prev.map((d) =>
                      d.id === selectedDepId ? { ...d, is_current_version_banned: isBanned } : d
                    )
                  );
                }
              }}
            />
          </div>
        ) : selectedSubTab !== 'overview' ? (
          <div className="flex-1 flex items-center justify-center p-8">
            <p className="text-sm text-foreground-secondary">Select a dependency to view {selectedSubTab === 'supply-chain' ? 'supply chain' : 'details'}.</p>
          </div>
        ) : panelOverviewLoading ? (
          <div className="flex-1 overflow-y-auto py-8">
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
              <PackageOverviewSkeleton />
            </div>
          </div>
        ) : panelOverviewError ? (
          <div className="flex-1 flex items-center justify-center p-8">
            <p className="text-destructive">{panelOverviewError}</p>
          </div>
        ) : panelDependency && projectId ? (
          <div className="flex-1 overflow-y-auto py-8">
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
              <PackageOverview
              dependency={panelDependency}
              organizationId={organizationId}
              projectId={projectId}
              latestVersion={panelOverview?.latest_version ?? null}
              policies={policies}
              deprecation={panelDeprecation}
              canManageDeprecations={panelCanManageDeprecations}
              onDeprecate={handlePanelDeprecate}
              onRemoveDeprecation={handlePanelRemoveDeprecation}
              isDevDependency={selectedDepFromList?.source === 'devDependencies'}
            />
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center p-8">
            <p className="text-foreground-secondary">Unable to load overview.</p>
          </div>
        )}
      </div>
      {/* Notes sidebar — only when a dependency is selected */}
      {organizationId && projectId && selectedDepId && (
        <DependencyNotesSidebar
          open={notesSidebarOpen}
          onOpenChange={setNotesSidebarOpen}
          organizationId={organizationId}
          projectId={projectId}
          projectDependencyId={selectedDepId}
          packageName={selectedDepFromList?.name ?? 'Package'}
          onNotesCountChange={handleNotesCountChange}
        />
      )}
    </main>
  );
}

export default function ProjectDependenciesPage() {
  const { project, organizationId, userPermissions, reloadProject } = useOutletContext<ProjectContextType>();
  return (
    <ProjectDependenciesContent
      project={project}
      organizationId={organizationId}
      userPermissions={userPermissions}
      reloadProject={reloadProject}
    />
  );
}
