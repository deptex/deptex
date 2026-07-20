import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import { useOutletContext, useNavigate, useParams } from 'react-router-dom';
import { Search, SlidersHorizontal, Loader2, PanelLeftClose, PanelLeftOpen, Package, RefreshCw } from 'lucide-react';
import { useRealtimeStatus } from '../../hooks/useRealtimeStatus';
import { isExtractionOngoing as checkExtractionOngoing, isInitialExtraction as checkInitialExtraction } from '../../lib/extractionStatus';
import { ExtractionProgressCard } from '../../components/ExtractionProgressCard';
import { api, ProjectWithRole, ProjectPermissions, ProjectDependency, ProjectEffectivePolicies, ProjectImportStatus, SupplyChainResponse } from '../../lib/api';
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
import { SupplyChainSections } from '../../components/supply-chain/SupplyChainSections';

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
  /** Open a finding in the project's Findings tab (the supply-chain table links findings there). */
  onOpenFinding?: (osvId: string) => void;
}

function getVulnSeverityInfo(dep: ProjectDependency): { tier: 'critical' | 'high' | 'medium' | 'low'; total: number; label: string } | null {
  const a = dep.analysis;
  if (!a) return null;
  const critical = a.critical_vulns ?? 0;
  const high = a.high_vulns ?? 0;
  const medium = a.medium_vulns ?? 0;
  const low = a.low_vulns ?? 0;
  const total = critical + high + medium + low;
  if (total === 0) return null;

  // Use max depscore (0–100) to determine badge tier if available, else fall back to severity
  const maxDepscore = a.max_depscore ?? null;
  let tier: 'critical' | 'high' | 'medium' | 'low';
  if (maxDepscore !== null) {
    tier = maxDepscore >= 75 ? 'critical' : maxDepscore >= 50 ? 'high' : maxDepscore >= 25 ? 'medium' : 'low';
  } else {
    tier = critical > 0 ? 'critical' : high > 0 ? 'high' : medium > 0 ? 'medium' : 'low';
  }

  const depscorePart = maxDepscore !== null ? ` · depscore ${maxDepscore.toFixed(0)}` : '';
  const label = `${total} ${total === 1 ? 'vulnerability' : 'vulnerabilities'}${depscorePart}`;
  return { tier, total, label };
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

const ECOSYSTEM_ICONS: Record<string, string> = {
  npm: '/images/npm_icon.png',
  pypi: '/images/pypi_icon.png',
  maven: '/images/maven_icon.png',
  nuget: '/images/nuget_icon.png',
  golang: '/images/go_icon.png',
  go: '/images/go_icon.png',
  cargo: '/images/cargo_icon.png',
  gem: '/images/frameworks/ruby.png',
  composer: '/images/frameworks/php.png',
};

function EcosystemIcon({ ecosystem, className }: { ecosystem?: string | null; className?: string }) {
  const src = ECOSYSTEM_ICONS[ecosystem ?? 'npm'] ?? null;
  if (src) {
    return <img src={src} alt="" className={className ?? 'h-4 w-4'} style={{ objectFit: 'contain' }} aria-hidden />;
  }
  return <Package className={className ?? 'h-4 w-4'} aria-hidden />;
}

// Dependency-row tags as small neutral text badges — a subtle chip (neutral surface + border)
// with a muted label, no coloured fill. Optional tooltip carries the detail (severity + count,
// reason) so the label can stay short.
function DepTagBadge({ label, tooltip }: { label: string; tooltip?: string }) {
  const badge = (
    <span className="shrink-0 inline-flex items-center rounded-md border border-border bg-foreground/[0.06] px-1.5 py-0.5 text-[10px] font-medium text-foreground-secondary">
      {label}
    </span>
  );
  if (!tooltip) return badge;
  return (
    <Tooltip>
      <TooltipTrigger asChild>{badge}</TooltipTrigger>
      <TooltipContent side="right">{tooltip}</TooltipContent>
    </Tooltip>
  );
}

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
    files_importing_count: overview?.files_importing_count ?? null,
    imported_functions: overview?.imported_functions ?? [],
    imported_file_paths: overview?.imported_file_paths ?? [],
    ai_usage_summary: overview?.ai_usage_summary ?? null,
    ai_usage_analyzed_at: overview?.ai_usage_analyzed_at ?? null,
    other_projects_using_count: overview?.other_projects_using_count ?? 0,
    other_projects_using_names: overview?.other_projects_using_names ?? [],
    description: overview?.description ?? null,
    ecosystem: overview?.ecosystem ?? null,
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

function extractionStepLabel(step: string | null | undefined): string {
  if (!step) return 'Starting extraction...';
  const labels: Record<string, string> = {
    queued: 'Job queued, waiting for worker...',
    cloning: 'Cloning repository...',
    sbom: 'Building SBOM...',
    deps_synced: 'Syncing dependencies...',
    usage_extraction: 'Analyzing imports...',
    framework_detection: 'Detecting entry points...',
    taint_engine: 'Running cross-file taint analysis...',
    scanning: 'Scanning for vulnerabilities...',
    uploading: 'Uploading results...',
    completed: 'Finishing up...',
  };
  return labels[step] ?? `Processing (${step})...`;
}

// Client-side cache (per browser session) of the enriched dependency list per project.
// The Dependencies tab unmounts/remounts on every sidebar-tab switch, and its list comes
// from a heavy server-side enrichment (multi-wave joins), so without this a re-open blocks
// on that recompute — 5s+ on local dev where every DB hop is a laptop→Ohio round trip.
// Seeding from here paints a re-open synchronously with zero round trips; the background
// fetch then refreshes it in place.
const depsListCache = new Map<string, ProjectDependency[]>();

/** Clear the per-session dependency-list cache. Called when the project sidebar CLOSES so
 *  reopening reloads the tab fresh (matching the Findings tab), rather than seeding a stale
 *  list. Tab switches WITHIN an open sidebar keep the cache (instant); closing drops it. */
export function clearProjectDepsCache() {
  depsListCache.clear();
}

/** Warm the client deps-list cache from the server's ALREADY-WARM cache when the project
 *  sidebar opens, so switching to the Dependencies tab paints instantly from the seed rather
 *  than waiting on a click-time round trip. `cachedOnly` means this NEVER triggers the heavy
 *  multi-wave recompute — it piggybacks on a warm cache (the common case; the deps cache is
 *  invalidated on data change, not by open) and no-ops on a miss, leaving the tab's own load
 *  to fetch fresh. Fire-and-forget, off the Findings first-paint critical path. */
export async function warmProjectDepsCache(organizationId: string, projectId: string): Promise<void> {
  if (!organizationId || !projectId) return;
  try {
    const cached = await api.getProjectDependencies(organizationId, projectId, { cachedOnly: true });
    if (cached && cached.length > 0) depsListCache.set(projectId, cached);
  } catch {
    /* best-effort warm; the tab's own load covers a miss */
  }
}

export function ProjectDependenciesContent(props: ProjectDependenciesContentProps) {
  const { project, organizationId, userPermissions, reloadProject, embedInSidebar, onOpenFinding } = props;
  /** Embedded: room under tabs + inset from drawer edge; full page keeps original spacing. */
  const listPad = embedInSidebar ? 'pl-3 pr-3' : 'pl-5 pr-3';
  const rowInset = embedInSidebar ? 'pl-3 pr-3 -ml-3 -mr-3' : 'pl-5 pr-3 -ml-5 -mr-3';
  const searchPad = embedInSidebar ? 'px-3 pt-3 pb-2' : 'px-3 pt-4 pb-2';
  const mainEmbedClass =
    embedInSidebar && '-mx-5 min-h-0 h-full w-[calc(100%+2.5rem)] max-w-none';
  /** Match org project drawer shell (#050505), not bg-background (#000) or content alone. */
  const embedShellBg = 'bg-background-card-header';

  const params = useParams<{ projectId: string; dependencyId?: string }>();
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
  const isInitialExtracting = checkInitialExtraction(realtime.status, realtime.extractionStep, realtime.lastExtractedAt);
  const isInitialExtractionFailed = realtime.status === 'error' && !realtime.isLoading && !realtime.lastExtractedAt;

  const depsBase = organizationId && projectId ? `/organizations/${organizationId}/projects/${projectId}/dependencies` : '';

  const [searchQuery, setSearchQuery] = useState('');
  const [filterVulnerability, setFilterVulnerability] = useState(false);
  const [filterDev, setFilterDev] = useState(false);
  const [filterUnused, setFilterUnused] = useState(false);
  const [permissionsChecked, setPermissionsChecked] = useState(false);
  const [dependencies, setDependencies] = useState<ProjectDependency[]>(() => depsListCache.get(projectId) ?? []);
  const [dependenciesLoading, setDependenciesLoading] = useState(false);
  // Only skeleton when there's genuinely nothing to show yet. The open effect seeds the
  // list from the cache (getProjectDependencies cachedOnly) before the full recompute
  // resolves — without the `dependencies.length === 0` guard that cached seed stays hidden
  // behind the skeleton until the slow recompute finishes, which is what made the tab feel
  // slow. Now the cached list paints immediately and the recompute refreshes it in place.
  const showListLoading = (realtime.isLoading || dependenciesLoading) && dependencies.length === 0 && !isInitialExtracting;
  const [dependenciesError, setDependenciesError] = useState<string | null>(null);
  const [refreshingDependencies, setRefreshingDependencies] = useState(false);
  const [policies, setPolicies] = useState<ProjectEffectivePolicies | null>(null);
  const [importStatus, setImportStatus] = useState<ProjectImportStatus | null>(null);
  const prefetchRowTimeoutsRef = useRef<Map<string, NodeJS.Timeout>>(new Map());
  const hasUserRefreshedRef = useRef(false);

  // Right panel overview (when a dependency is selected and sub-tab is Overview)
  const [panelOverview, setPanelOverview] = useState<DependencyOverviewResponse | null>(null);
  const [panelOverviewDepId, setPanelOverviewDepId] = useState<string | null>(null);
  const [panelOverviewLoading, setPanelOverviewLoading] = useState(false);
  const [panelOverviewError, setPanelOverviewError] = useState<string | null>(null);
  // Supply chain + newest-safe-version for the selected dep — also fetched with the overview
  // (in parallel) and committed together, so the whole package pane paints in one go instead
  // of the supply-chain block popping in after. Passed down to SupplyChainSections as `preloaded`.
  const [panelSupplyChain, setPanelSupplyChain] = useState<SupplyChainResponse | null>(null);
  const [panelSafeVersion, setPanelSafeVersion] = useState<{ version: string | null; isCurrent: boolean } | null>(null);
  const [panelReloadNonce, setPanelReloadNonce] = useState(0);

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
    // Fire the list rebuild and (if a package is open) its overview refresh CONCURRENTLY —
    // they're independent, so total time is max(list, overview) instead of list + overview.
    // The `.catch` on the overview keeps it from becoming an unhandled rejection while we
    // await the list first (so the list paints as soon as it's ready).
    if (selectedDepId) api.clearDependencyOverviewPrefetch(organizationId, projectId, selectedDepId);
    const listP = api.getProjectDependencies(organizationId, projectId, { bypassCache: true });
    const overviewP = selectedDepId
      ? api.getDependencyOverview(organizationId, projectId, selectedDepId, { bypassCache: true }).catch(() => null)
      : null;
    try {
      const data = await listP;
      setDependencies(data);
      depsListCache.set(projectId, data);
      setDependenciesError(null);
    } catch (error: any) {
      setDependenciesError(error.message || 'Failed to load dependencies');
    }
    if (overviewP && selectedDepId) {
      const overview = await overviewP;
      if (overview) {
        setPanelOverview(overview);
        setPanelOverviewDepId(selectedDepId);
      }
    }
    // Keep spinner visible until React has committed and painted the new data
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        setRefreshingDependencies(false);
      });
    });
  }, [organizationId, projectId, selectedDepId]);

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
    // Instant paint from the client cache before any network resolves (covers a projectId
    // switch while mounted; the useState initializer covers a fresh remount; and the
    // warm-on-open prefetch — see warmProjectDepsCache — usually filled this already).
    const seededList = depsListCache.get(projectId);
    if (seededList && seededList.length > 0) setDependencies(seededList);
    // Full DB. Now that this endpoint is read-through (serves the invalidate-on-change cache
    // when warm), it's as fast as the old cachedOnly fast-path on a warm cache and the ONLY
    // list fetch we need — the separate cachedOnly request it used to fire gave no head start
    // anymore, so it's gone. List is ready when this resolves; don't wait for policies/import.
    api.getProjectDependencies(organizationId, projectId)
      .then((deps) => {
        if (cancelled || hasUserRefreshedRef.current) return;
        setDependencies(deps);
        depsListCache.set(projectId, deps);
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


  // Load EVERYTHING the package pane needs when a dependency is selected — overview,
  // capabilities, supply chain and the newest-safe-version — in parallel, and commit them in
  // one setState batch. The pane's skeleton stays until all four resolve, so the whole thing
  // (overview + supply-chain table + recommendation chip) paints at once instead of the
  // overview appearing first and the rest popping in after. panelReloadNonce lets the child's
  // "Try again" re-run this.
  useEffect(() => {
    if (!organizationId || !projectId || !selectedDepId) {
      setPanelOverview(null);
      setPanelOverviewError(null);
      setPanelSupplyChain(null);
      setPanelSafeVersion(null);
      return;
    }
    let cancelled = false;
    setPanelOverview(null);
    setPanelOverviewDepId(null);
    setPanelOverviewLoading(true);
    setPanelOverviewError(null);
    setPanelSupplyChain(null);
    setPanelSafeVersion(null);
    const depIdForFetch = selectedDepId;
    const prefetched = api.consumePrefetchedOverview(organizationId, projectId, selectedDepId);
    const overviewPromise = prefetched
      ? prefetched.then(([res]) => res).catch(() => null)
      : api.getDependencyOverview(organizationId, projectId, selectedDepId);
    // These two used to live inside SupplyChainSections (data, then safe-version waterfalled
    // after it). Fetching them here — alongside the overview — is what lets the pane paint once.
    const supplyChainPromise = api
      .getDependencySupplyChain(organizationId, projectId, selectedDepId)
      .catch(() => null);
    const safeVersionPromise = api
      .getLatestSafeVersion(organizationId, projectId, selectedDepId, 'high', true)
      .then((r) => ({ version: r.safeVersion, isCurrent: r.isCurrent }))
      .catch(() => null);
    (async () => {
      try {
        const res = await overviewPromise;
        if (cancelled) return;
        if (!res) {
          setPanelOverviewError('Failed to load dependency');
          return;
        }
        const [supplyChain, safeVersion] = await Promise.all([supplyChainPromise, safeVersionPromise]);
        if (cancelled) return;
        setPanelSupplyChain(supplyChain);
        setPanelSafeVersion(safeVersion);
        setPanelOverview(res);
        setPanelOverviewDepId(depIdForFetch);
      } catch (err: any) {
        if (!cancelled) setPanelOverviewError(err?.message ?? 'Failed to load dependency');
      } finally {
        if (!cancelled) setPanelOverviewLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [organizationId, projectId, selectedDepId, panelReloadNonce]);

  const selectedDepFromList = selectedDepId ? dependencies.find((d) => d.id === selectedDepId) : null;

  // Only use panelOverview if it was fetched for the current selectedDepId — prevents stale data flash
  const safeOverview = panelOverviewDepId === selectedDepId ? panelOverview : null;
  // Show skeleton immediately when dep changes (before the effect fires), not just when panelOverviewLoading
  const effectiveOverviewLoading = panelOverviewLoading || (!!selectedDepId && panelOverviewDepId !== selectedDepId);

  const panelDependency = useMemo(
    () => (projectId && selectedDepId && safeOverview ? buildDependencyFromOverview(projectId, selectedDepId, safeOverview, selectedDepFromList) : null),
    [projectId, selectedDepId, safeOverview, selectedDepFromList]
  );

  // Prefetch overview when hovering a package row (100ms debounce). Never for the
  // already-selected dep — its data is live in the panel, and re-arming a prefetch here
  // would snapshot a stale copy into the module-level cache (e.g. without a fresh
  // AI usage summary) that a later visit would consume.
  const handleRowHover = useCallback((depId: string) => {
    if (!organizationId || !projectId || depId === selectedDepId) return;
    const existing = prefetchRowTimeoutsRef.current.get(depId);
    if (existing) clearTimeout(existing);
    const timeout = setTimeout(() => {
      api.prefetchDependencyOverview(organizationId, projectId, depId);
      prefetchRowTimeoutsRef.current.delete(depId);
    }, 100);
    prefetchRowTimeoutsRef.current.set(depId, timeout);
  }, [organizationId, projectId, selectedDepId]);

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
          embedInSidebar ? cn('h-full min-h-0 flex-1', embedShellBg) : 'h-[100vh]',
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
        {/* Static 1px divider so the two-pane split reads the same as the loaded view (which
            shows a resize handle here). Without it the skeleton looked like a single pane. */}
        <div className="shrink-0 flex justify-center px-2 -mx-2 -ml-px" aria-hidden>
          <div className="self-stretch bg-border min-h-full shrink-0" style={{ width: 1, minWidth: 1, maxWidth: 1 }} />
        </div>
        {/* Right pane shows the real "no package selected" empty state, not a content
            skeleton — nothing is selected while loading, so this is exactly what the loaded
            view renders here anyway. Keeping it steady avoids a skeleton→empty-state flash. */}
        <div
          className={cn(
            'flex-1 min-w-0 flex flex-col overflow-hidden',
            embedInSidebar ? embedShellBg : 'bg-background-content'
          )}
        >
          <div className="flex-1 flex items-center justify-center p-8">
            <div className="flex flex-col items-center gap-4 text-center max-w-md">
              <div className="rounded-full bg-background-card/80 border border-border p-5 shadow-sm ring-1 ring-foreground/[0.04]">
                <Package className="h-10 w-10 text-foreground-secondary" aria-hidden />
              </div>
              <div className="space-y-1">
                <p className="text-base font-medium text-foreground">No package selected</p>
                <p className="text-sm text-foreground-secondary leading-relaxed">
                  Click a dependency in the list to see its version, vulnerabilities, license, and where it’s used in your code.
                </p>
              </div>
            </div>
          </div>
        </div>
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
      if (filterVulnerability && !getVulnSeverityInfo(dep)) return false;
      if (filterDev && dep.source !== 'devDependencies') return false;
      // "Unused" mirrors the row icon exactly: direct, imported by no file, and not a dev
      // dep (dev tooling isn't imported by design, so it's never flagged unused).
      const isUnused = dep.files_importing_count === 0 && dep.is_direct && dep.source !== 'devDependencies';
      if (filterUnused && !isUnused) return false;
      return true;
    })
    .sort((a, b) => (b.files_importing_count || 0) - (a.files_importing_count || 0));

  // Filter dropdown options — mirror the row tags worth filtering on.
  const filterOptions = [
    { id: 'vulnerable', label: 'Vulnerable', checked: filterVulnerability, set: setFilterVulnerability },
    { id: 'dev', label: 'Dev dependency', checked: filterDev, set: setFilterDev },
    { id: 'unused', label: 'Unused', checked: filterUnused, set: setFilterUnused },
  ];
  const anyFilterActive = filterVulnerability || filterDev || filterUnused;

  return (
    <main
      className={cn(
        'flex min-h-0 relative',
        embedInSidebar ? cn('h-full min-h-0 flex-1', embedShellBg) : 'h-[100vh]',
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
                  className="w-full pl-9 pr-4 h-9 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:ring-2 focus:ring-ring focus:border-input"
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
                    {filterOptions.map((opt) => (
                      <div
                        key={opt.id}
                        className="group flex items-center gap-2 py-1 px-0 rounded-md cursor-pointer"
                        onClick={() => opt.set((v) => !v)}
                        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); opt.set((v) => !v); } }}
                        role="option"
                        aria-selected={opt.checked}
                        tabIndex={0}
                      >
                        <Checkbox
                          id={`filter-${opt.id}`}
                          checked={opt.checked}
                          onCheckedChange={(checked) => opt.set(checked === true)}
                          className="data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
                        />
                        <label htmlFor={`filter-${opt.id}`} className="text-sm font-normal cursor-pointer flex-1 text-foreground">
                          {opt.label}
                        </label>
                        <button
                          type="button"
                          className="ml-auto opacity-0 group-hover:opacity-100 transition-opacity text-xs font-medium px-2 py-1 rounded-md border border-foreground/40 bg-transparent text-foreground hover:bg-foreground/10 focus:opacity-100 focus:outline-none"
                          onClick={(e) => { e.stopPropagation(); filterOptions.forEach((o) => o.set(o.id === opt.id)); }}
                        >
                          Select only
                        </button>
                      </div>
                    ))}
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
          {isInitialExtracting ? (
            <ExtractionProgressCard
              description={
                !realtime.isLoading && realtime.status === 'not_connected'
                  ? 'Connect a repository in Project Settings to see dependencies.'
                  : 'Dependencies will appear here once extraction completes.'
              }
              organizationId={organizationId}
              projectId={projectId}
            />
          ) : isInitialExtractionFailed ? (
            <ExtractionProgressCard
              isError
              title="Extraction failed"
              description="Dependencies will not be available until extraction succeeds."
              showLogsToggle
              organizationId={organizationId}
              projectId={projectId}
              onRetry={async () => {
                if (!organizationId || !projectId) return;
                await api.triggerProjectSync(organizationId, projectId);
              }}
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
                  : anyFilterActive
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
                      aria-current={isSelected ? 'true' : undefined}
                      className={cn(
                        'flex items-center gap-1.5 py-1.5 text-sm transition-colors duration-150 cursor-pointer',
                        rowInset,
                        // The open dependency stays tinted so it's clear which row the right
                        // pane belongs to — a persistent background, distinct from hover.
                        isSelected ? 'bg-background-subtle' : 'hover:bg-background-subtle'
                      )}
                    >
                      <EcosystemIcon ecosystem={dep.ecosystem} className="h-4 w-4 shrink-0 object-contain" />
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
                      {hasLicenseIssue && (
                        <DepTagBadge label="License" tooltip="License doesn’t match project policy" />
                      )}
                      {dep.source === 'devDependencies' && (
                        <DepTagBadge label="Dev" tooltip="Dev dependency" />
                      )}
                      {vulnInfo && (
                        <DepTagBadge label="Vulnerable" tooltip={vulnInfo.label} />
                      )}
                      {/* "Unused" = declared but imported by no source file. Only a meaningful
                          signal for runtime deps; dev tooling (eslint, tsc, jest, @types/*, build
                          tools) is used via scripts/config/type-resolution, not `import`, so 0
                          imports there is expected — flagging it "Unused" is misleading (and dev
                          scope is already floored to `unreachable` on the reachability side). */}
                      {dep.files_importing_count === 0 && dep.is_direct && dep.source !== 'devDependencies' && (
                        <DepTagBadge label="Unused" tooltip="Not imported in any file" />
                      )}
                      {dep.is_current_version_banned && (
                        <DepTagBadge label="Banned" tooltip="This version is banned by org policy" />
                      )}
                      {dep.is_outdated && (
                        <DepTagBadge
                          label={dep.versions_behind && dep.versions_behind > 0 ? `${dep.versions_behind} behind` : 'Outdated'}
                          tooltip={
                            dep.versions_behind && dep.versions_behind > 0
                              ? `${dep.versions_behind} version${dep.versions_behind > 1 ? 's' : ''} behind latest`
                              : 'A newer version is available'
                          }
                        />
                      )}
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
      {/* Right area: package detail page (overview + supply chain) when a dependency is selected */}
      <div
        className={cn(
          'flex-1 min-w-0 flex flex-col overflow-hidden',
          embedInSidebar ? embedShellBg : 'bg-background-content',
          // When the list is collapsed the rail is position:absolute (out of flow), so this
          // pane fills the full width and the rail overlays — and clips — its left edge. Inset
          // it by the rail width so nothing hides behind the collapse button.
          sidebarCollapsed && 'pl-12'
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
        ) : effectiveOverviewLoading ? (
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
            <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8 space-y-10">
              <PackageOverview
                key={selectedDepId}
                dependency={panelDependency}
                organizationId={organizationId}
                projectId={projectId}
                latestVersion={panelOverview?.latest_version ?? null}
                policies={policies}
                isDevDependency={selectedDepFromList?.source === 'devDependencies'}
              />
              {/* Supply chain folded into the package page: version tooling + vulns + brings-in.
                  Keyed by dep so version-simulation state never leaks across packages. */}
              {selectedDepId && organizationId && (
                <SupplyChainSections
                  key={selectedDepId}
                  orgId={organizationId}
                  projectId={projectId}
                  dependencyId={selectedDepId}
                  ecosystem={selectedDepFromList?.ecosystem ?? panelOverview?.ecosystem ?? null}
                  onOpenFinding={onOpenFinding}
                  preloaded={{ data: panelSupplyChain, safeVersion: panelSafeVersion }}
                  onRetry={() => setPanelReloadNonce((n) => n + 1)}
                />
              )}
            </div>
          </div>
        ) : (
          <div className="flex-1 flex items-center justify-center p-8">
            <p className="text-foreground-secondary">Unable to load overview.</p>
          </div>
        )}
      </div>
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
