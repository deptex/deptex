import { Fragment, useState, useEffect, useCallback, useLayoutEffect, useMemo, useRef, type ReactNode } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  GitPullRequest,
  Loader2,
  Package,
  Search,
} from 'lucide-react';
import { api, type SupplyChainResponse, type SupplyChainChild, type ProjectVulnerability } from '../../lib/api';
import { calculateDepscore, SEVERITY_TO_CVSS } from '../../lib/scoring/depscore';
import { cn } from '../../lib/utils';
import { Button } from '../ui/button';
import { SeverityPills } from '../SeverityPills';
import { UnusedInProjectCard } from './UnusedInProjectCard';
import { getEcosystemIcon } from '../PreflightSidebar';
import { FindingRow, type SecurityTableRow } from '../security/VulnerabilityExpandableTable';
import { Tooltip, TooltipTrigger, TooltipContent } from '../ui/tooltip';
import { useToast } from '../../hooks/use-toast';

// Ancestor path visualization
function AncestorPath({
  path,
}: {
  path: Array<{ name: string; version: string; dependency_version_id: string; is_direct: boolean }>;
}) {
  return (
    <div className="flex items-center gap-1.5 flex-wrap">
      <span className="text-xs font-medium text-primary">Your App</span>
      {path.map((node, index) => (
        <div key={node.dependency_version_id} className="flex items-center gap-1.5">
          <span className="text-foreground-muted text-xs">&rarr;</span>
          <span
            className={`text-xs font-medium ${index === path.length - 1
                ? 'text-foreground'
                : node.is_direct
                  ? 'text-success'
                  : 'text-foreground-secondary'
              }`}
          >
            {node.name}
          </span>
          <span className="text-[11px] text-foreground-muted font-mono">{node.version}</span>
        </div>
      ))}
    </div>
  );
}

const TABLE_HEAD_CELL = 'text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider';
const SECTION_TITLE = 'text-sm font-medium text-foreground-secondary uppercase tracking-wider';

/** Loose vuln shape — the API rows may carry scoring fields the interface doesn't declare. */
interface RawVuln {
  osv_id: string;
  severity: string;
  summary: string | null;
  aliases: string[];
  depscore?: number | null;
  cvss_score?: number | null;
  epss_score?: number | null;
  cisa_kev?: boolean | null;
  is_reachable?: boolean | null;
  reachability_level?: string | null;
}

/**
 * Adapt a supply-chain vuln into the findings table's row shape so the shared
 * `FindingRow` renders it identically. The package name/version come from the row
 * it sits under (the collapsed FindingRow shows them as the description line), and
 * `depscore` is the already-computed, reachability-aware score so the chip matches
 * the Findings tab. Fields the collapsed row never reads are filled with safe
 * defaults. Casting through the known fields avoids an excess-property error.
 */
function toSecurityRow(v: RawVuln, depName: string, depVersion: string, depscore: number): SecurityTableRow {
  const sev = (v.severity || '').toLowerCase();
  const severity = (['critical', 'high', 'medium', 'low'].includes(sev) ? sev : 'low') as ProjectVulnerability['severity'];
  const data: ProjectVulnerability = {
    id: v.osv_id,
    osv_id: v.osv_id,
    severity,
    summary: v.summary,
    details: null,
    aliases: v.aliases ?? [],
    fixed_versions: [],
    published_at: null,
    modified_at: null,
    dependency_id: '',
    dependency_name: depName,
    dependency_version: depVersion,
    depscore,
    is_reachable: v.is_reachable ?? undefined,
    reachability_level: (v.reachability_level ?? undefined) as ProjectVulnerability['reachability_level'],
    cvss_score: v.cvss_score ?? undefined,
    epss_score: v.epss_score ?? undefined,
    cisa_kev: v.cisa_kev ?? undefined,
  };
  return { type: 'vulnerability', data };
}

/** One row of the merged packages table: the package itself, or one of its transitive deps. */
interface PackageRow {
  key: string;
  isSelf: boolean;
  name: string;
  version: string;
  license: string | null;
  counts: { critical: number; high: number; medium: number; low: number };
  vulns: RawVuln[];
}

const FADE_MASK = {
  maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
  WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
} as const;

/**
 * Height-animated drawer for expanded rows — same pattern as the findings
 * table (VulnerabilityExpandableTable): measured natural height + transition,
 * content stays mounted so reopening doesn't flash.
 */
function ExpandableDrawer({ expanded, children }: { expanded: boolean; children: ReactNode }) {
  const innerRef = useRef<HTMLDivElement>(null);
  const [contentHeight, setContentHeight] = useState(0);

  useLayoutEffect(() => {
    const el = innerRef.current;
    if (!el) return;
    const measure = () => setContentHeight(el.offsetHeight);
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  return (
    <div
      className="overflow-hidden transition-[height] duration-300 ease-in-out"
      style={{ height: expanded ? contentHeight : 0 }}
    >
      <div ref={innerRef} className={cn('px-4 pb-4', !expanded && 'invisible')}>
        {children}
      </div>
    </div>
  );
}

/** Loading skeleton — header row (title + controls) + fading table (Vercel style, like the findings table). */
function SupplyChainSectionsSkeleton() {
  return (
    <div className="space-y-8 pointer-events-none select-none" aria-busy="true" data-testid="supply-chain-skeleton">
      {/* Table with header row: section title left, bump + search controls right */}
      <div>
        <div className="flex items-center justify-between gap-3 mb-3">
          <div className="h-3.5 w-36 rounded bg-muted/40 animate-pulse" />
          <div className="flex items-center gap-3">
            <div className="h-8 w-32 rounded-lg bg-muted/40 animate-pulse" />
            <div className="h-8 w-56 rounded-lg bg-muted/40 animate-pulse" />
          </div>
        </div>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden" style={FADE_MASK}>
          <table className="w-full text-sm table-fixed">
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                {[0, 1, 2].map((c) => (
                  <th key={c} className="px-4 py-3">
                    <div className="h-3 w-16 rounded bg-muted/40 animate-pulse" />
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {Array.from({ length: 8 }, (_, i) => (
                <tr key={i} className={cn(i < 7 && 'border-b border-border')}>
                  {[0, 1, 2].map((c) => (
                    <td key={c} className="px-4 py-3">
                      <div
                        className={cn(
                          'h-4 rounded-md bg-muted/50 animate-pulse',
                          (i + c) % 3 === 0 && 'w-[70%]',
                          (i + c) % 3 === 1 && 'w-[55%]',
                          (i + c) % 3 === 2 && 'w-[80%]',
                        )}
                      />
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export interface SupplyChainSectionsProps {
  orgId: string;
  projectId: string;
  dependencyId: string;
  /** Package ecosystem (npm, pypi, ...) — children share the parent's ecosystem, so one icon serves all rows. */
  ecosystem?: string | null;
  /** Click a finding row → switch to the Findings tab and open that finding's card there. */
  onOpenFinding?: (osvId: string) => void;
  /** When the parent has already fetched the supply-chain data + newest-safe-version (so the
   *  whole package pane can paint in one commit), it passes them here and this component renders
   *  from them instead of fetching — no separate skeleton, no late pop-in. Omit to keep the
   *  self-fetching behaviour (used by tests / any other caller). */
  preloaded?: {
    data: SupplyChainResponse | null;
    safeVersion: { version: string | null; isCurrent: boolean } | null;
  };
  /** Re-run the parent's fetch — only meaningful in `preloaded` mode's error state. */
  onRetry?: () => void;
}

/**
 * Supply-chain sections of the package detail page: the latest-safe-version
 * recommendation (+ bump PRs) and the merged packages table — the package
 * itself + everything it brings in, with rows expanding to show each
 * package's vulnerabilities. Rendered below PackageOverview — owns its own
 * data fetching (consumes the supply-chain prefetch armed on row selection).
 */
export function SupplyChainSections({ orgId, projectId, dependencyId, ecosystem, onOpenFinding, preloaded, onRetry }: SupplyChainSectionsProps) {
  const { toast } = useToast();

  // Controlled mode: the parent supplied data + safe version (fetched in parallel with the
  // overview) so the whole pane paints at once. `key={dependencyId}` on this component means
  // it remounts per package, so these initialisers always reflect the current package.
  const isPreloaded = preloaded !== undefined;

  const [data, setData] = useState<SupplyChainResponse | null>(preloaded?.data ?? null);
  const [loading, setLoading] = useState(!isPreloaded);
  const [loadError, setLoadError] = useState(isPreloaded ? preloaded!.data === null : false);
  const [retryCounter, setRetryCounter] = useState(0);
  const [projectImportance, setProjectImportance] = useState<number>(1.0);
  const [showAllPaths, setShowAllPaths] = useState(false);

  // Latest safe version (recommendation): newest release with no findings >= high
  const [safeVersion, setSafeVersion] = useState<{ version: string | null; isCurrent: boolean } | null>(preloaded?.safeVersion ?? null);
  const [safeVersionLoading, setSafeVersionLoading] = useState(false);
  const safeVersionRequestRef = useRef(0);

  // Bump PR state: created this visit, or pre-existing from the response
  const [bumping, setBumping] = useState(false);
  const [createdBumpPr, setCreatedBumpPr] = useState<{ pr_url: string; pr_number: number } | null>(null);

  // Zombie (unused) package: remove PR state (from server or set after creating PR)
  const [removePrUrl, setRemovePrUrl] = useState<string | null>(preloaded?.data?.parent.remove_pr_url ?? null);
  const [removingPr, setRemovingPr] = useState(false);

  // Packages table: search + expanded rows
  const [depSearch, setDepSearch] = useState('');
  const [expandedRows, setExpandedRows] = useState<Set<string>>(new Set());

  // Load project importance for Depscore (use cache or fetch)
  useEffect(() => {
    if (!orgId || !projectId) return;
    const cached = api.getCachedProject(orgId, projectId);
    if (cached && typeof cached.importance === 'number') {
      setProjectImportance(cached.importance);
      return;
    }
    api.getProject(orgId, projectId, false).then((p) => setProjectImportance(typeof p.importance === 'number' ? p.importance : 1.0)).catch(() => {});
  }, [orgId, projectId]);

  useEffect(() => {
    if (isPreloaded) return; // parent supplied data — see the `preloaded` prop
    if (!orgId || !projectId || !dependencyId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setLoadError(false);
    setRemovePrUrl(null);
    setCreatedBumpPr(null);
    setDepSearch('');
    setExpandedRows(new Set());

    // Use prefetched data if available (armed on row selection), otherwise fetch fresh.
    // The prefetch resolves a [supplyChain, policies] tuple — policies is unused here.
    const dataPromise = api.consumePrefetchedSupplyChain(orgId, projectId, dependencyId)
      ?? Promise.all([
        api.getDependencySupplyChain(orgId, projectId, dependencyId),
        Promise.resolve(null),
      ]);

    dataPromise
      .then(([res]) => {
        if (res == null) {
          setLoadError(true);
          return;
        }
        setData(res);
        setRemovePrUrl(res.parent.remove_pr_url ?? null);
      })
      .catch((err) => {
        console.error('Failed to load supply chain data:', err);
        setLoadError(true);
      })
      .finally(() => setLoading(false));
  }, [orgId, projectId, dependencyId, retryCounter]);

  // Fetch the latest safe version (recommendation) in PARALLEL with the supply-chain data —
  // it only needs the dependency id, so gating it on `data` (as it used to) just made the
  // recommendation chip pop in a round trip after everything else. Skipped in preloaded mode.
  useEffect(() => {
    if (isPreloaded) return; // parent supplied the safe version
    if (!orgId || !projectId || !dependencyId) return;
    const requestId = ++safeVersionRequestRef.current;
    setSafeVersionLoading(true);
    api
      .getLatestSafeVersion(orgId, projectId, dependencyId, 'high', true)
      .then((res) => {
        if (requestId === safeVersionRequestRef.current) {
          setSafeVersion({ version: res.safeVersion, isCurrent: res.isCurrent });
        }
      })
      .catch((err) => {
        console.error('Failed to fetch latest safe version:', err);
        if (requestId === safeVersionRequestRef.current) {
          setSafeVersion(null);
        }
      })
      .finally(() => {
        if (requestId === safeVersionRequestRef.current) {
          setSafeVersionLoading(false);
        }
      });
  }, [orgId, projectId, dependencyId, isPreloaded]);

  // Bump handler — opens a PR updating THIS project to the newest safe version.
  const handleBump = useCallback(async () => {
    if (!orgId || !projectId || !dependencyId || !safeVersion?.version || bumping) return;
    setBumping(true);
    try {
      const result = await api.createDependencyBumpPR(orgId, projectId, dependencyId, safeVersion.version);
      setCreatedBumpPr(result);
      toast({
        title: 'Bump PR ready',
        description: `PR #${result.pr_number} updates this project to v${safeVersion.version}.`,
      });
    } catch (err: any) {
      toast({
        variant: 'destructive',
        title: 'Failed to create bump PR',
        description: err?.message ?? 'Something went wrong.',
      });
    } finally {
      setBumping(false);
    }
  }, [orgId, projectId, dependencyId, safeVersion, bumping, toast]);

  // Create PR to remove zombie (unused) dependency
  const handleCreateRemovePr = useCallback(async () => {
    if (!orgId || !projectId || !dependencyId || removingPr) return;
    setRemovingPr(true);
    try {
      const result = await api.createRemoveDependencyPR(orgId, projectId, dependencyId);
      setRemovePrUrl(result.pr_url);
      toast({
        title: result.already_exists ? 'Removal PR already exists' : 'Removal PR created',
        description: result.already_exists ? 'A PR to remove this dependency already exists.' : undefined,
      });
    } catch (err) {
      console.error('Failed to create remove PR:', err);
      toast({
        variant: 'destructive',
        title: 'Failed to create removal PR',
        description: err instanceof Error ? err.message : 'Something went wrong.',
      });
    } finally {
      setRemovingPr(false);
    }
  }, [orgId, projectId, dependencyId, removingPr, toast]);

  const children = data?.children ?? [];
  const parentVulns = data?.parent.vulnerabilities_affecting_current_version ?? data?.parent.vulnerabilities ?? [];

  const rowDepscore = useCallback((v: RawVuln): number => {
    if (v.depscore != null && Number.isFinite(v.depscore)) return v.depscore;
    return calculateDepscore({
      cvss: v.cvss_score ?? (v.severity ? (SEVERITY_TO_CVSS[v.severity] ?? 0) : 0),
      epss: v.epss_score ?? 0,
      cisaKev: v.cisa_kev ?? false,
      isReachable: v.is_reachable ?? true,
      importance: projectImportance,
    });
  }, [projectImportance]);

  // Merged packages table: the package itself first, then its children
  // (vulnerable first, alphabetical within). Rows expand to show vulnerabilities.
  const packageRows: PackageRow[] = useMemo(() => {
    if (!data) return [];

    const selfCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const v of parentVulns) {
      const s = (v.severity ?? '').toLowerCase();
      if (s === 'critical') selfCounts.critical++;
      else if (s === 'high') selfCounts.high++;
      else if (s === 'medium') selfCounts.medium++;
      else selfCounts.low++;
    }

    const selfRow: PackageRow = {
      key: '__self',
      isSelf: true,
      name: data.parent.name,
      version: data.parent.version,
      license: data.parent.license ?? null,
      counts: selfCounts,
      vulns: parentVulns as RawVuln[],
    };

    const total = (c: SupplyChainChild) => c.critical_vulns + c.high_vulns + c.medium_vulns + c.low_vulns;
    const childRows: PackageRow[] = [...children]
      .sort((a, b) => total(b) - total(a) || a.name.localeCompare(b.name))
      .map((c) => ({
        key: c.dependency_version_id,
        isSelf: false,
        name: c.name,
        version: c.version,
        license: c.license ?? null,
        counts: { critical: c.critical_vulns, high: c.high_vulns, medium: c.medium_vulns, low: c.low_vulns },
        vulns: c.vulnerabilities as RawVuln[],
      }));

    return [selfRow, ...childRows];
  }, [data, parentVulns, children]);

  // Search filters child rows by name; the package's own row stays pinned.
  const visibleRows = useMemo(() => {
    const q = depSearch.trim().toLowerCase();
    if (!q) return packageRows;
    return packageRows.filter((r) => r.isSelf || r.name.toLowerCase().includes(q));
  }, [packageRows, depSearch]);

  const toggleRow = useCallback((key: string) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  if (loading) {
    return <SupplyChainSectionsSkeleton />;
  }

  if (loadError || !data) {
    if (!loadError) return null;
    return (
      <div className="rounded-lg border border-border bg-background-card px-6 py-10 flex flex-col items-center text-center">
        <p className="text-sm font-medium text-foreground">Couldn't load supply chain</p>
        <p className="text-xs text-foreground-secondary mt-1">
          Vulnerabilities and transitive packages for this dependency couldn't be fetched.
        </p>
        <Button
          variant="outline"
          className="h-8 rounded-lg px-3 mt-4"
          onClick={() => (isPreloaded ? onRetry?.() : setRetryCounter((c) => c + 1))}
        >
          Try again
        </Button>
      </div>
    );
  }

  const isDirect = data.parent.is_direct;
  const isZombie = isDirect && data.parent.files_importing_count === 0;
  const hasAncestors = (data.ancestors?.length ?? 0) > 0;
  const displayedPaths = showAllPaths ? (data.ancestors ?? []) : (data.ancestors ?? []).slice(0, 1);
  const ecosystemIconSrc = getEcosystemIcon(ecosystem);
  // A bump PR for the newest safe version — created just now, or already open from before.
  const bumpPr =
    createdBumpPr ??
    (safeVersion?.version
      ? data.bumpPrs?.find((pr) => pr.target_version === safeVersion.version) ?? null
      : null);

  return (
    <div className="space-y-8">
      {/* Transitive dependency notice + paths */}
      {!isDirect && hasAncestors && (
        <div className="space-y-3">
          <div className="rounded-lg border border-amber-500/15 bg-amber-500/5 px-4 py-3.5">
            <div className="flex items-center gap-2.5 mb-1">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-500 flex-shrink-0" />
              <span className="text-sm font-medium text-foreground">Transitive dependency</span>
            </div>
            <p className="text-xs text-foreground-secondary leading-relaxed pl-6">
              Imported by{' '}
              <span className="font-mono font-medium text-foreground">
                {data.ancestors[0]?.[0]?.name ?? 'unknown'}
              </span>
              . To update or remove this package, manage the direct dependency that brings it in.
            </p>
          </div>

          {/* Dependency paths */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className={SECTION_TITLE}>
                Dependency Path{data.ancestors.length > 1 ? 's' : ''}
              </span>
              {data.ancestors.length > 1 && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setShowAllPaths(!showAllPaths)}
                  className="gap-1.5 h-6 text-xs text-foreground-secondary hover:text-foreground px-2"
                >
                  {showAllPaths ? 'Show primary' : `All ${data.ancestors.length} paths`}
                  {showAllPaths ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </Button>
              )}
            </div>
            <div className="space-y-2">
              {displayedPaths.map((path, idx) => (
                <div key={idx} className="rounded-lg border border-border bg-background-card px-4 py-3">
                  <AncestorPath path={path} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Brings in — the package itself + everything it pulls in; rows expand to show vulnerabilities */}
      <section aria-labelledby="supply-chain-deps-heading">
        <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
          <h2 id="supply-chain-deps-heading" className={SECTION_TITLE}>
            Brings in ({children.length})
          </h2>
          <div className="flex items-center gap-3 flex-wrap">
            {isZombie ? (
              <UnusedInProjectCard
                removePrUrl={removePrUrl ?? data.parent.remove_pr_url ?? null}
                removePrNumber={data.parent.remove_pr_number ?? null}
                onRemove={handleCreateRemovePr}
                removing={removingPr}
              />
            ) : safeVersionLoading ? (
              <div className="h-8 w-36 rounded-lg bg-muted/40 animate-pulse" aria-busy="true" aria-label="Loading newest safe version" />
            ) : bumpPr ? (
              <a
                href={bumpPr.pr_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 h-8 px-3 rounded-lg text-xs font-medium text-foreground-secondary border border-border hover:bg-foreground-secondary/10 hover:text-foreground transition-colors"
              >
                <GitPullRequest className="h-3 w-3" />
                View bump PR
              </a>
            ) : safeVersion?.version ? (
              safeVersion.isCurrent ? (
                <span className="inline-flex items-center gap-1.5 text-xs text-foreground-secondary">
                  <CheckCircle2 className="h-3.5 w-3.5 text-success shrink-0" />
                  On the newest safe version
                </span>
              ) : isDirect ? (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Button
                      variant="green"
                      className="relative h-8 rounded-lg px-3"
                      onClick={handleBump}
                      disabled={bumping}
                    >
                      {/* Keep the label in the layout (just hidden) while bumping so the button
                          doesn't shrink to the spinner's width — the spinner overlays it. */}
                      <span className={bumping ? 'invisible' : undefined}>Bump to {safeVersion.version}</span>
                      {bumping && (
                        <span className="absolute inset-0 flex items-center justify-center">
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        </span>
                      )}
                    </Button>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    Newest version with no high or critical findings — opens a PR updating this project
                  </TooltipContent>
                </Tooltip>
              ) : (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="text-xs text-foreground-secondary cursor-default">
                      Newest safe{' '}
                      <span className="text-foreground font-medium font-mono">{safeVersion.version}</span>
                    </span>
                  </TooltipTrigger>
                  <TooltipContent side="top">
                    Transitive dependency — bump the direct dependency that brings it in
                  </TooltipContent>
                </Tooltip>
              )
            ) : null}
            {children.length > 8 && (
              <div className="relative w-56">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-foreground-secondary pointer-events-none" />
                <input
                  type="text"
                  value={depSearch}
                  onChange={(e) => setDepSearch(e.target.value)}
                  placeholder="Search packages..."
                  className="w-full pl-9 pr-3 h-8 bg-background-card border border-border rounded-lg text-xs text-foreground placeholder:text-foreground-secondary focus:outline-none focus:border-foreground-secondary/50 focus:ring-1 focus:ring-foreground-secondary/20"
                />
              </div>
            )}
          </div>
        </div>
        <div className="rounded-lg border border-border bg-background-card overflow-hidden">
          <table className="w-full text-sm table-fixed">
            <colgroup>
              <col style={{ width: '52%' }} />
              <col style={{ width: '18%' }} />
              <col style={{ width: '30%' }} />
            </colgroup>
            <thead className="bg-background-card-header border-b border-border">
              <tr>
                <th className={TABLE_HEAD_CELL}>Package</th>
                <th className={TABLE_HEAD_CELL}>License</th>
                <th className={TABLE_HEAD_CELL}>Findings</th>
              </tr>
            </thead>
            <tbody>
              {visibleRows.map((row, idx) => {
                const hasFindings = row.counts.critical + row.counts.high + row.counts.medium + row.counts.low > 0;
                const expandable = hasFindings && row.vulns.length > 0;
                const isExpanded = expandable && expandedRows.has(row.key);
                const isLast = idx === visibleRows.length - 1;
                return (
                  <Fragment key={row.key}>
                    <tr
                      className={cn(
                        'transition-colors',
                        expandable && 'cursor-pointer',
                        isExpanded ? 'hover:bg-transparent' : cn('hover:bg-table-hover/50', !isLast && 'border-b border-border')
                      )}
                      aria-expanded={expandable ? isExpanded : undefined}
                      onClick={expandable ? () => toggleRow(row.key) : undefined}
                    >
                      <td className="px-4 py-3 min-w-0">
                        <div className="flex items-center gap-2.5 min-w-0">
                          {ecosystemIconSrc ? (
                            <img src={ecosystemIconSrc} alt="" className="h-4 w-4 shrink-0 object-contain" aria-hidden />
                          ) : (
                            <Package className="h-4 w-4 shrink-0 text-foreground-secondary" aria-hidden />
                          )}
                          <span className="min-w-0 truncate text-sm">
                            <span className="font-medium text-foreground">{row.name}</span>
                            <span className="text-foreground-secondary">@{row.version}</span>
                          </span>
                          {row.isSelf && (
                            <span className="shrink-0 inline-flex items-center px-1.5 py-0.5 rounded-md text-[10px] font-medium border border-border text-foreground-secondary">
                              This package
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 min-w-0">
                        {row.license && row.license !== 'Unknown' ? (
                          <span className="inline-flex max-w-full items-center px-1.5 py-0.5 rounded-md text-[10px] font-medium border border-border/60 text-foreground-secondary">
                            <span className="truncate">{row.license}</span>
                          </span>
                        ) : (
                          <span className="text-xs text-foreground-muted">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-between gap-2">
                          <SeverityPills
                            critical={row.counts.critical}
                            high={row.counts.high}
                            medium={row.counts.medium}
                            low={row.counts.low}
                          />
                          {expandable && (
                            <ChevronDown
                              className={cn(
                                'h-3.5 w-3.5 text-foreground-secondary shrink-0 transition-transform duration-200',
                                isExpanded && 'rotate-180'
                              )}
                            />
                          )}
                        </div>
                      </td>
                    </tr>

                    {/* Expanded content — this package's vulnerabilities */}
                    {expandable && (
                      <tr className={cn(!isLast && (isExpanded ? 'border-b border-border' : 'border-b border-transparent'))} data-expanded-content>
                        <td colSpan={3} className="p-0">
                          <ExpandableDrawer expanded={isExpanded}>
                            {/* Findings render with the SAME FindingRow as the Findings tab —
                                clicking one switches to that tab and opens its card there, so the
                                rich finding detail lives in exactly one place. */}
                            <div className="rounded-lg border border-border bg-background-subtle/30 overflow-hidden">
                              <table className="w-full text-sm table-fixed">
                                <colgroup>
                                  <col />
                                  <col className="w-[8rem]" />
                                </colgroup>
                                <tbody>
                                  {row.vulns.map((v, vi) => (
                                    <FindingRow
                                      key={v.osv_id}
                                      row={toSecurityRow(v, row.name, row.version, rowDepscore(v))}
                                      isLast={vi === row.vulns.length - 1}
                                      onClick={() => onOpenFinding?.(v.osv_id)}
                                    />
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </ExpandableDrawer>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
              {children.length === 0 && (
                <tr>
                  <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                    {data.parent.name}@{data.parent.version} doesn't pull in any other packages.
                  </td>
                </tr>
              )}
              {children.length > 0 && visibleRows.length === 1 && (
                <tr>
                  <td colSpan={3} className="px-4 py-6 text-center text-sm text-foreground-secondary">
                    No packages match "{depSearch}".
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
