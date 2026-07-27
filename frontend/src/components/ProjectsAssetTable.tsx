import { useState, type ReactNode } from 'react';
import { Search, FolderKanban, ChevronDown, X, Check } from 'lucide-react';
import { cn } from '../lib/utils';
import type { Project, ProjectSecuritySummary } from '../lib/api';
import { filterAndSortOrgProjects, type OrgProjectSort } from '../lib/orgSidebarProjects';
import { formatRelativeTime, prettyFramework, PROVIDER_LOGOS } from '../lib/projectDisplay';
import { SeverityPills } from './SeverityPills';
import { FrameworkIcon } from './framework-icon';
import { FindingTypeIcon } from './security/FindingTypeIcon';
import { Checkbox } from './ui/checkbox';
import { Button } from './ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger, DropdownMenuItem } from './ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';

// Polished org-style projects "asset" table — depscore-band finding pills, scanner badges, Type filter.
// Shared by the org-overview sidebar (showTeamColumn) and the team sidebar Projects tab (single team,
// so the Team column + Teams filter are hidden). Always sorted by findings, worst first.

const TH = 'text-left px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-foreground-secondary';
const THR = 'text-right px-4 py-2.5 text-xs font-semibold uppercase tracking-wider text-foreground-secondary';

// Findings uses the shared SeverityPills (kept per Henry's call — original look). Team folds into the
// project subtext line in the row below (matches the members table's `email • teams`).

// Sort options — label + one-line description (Sentry-style) + the (key, dir) the pure helper understands.
const SORT_OPTIONS: { label: string; desc: string; sort: OrgProjectSort }[] = [
  { label: 'Findings', desc: 'Most severe, most findings first.', sort: { key: 'findings', dir: 'desc' } },
  { label: 'Last scan', desc: 'Most recently scanned first.', sort: { key: 'lastScan', dir: 'desc' } },
];

/** Locked column widths — shared by the skeleton and the loaded table (both `table-fixed`) so columns
 * stay put when data arrives (no layout shift). */
function AssetColgroup() {
  return (
    <colgroup>
      <col className="w-[76px]" />
      {/* Project column has no fixed width — it absorbs the leftover space (repo + team fold in here). */}
      <col />
      <col className="w-[190px]" />
      <col className="w-[128px]" />
    </colgroup>
  );
}

/** Plain (non-interactive) header — same markup for skeleton + loaded table so heights match. */
function AssetHeader() {
  return (
    <thead className="bg-background-card-header border-b border-border">
      <tr>
        <th className={TH}>Type</th>
        <th className={TH}>Project</th>
        <th className={TH}>Findings</th>
        <th className={THR}>Last scan</th>
      </tr>
    </thead>
  );
}

/** Removable active-filter chip shown inside the search field (faceted-search style). */
function FilterChip({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex shrink-0 items-center gap-1 rounded-md bg-background-subtle px-1.5 py-0.5 text-xs text-foreground">
      <span className="max-w-[140px] truncate">{label}</span>
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${label} filter`}
        className="text-foreground-secondary transition-colors hover:text-foreground"
      >
        <X className="h-3 w-3" />
      </button>
    </span>
  );
}

export interface ProjectsAssetTableProps {
  summaries: ProjectSecuritySummary[];
  /** Backing project list — supplies framework / owner-team / repo lookups + the filter options. */
  projects: Project[];
  loading: boolean;
  error?: boolean;
  onRetry?: () => void;
  onProjectClick?: (project: Project) => void;
  /** Show the Team column + Teams filter (org context). Off for the team sidebar (single team). */
  showTeamColumn?: boolean;
  searchPlaceholder?: string;
  /** Second line of the "no projects yet" empty state. */
  emptyHint?: string;
  /** Sentence fragment for the error body, e.g. "this organization's projects". */
  errorContext?: string;
  /** Optional trailing control in the search/filter row (e.g. a "Create Project" button). */
  action?: ReactNode;
}

export function ProjectsAssetTable({
  summaries,
  projects,
  loading,
  error = false,
  onRetry,
  onProjectClick,
  showTeamColumn = true,
  searchPlaceholder = 'Search projects',
  emptyHint = 'Connect a repository to start seeing findings.',
  errorContext = 'these projects',
  action,
}: ProjectsAssetTableProps) {
  const [search, setSearch] = useState('');
  const [teamFilter, setTeamFilter] = useState<string[]>([]);
  // Scanner tokens: 'infra' (container/IaC), 'dast', or a framework id (e.g. 'express').
  const [scannerFilter, setScannerFilter] = useState<string[]>([]);
  const [sort, setSort] = useState<OrgProjectSort>({ key: 'findings', dir: 'desc' });

  const teamOptions = Array.from(
    new Set(projects.map((p) => p.owner_team_name).filter((n): n is string => !!n)),
  ).sort();
  const frameworkOptions = Array.from(
    new Set(projects.map((p) => p.framework).filter((f): f is string => !!f)),
  ).sort();
  const toggleTeam = (t: string) =>
    setTeamFilter((prev) => (prev.includes(t) ? prev.filter((x) => x !== t) : [...prev, t]));
  const toggleScanner = (k: string) =>
    setScannerFilter((prev) => (prev.includes(k) ? prev.filter((x) => x !== k) : [...prev, k]));
  // Human label for an active scanner chip: framework id → pretty name, plus the two synthetic tokens.
  const scannerLabel = (k: string) => (k === 'infra' ? 'Container / IaC' : k === 'dast' ? 'DAST' : prettyFramework(k));
  const clearAll = () => { setSearch(''); setTeamFilter([]); setScannerFilter([]); };
  const currentSort = SORT_OPTIONS.find((o) => o.sort.key === sort.key) ?? SORT_OPTIONS[0];

  // Checkbox row matching the graph's "Filter by" dropdown. The whole row toggles; the Checkbox is
  // presentational (pointer-events-none) so a direct click can't double-toggle.
  const filterRow = (key: string, checked: boolean, onToggle: () => void, label: ReactNode) => (
    <div
      key={key}
      role="option"
      aria-selected={checked}
      tabIndex={0}
      onClick={onToggle}
      onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onToggle(); } }}
      className="flex items-center gap-2 rounded-md px-1 py-1 cursor-pointer hover:bg-white/5"
    >
      <Checkbox
        checked={checked}
        tabIndex={-1}
        className="pointer-events-none data-[state=checked]:bg-foreground data-[state=checked]:text-background data-[state=checked]:border-foreground"
      />
      <span className="flex-1 truncate text-sm text-foreground">{label}</span>
    </div>
  );

  return (
    <div>
      <div className="mb-3 flex items-center gap-2">
        {/* Filter selectors — consistent labelled pill-dropdowns (Sentry-style segmented row). */}
        {showTeamColumn && teamOptions.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className={cn(
                  'group inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border bg-background-card px-3 text-sm text-foreground transition-colors',
                  teamFilter.length > 0 ? 'border-foreground-secondary/40' : 'border-border hover:border-foreground-secondary/30',
                )}
              >
                Teams
                <ChevronDown className="h-3.5 w-3.5 opacity-60 transition-transform group-data-[state=open]:rotate-180" />
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start" className="w-56 rounded-lg border-border bg-background-card shadow-lg p-0">
              <div className="px-2 py-2 max-h-[260px] overflow-y-auto">
                {teamOptions.map((t) => filterRow(`team-${t}`, teamFilter.includes(t), () => toggleTeam(t), t))}
              </div>
            </DropdownMenuContent>
          </DropdownMenu>
        )}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              className={cn(
                'group inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border bg-background-card px-3 text-sm text-foreground transition-colors',
                scannerFilter.length > 0 ? 'border-foreground-secondary/40' : 'border-border hover:border-foreground-secondary/30',
              )}
            >
              Type
              <ChevronDown className="h-3.5 w-3.5 opacity-60 transition-transform group-data-[state=open]:rotate-180" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-56 rounded-lg border-border bg-background-card shadow-lg p-0">
            <div className="px-2 py-2">
              <div className="px-1 pb-1 text-xs font-semibold uppercase tracking-wider text-foreground-secondary">Type</div>
              <div className="max-h-[260px] overflow-y-auto">
                {frameworkOptions.map((fw) =>
                  filterRow(`fw-${fw}`, scannerFilter.includes(fw), () => toggleScanner(fw), (
                    <span className="flex items-center gap-2">
                      <FrameworkIcon frameworkId={fw} size={16} className="text-white" />
                      {prettyFramework(fw)}
                    </span>
                  )),
                )}
                {filterRow('infra', scannerFilter.includes('infra'), () => toggleScanner('infra'), (
                  <span className="flex items-center gap-2">
                    <FrameworkIcon frameworkId="dockerfile" size={16} className="text-white" />
                    Container / IaC
                  </span>
                ))}
                {filterRow('dast', scannerFilter.includes('dast'), () => toggleScanner('dast'), (
                  <span className="flex items-center gap-2">
                    <FindingTypeIcon type="dast" size={16} className="text-white" />
                    DAST
                  </span>
                ))}
              </div>
            </div>
          </DropdownMenuContent>
        </DropdownMenu>

        {/* Faceted search — active team/type filters render as removable chips inside the field, with a
            single clear-all ×. Same h-9 rounded-lg language as the selectors so the row reads as one set. */}
        <div className="flex h-9 min-w-0 flex-1 items-center gap-1.5 rounded-lg border border-border bg-background-card px-3 transition-colors focus-within:border-foreground-secondary/50">
          <Search className="h-4 w-4 shrink-0 text-foreground-secondary" />
          {teamFilter.map((t) => (
            <FilterChip key={`chip-team-${t}`} label={t} onRemove={() => toggleTeam(t)} />
          ))}
          {scannerFilter.map((k) => (
            <FilterChip key={`chip-type-${k}`} label={scannerLabel(k)} onRemove={() => toggleScanner(k)} />
          ))}
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape') { e.preventDefault(); clearAll(); } }}
            placeholder={teamFilter.length + scannerFilter.length > 0 ? 'Search' : searchPlaceholder}
            className="min-w-0 flex-1 border-0 bg-transparent text-sm text-foreground outline-none placeholder:text-foreground-secondary focus:outline-none focus:ring-0"
          />
          {(search || teamFilter.length > 0 || scannerFilter.length > 0) && (
            <button
              type="button"
              onClick={clearAll}
              aria-label="Clear search and filters (Esc)"
              className="shrink-0 rounded-md border border-foreground/15 px-1.5 py-0.5 text-[11px] font-medium text-foreground-secondary transition-colors hover:bg-background-subtle hover:text-foreground"
            >
              Esc
            </button>
          )}
        </div>
        {/* Sort — single-select order dropdown after the search (Sentry-style). */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              aria-label="Sort projects"
              className="group inline-flex h-9 shrink-0 items-center gap-1.5 rounded-lg border border-border bg-background-card px-3 text-sm text-foreground transition-colors hover:border-foreground-secondary/30"
            >
              {currentSort.label}
              <ChevronDown className="h-3.5 w-3.5 opacity-60 transition-transform group-data-[state=open]:rotate-180" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64 rounded-lg border-border bg-background-card shadow-lg p-1">
            {SORT_OPTIONS.map((opt) => {
              const active = opt.sort.key === sort.key;
              return (
                <DropdownMenuItem
                  key={opt.sort.key}
                  onClick={() => setSort(opt.sort)}
                  className={cn('flex cursor-pointer items-center gap-2 px-2 py-2', active && 'bg-background-subtle')}
                >
                  <Check className={cn('h-4 w-4 shrink-0 text-foreground', active ? 'opacity-100' : 'opacity-0')} />
                  <div className="flex flex-col">
                    <span className="text-sm font-medium leading-tight text-foreground">{opt.label}</span>
                    <span className="mt-0.5 text-xs text-foreground-secondary">{opt.desc}</span>
                  </div>
                </DropdownMenuItem>
              );
            })}
          </DropdownMenuContent>
        </DropdownMenu>
        {action}
      </div>

      {loading ? (
        <div
          className="bg-background-card border border-border rounded-lg overflow-hidden pointer-events-none select-none"
          style={{
            maskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
            WebkitMaskImage: 'linear-gradient(to bottom, #000 0%, #000 35%, transparent 100%)',
          }}
        >
          <table className="w-full table-fixed">
            <AssetColgroup />
            <AssetHeader />
            <tbody className="divide-y divide-border">
              {/* animate-pulse lives on the placeholder blocks, NOT the <tr> — the divide-y borders
                  belong to the rows, so pulsing the row makes the borders flash in and out. */}
              {[1, 2, 3, 4, 5].map((i) => (
                <tr key={i}>
                  <td className="px-4 py-2.5"><div className="h-5 w-5 rounded bg-muted animate-pulse" /></td>
                  <td className="px-4 py-2.5">
                    <div className="flex flex-col gap-1.5">
                      <div className="h-4 w-28 rounded bg-muted animate-pulse" />
                      <div className="h-3 w-20 rounded bg-muted animate-pulse" />
                    </div>
                  </td>
                  <td className="px-4 py-2.5"><div className="flex items-center gap-1.5">{[0, 1, 2, 3].map((j) => (<div key={j} className="h-7 w-8 rounded-full bg-muted animate-pulse" />))}</div></td>
                  <td className="px-4 py-2.5"><div className="flex justify-end"><div className="h-4 w-14 rounded bg-muted animate-pulse" /></div></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <h3 className="text-base font-medium text-foreground mb-1">Couldn't load projects</h3>
          <p className="text-sm text-foreground-secondary max-w-[260px] mb-4">Something went wrong fetching {errorContext}.</p>
          {onRetry && (
            <Button variant="outline" onClick={onRetry} className="h-8 rounded-lg px-3">
              Try again
            </Button>
          )}
        </div>
      ) : (() => {
        const projMap = new Map(projects.map((p) => [p.id, p]));
        const teamNameById = new Map<string, string | null | undefined>(
          projects.map((p) => [p.id, p.owner_team_name]),
        );
        const frameworkById = new Map<string, string | null | undefined>(
          projects.map((p) => [p.id, p.framework]),
        );
        const filtersActive = search.trim().length > 0 || teamFilter.length > 0 || scannerFilter.length > 0;
        // Sort is user-selectable via the Sort dropdown (defaults to findings, worst first).
        const rows = filterAndSortOrgProjects(summaries, teamNameById, {
          search,
          teamFilter,
          scannerFilter,
          frameworkById,
          sort,
        });
        if (rows.length === 0) {
          return (
            <div className="flex flex-col items-center justify-center rounded-lg border border-border bg-background-card py-16 text-center">
              <div className="mb-5 flex h-16 w-16 items-center justify-center rounded-full border border-border bg-background-subtle/50">
                {filtersActive
                  ? <Search className="h-6 w-6 text-foreground-secondary" />
                  : <FolderKanban className="h-6 w-6 text-foreground-secondary" />}
              </div>
              <h3 className="mb-1.5 text-base font-semibold text-foreground">{filtersActive ? 'No projects found' : 'No projects yet'}</h3>
              <p className="max-w-[340px] text-sm leading-relaxed text-foreground-secondary">
                {filtersActive ? 'No projects match your search or filters. Try a different term, or press Esc to clear.' : emptyHint}
              </p>
            </div>
          );
        }
        return (
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <table className="w-full table-fixed">
              <AssetColgroup />
              <AssetHeader />
              <tbody className="divide-y divide-border">
                {rows.map((s) => {
                  const proj = projMap.get(s.project_id);
                  const logo = s.repo_provider ? PROVIDER_LOGOS[s.repo_provider] : null;
                  // Container + IaC collapse into one Docker badge — both are "infra we scan".
                  const hasInfra = s.has_container || (s.infra_types?.length ?? 0) > 0;
                  const clickable = !!proj && !!onProjectClick;
                  return (
                    <tr
                      key={s.project_id}
                      onClick={() => proj && onProjectClick?.(proj)}
                      className={cn('transition-colors group', clickable ? 'cursor-pointer hover:bg-table-hover' : 'opacity-70')}
                    >
                      {/* Type — framework icon + non-obvious infra coverage (Docker / K8s / Terraform) + DAST */}
                      <td className="px-4 py-2.5">
                        <div className="flex items-center gap-2">
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="flex h-5 w-5 items-center justify-center">
                                <FrameworkIcon frameworkId={proj?.framework ?? null} size={20} className="text-white" />
                              </span>
                            </TooltipTrigger>
                            <TooltipContent>{prettyFramework(proj?.framework)}</TooltipContent>
                          </Tooltip>
                          {hasInfra && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="flex h-5 w-5 items-center justify-center">
                                  <FrameworkIcon frameworkId="dockerfile" size={16} className="text-white/70" />
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>Container &amp; IaC scanning</TooltipContent>
                            </Tooltip>
                          )}
                          {s.has_dast && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="flex h-5 w-5 items-center justify-center">
                                  <FindingTypeIcon type="dast" size={16} className="text-white/70" />
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>DAST (runtime scanning)</TooltipContent>
                            </Tooltip>
                          )}
                        </div>
                      </td>
                      {/* Project — name (primary) with repo + owner-team folded into one muted subtext
                          line (Sentry culprit style; mirrors the members table's `email • teams`). */}
                      <td className="px-4 py-2.5">
                        <div className="flex min-w-0 flex-col gap-0.5">
                          <span className="truncate text-sm font-semibold text-foreground">{s.project_name}</span>
                          <span className="flex min-w-0 items-center gap-1.5 text-xs text-foreground-secondary">
                            {logo && <img src={logo} alt={s.repo_provider ?? ''} className="h-3 w-3 flex-shrink-0 rounded-sm object-contain opacity-70" />}
                            <span className="min-w-0 truncate">{s.repo_full_name ?? s.repo_provider ?? 'No repository'}</span>
                            {showTeamColumn && proj?.owner_team_name && (
                              <span className="shrink-0 whitespace-nowrap text-foreground-secondary/80">• {proj.owner_team_name}</span>
                            )}
                          </span>
                        </div>
                      </td>
                      {/* Findings — original depscore-band pills (kept per Henry's call) */}
                      <td className="px-4 py-2.5">
                        <SeverityPills critical={s.band_critical} high={s.band_high} medium={s.band_medium} low={s.band_low} />
                      </td>
                      {/* Last scan — right-aligned */}
                      <td className="px-4 py-2.5 text-right">
                        <span className="whitespace-nowrap text-sm text-foreground-secondary">{formatRelativeTime(s.last_scan_at)}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        );
      })()}
    </div>
  );
}
