import { useState, type ReactNode } from 'react';
import { Search, Filter, Users, AlertTriangle, RotateCw, FolderKanban } from 'lucide-react';
import { cn } from '../lib/utils';
import type { Project, ProjectSecuritySummary } from '../lib/api';
import { filterAndSortOrgProjects } from '../lib/orgSidebarProjects';
import { formatRelativeTime, prettyFramework, PROVIDER_LOGOS } from '../lib/projectDisplay';
import { SeverityPills } from './SeverityPills';
import { FrameworkIcon } from './framework-icon';
import { FindingTypeIcon } from './security/FindingTypeIcon';
import { Checkbox } from './ui/checkbox';
import { Button } from './ui/button';
import { DropdownMenu, DropdownMenuContent, DropdownMenuTrigger } from './ui/dropdown-menu';
import { Tooltip, TooltipContent, TooltipTrigger } from './ui/tooltip';

// Polished org-style projects "asset" table — depscore-band finding pills, scanner badges, Type filter.
// Shared by the org-overview sidebar (showTeamColumn) and the team sidebar Projects tab (single team,
// so the Team column + Teams filter are hidden). Always sorted by findings, worst first.

const TH = 'text-left px-4 py-3 text-xs font-semibold text-foreground-secondary uppercase tracking-wider';

/** Locked column widths — shared by the skeleton and the loaded table (both `table-fixed`) so columns
 * stay put when data arrives (no layout shift). The Team column (150px) is dropped when hidden. */
function AssetColgroup({ showTeamColumn }: { showTeamColumn: boolean }) {
  return (
    <colgroup>
      <col className="w-[120px]" />
      <col className="w-[200px]" />
      {showTeamColumn && <col className="w-[150px]" />}
      <col className="w-[240px]" />
      <col className="w-[190px]" />
      <col className="w-[90px]" />
      <col className="w-[140px]" />
    </colgroup>
  );
}

/** Plain (non-interactive) header — same markup for skeleton + loaded table so heights match. */
function AssetHeader({ showTeamColumn }: { showTeamColumn: boolean }) {
  return (
    <thead className="bg-background-card-header border-b border-border">
      <tr>
        <th className={TH}>Type</th>
        <th className={TH}>Project name</th>
        {showTeamColumn && <th className={TH}>Team</th>}
        <th className={TH}>Repository</th>
        <th className={TH}>Findings</th>
        <th className={TH}>Ignored</th>
        <th className={TH}>Last scan</th>
      </tr>
    </thead>
  );
}

export interface ProjectsAssetTableProps {
  summaries: ProjectSecuritySummary[];
  /** Backing project list — supplies framework / owner-team / repo lookups + the filter options. */
  projects: Project[];
  loading: boolean;
  error?: boolean;
  errorMsg?: string | null;
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
  errorMsg = null,
  onRetry,
  onProjectClick,
  showTeamColumn = true,
  searchPlaceholder = 'Search projects, teams, repos…',
  emptyHint = 'Connect a repository to start seeing findings.',
  errorContext = 'these projects',
  action,
}: ProjectsAssetTableProps) {
  const [search, setSearch] = useState('');
  const [teamFilter, setTeamFilter] = useState<string[]>([]);
  // Scanner tokens: 'infra' (container/IaC), 'dast', or a framework id (e.g. 'express').
  const [scannerFilter, setScannerFilter] = useState<string[]>([]);

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
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-foreground-secondary" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Escape' && search) { e.preventDefault(); setSearch(''); } }}
            placeholder={searchPlaceholder}
            className="w-full h-9 pl-9 pr-12 bg-background-card border border-border rounded-md text-sm text-foreground placeholder:text-foreground-secondary focus:outline-none focus:border-foreground-secondary/50 focus:ring-1 focus:ring-foreground-secondary/20"
          />
          {search && (
            <button
              type="button"
              onClick={() => setSearch('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 rounded-lg border border-foreground/15 px-2 py-1 text-xs text-foreground-secondary transition-colors hover:bg-background-subtle/85 hover:text-foreground"
            >
              Esc
            </button>
          )}
        </div>
        {showTeamColumn && teamOptions.length > 0 && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="inline-flex h-9 shrink-0 items-center gap-1.5 rounded-md border border-border bg-background-card px-3 text-sm text-foreground-secondary hover:text-foreground transition-colors"
              >
                <Users className="h-4 w-4" />
                Teams
                {teamFilter.length > 0 && (
                  <span className="ml-0.5 inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-foreground px-1 text-[10px] font-semibold text-background">{teamFilter.length}</span>
                )}
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" className="w-56 rounded-lg border-border bg-background-card shadow-lg p-0">
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
              aria-label="Filter by type"
              className="relative inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border bg-background-card text-foreground-secondary hover:text-foreground transition-colors"
            >
              <Filter className="h-4 w-4" />
              {scannerFilter.length > 0 && (
                <span className="absolute -right-1.5 -top-1.5 inline-flex h-4 min-w-[1rem] items-center justify-center rounded-full bg-foreground px-1 text-[10px] font-semibold text-background">{scannerFilter.length}</span>
              )}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56 rounded-lg border-border bg-background-card shadow-lg p-0">
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
            <AssetColgroup showTeamColumn={showTeamColumn} />
            <AssetHeader showTeamColumn={showTeamColumn} />
            <tbody className="divide-y divide-border">
              {/* animate-pulse lives on the placeholder blocks, NOT the <tr> — the divide-y borders
                  belong to the rows, so pulsing the row makes the borders flash in and out. */}
              {[1, 2, 3, 4, 5].map((i) => (
                <tr key={i}>
                  <td className="px-4 py-3"><div className="h-5 w-5 rounded bg-muted animate-pulse" /></td>
                  <td className="px-4 py-3"><div className="h-4 w-28 rounded bg-muted animate-pulse" /></td>
                  {showTeamColumn && <td className="px-4 py-3"><div className="h-4 w-20 rounded bg-muted animate-pulse" /></td>}
                  <td className="px-4 py-3"><div className="flex items-center gap-2"><div className="h-4 w-4 rounded-sm bg-muted animate-pulse" /><div className="h-4 w-24 rounded bg-muted animate-pulse" /></div></td>
                  <td className="px-4 py-3"><div className="flex items-center gap-1.5">{[0, 1, 2, 3].map((j) => (<div key={j} className="h-7 w-8 rounded-full bg-muted animate-pulse" />))}</div></td>
                  <td className="px-4 py-3"><div className="h-4 w-8 rounded bg-muted animate-pulse" /></td>
                  <td className="px-4 py-3"><div className="h-4 w-14 rounded bg-muted animate-pulse" /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : error ? (
        <div className="flex flex-col items-center justify-center py-12 text-center">
          <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
            <AlertTriangle className="h-6 w-6 text-foreground-secondary" />
          </div>
          <h3 className="text-base font-medium text-foreground mb-1">Couldn't load projects</h3>
          <p className="text-sm text-foreground-secondary max-w-[260px] mb-3">Something went wrong fetching {errorContext}.</p>
          {errorMsg && (
            <p className="text-xs text-foreground-secondary/70 font-mono max-w-[280px] mb-4 break-words">{errorMsg}</p>
          )}
          {onRetry && (
            <Button variant="outline" size="sm" onClick={onRetry}>
              <RotateCw className="h-4 w-4 mr-2" /> Try again
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
        // Always sorted by findings, worst first — no interactive sort.
        const rows = filterAndSortOrgProjects(summaries, teamNameById, {
          search,
          teamFilter,
          scannerFilter,
          frameworkById,
          sort: { key: 'findings', dir: 'desc' },
        });
        if (rows.length === 0) {
          return (
            <div className="flex flex-col items-center justify-center py-12 text-center">
              <div className="h-12 w-12 rounded-lg border border-border bg-background-subtle/50 flex items-center justify-center mb-4">
                <FolderKanban className="h-6 w-6 text-foreground-secondary" />
              </div>
              <h3 className="text-base font-medium text-foreground mb-1">{filtersActive ? 'No matches' : 'No projects yet'}</h3>
              <p className="text-sm text-foreground-secondary max-w-[260px]">
                {filtersActive ? 'No projects match your search or filters.' : emptyHint}
              </p>
            </div>
          );
        }
        return (
          <div className="bg-background-card border border-border rounded-lg overflow-hidden">
            <table className="w-full table-fixed">
              <AssetColgroup showTeamColumn={showTeamColumn} />
              <AssetHeader showTeamColumn={showTeamColumn} />
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
                      {/* Type — framework icon + non-obvious infra coverage (Docker / K8s / Terraform / …) + DAST */}
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2.5">
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
                                  <FrameworkIcon frameworkId="dockerfile" size={16} className="text-white" />
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>Container &amp; IaC scanning</TooltipContent>
                            </Tooltip>
                          )}
                          {s.has_dast && (
                            <Tooltip>
                              <TooltipTrigger asChild>
                                <span className="flex h-5 w-5 items-center justify-center">
                                  <FindingTypeIcon type="dast" size={16} className="text-white" />
                                </span>
                              </TooltipTrigger>
                              <TooltipContent>DAST (runtime scanning)</TooltipContent>
                            </Tooltip>
                          )}
                        </div>
                      </td>
                      {/* Project name */}
                      <td className="px-4 py-3">
                        <span className="truncate text-sm font-semibold text-foreground">{s.project_name}</span>
                      </td>
                      {/* Owner team (org context only) */}
                      {showTeamColumn && (
                        <td className="px-4 py-3">
                          {proj?.owner_team_name ? (
                            <span className="truncate text-sm text-foreground">{proj.owner_team_name}</span>
                          ) : (
                            <span className="text-sm text-foreground-secondary/40">—</span>
                          )}
                        </td>
                      )}
                      {/* Repository — provider logo */}
                      <td className="px-4 py-3">
                        {logo ? (
                          <div className="flex items-center gap-2 min-w-0">
                            <img src={logo} alt={s.repo_provider ?? ''} className="h-4 w-4 rounded-sm flex-shrink-0 object-contain" />
                            <span className="truncate text-sm text-foreground">{s.repo_full_name ?? s.repo_provider}</span>
                          </div>
                        ) : (
                          <span className="text-sm text-foreground-secondary/40">—</span>
                        )}
                      </td>
                      {/* Findings — depscore-band pills */}
                      <td className="px-4 py-3">
                        <SeverityPills critical={s.band_critical} high={s.band_high} medium={s.band_medium} low={s.band_low} />
                      </td>
                      {/* Ignored count */}
                      <td className="px-4 py-3">
                        <span className="text-sm text-foreground-secondary">{s.ignored_count ?? 0}</span>
                      </td>
                      {/* Last scan */}
                      <td className="px-4 py-3">
                        <span className="text-sm text-foreground-secondary whitespace-nowrap">{formatRelativeTime(s.last_scan_at)}</span>
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
