import type { ProjectSecuritySummary } from './api';

// Pure filter/sort logic for the org-sidebar projects table. Extracted from
// OrganizationOverviewPage so the search / team-filter / scanner-filter / sort behaviour can be
// unit-tested without mounting the (very large) overview page.

export type OrgProjectSortKey = 'project' | 'team' | 'issues' | 'ignored' | 'lastScan';
export type OrgProjectSort = { key: OrgProjectSortKey; dir: 'asc' | 'desc' };
export type OrgScannerKey = 'infra' | 'dast';

export interface OrgProjectQuery {
  search: string;
  teamFilter: string[];
  scannerFilter: OrgScannerKey[];
  sort: OrgProjectSort;
}

/** Risk-weighted "issues" magnitude — severity first, then count (1 critical > 50 lows). */
export function issuesRank(s: ProjectSecuritySummary): number {
  return (s.band_critical ?? 0) * 1e9 + (s.band_high ?? 0) * 1e6 + (s.band_medium ?? 0) * 1e3 + (s.band_low ?? 0);
}

/** Container + IaC are surfaced as one "infra" badge — true if either scanner has coverage. */
export function projectHasInfra(s: ProjectSecuritySummary): boolean {
  return !!s.has_container || (s.infra_types?.length ?? 0) > 0;
}

/**
 * Apply the search box + team/scanner filters, then sort. `teamNameById` maps a project id to its
 * owning team name (used for team search, the team filter, and team sorting). Returns a new array.
 */
export function filterAndSortOrgProjects(
  summaries: ProjectSecuritySummary[],
  teamNameById: Map<string, string | null | undefined>,
  { search, teamFilter, scannerFilter, sort }: OrgProjectQuery,
): ProjectSecuritySummary[] {
  const q = search.trim().toLowerCase();
  const dir = sort.dir === 'asc' ? 1 : -1;
  const teamOf = (s: ProjectSecuritySummary) => teamNameById.get(s.project_id) ?? '';

  const sortVal = (s: ProjectSecuritySummary): string | number => {
    switch (sort.key) {
      case 'project': return s.project_name.toLowerCase();
      case 'team': return teamOf(s).toLowerCase();
      case 'ignored': return s.ignored_count ?? 0;
      case 'lastScan': return s.last_scan_at ? new Date(s.last_scan_at).getTime() : 0;
      case 'issues':
      default: return issuesRank(s);
    }
  };

  return summaries
    .filter((s) => {
      if (q) {
        const match =
          s.project_name.toLowerCase().includes(q) ||
          teamOf(s).toLowerCase().includes(q) ||
          (s.repo_full_name ?? '').toLowerCase().includes(q);
        if (!match) return false;
      }
      if (teamFilter.length && !teamFilter.includes(teamOf(s))) return false;
      if (scannerFilter.length) {
        const ok = scannerFilter.some(
          (k) => (k === 'infra' && projectHasInfra(s)) || (k === 'dast' && !!s.has_dast),
        );
        if (!ok) return false;
      }
      return true;
    })
    .sort((a, b) => {
      const va = sortVal(a);
      const vb = sortVal(b);
      if (typeof va === 'string' || typeof vb === 'string') {
        return String(va).localeCompare(String(vb)) * dir;
      }
      return (va - vb) * dir;
    });
}
