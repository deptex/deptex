import { describe, it, expect } from 'vitest';
import {
  filterAndSortOrgProjects,
  findingsRank,
  projectHasInfra,
  type OrgProjectQuery,
} from '../lib/orgSidebarProjects';
import type { ProjectSecuritySummary } from '../lib/api';

// Minimal summary factory — only the fields the filter/sort logic reads.
function p(over: Partial<ProjectSecuritySummary> & { project_id: string; project_name: string }): ProjectSecuritySummary {
  return {
    team_id: null,
    vuln_count: 0,
    critical_count: 0,
    reachable_count: 0,
    worst_depscore: 0,
    semgrep_count: 0,
    secret_count: 0,
    verified_secret_count: 0,
    ...over,
  } as ProjectSecuritySummary;
}

const base: OrgProjectQuery = {
  search: '',
  teamFilter: [],
  scannerFilter: [],
  sort: { key: 'findings', dir: 'desc' },
};

const ids = (rows: ProjectSecuritySummary[]) => rows.map((r) => r.project_id);

describe('findingsRank', () => {
  it('weights severity over raw count (1 critical beats 50 lows)', () => {
    expect(findingsRank(p({ project_id: 'a', project_name: 'a', band_critical: 1 }))).toBeGreaterThan(
      findingsRank(p({ project_id: 'b', project_name: 'b', band_low: 50 })),
    );
  });
});

describe('projectHasInfra', () => {
  it('is true when container findings exist OR infra_types is non-empty', () => {
    expect(projectHasInfra(p({ project_id: 'a', project_name: 'a', has_container: true }))).toBe(true);
    expect(projectHasInfra(p({ project_id: 'b', project_name: 'b', infra_types: ['kubernetes'] }))).toBe(true);
    expect(projectHasInfra(p({ project_id: 'c', project_name: 'c', infra_types: [] }))).toBe(false);
  });
});

describe('filterAndSortOrgProjects', () => {
  const projects = [
    p({ project_id: '1', project_name: 'checkout-svc', band_high: 2, ignored_count: 5, last_scan_at: '2026-06-01T00:00:00Z', has_dast: true, repo_full_name: 'acme/checkout' }),
    p({ project_id: '2', project_name: 'auth-svc', band_critical: 1, ignored_count: 0, last_scan_at: '2026-06-03T00:00:00Z', has_container: true, repo_full_name: 'acme/auth' }),
    p({ project_id: '3', project_name: 'metrics', band_low: 9, ignored_count: 2, last_scan_at: '2026-06-02T00:00:00Z', repo_full_name: 'other/metrics' }),
  ];
  const teamNameById = new Map<string, string | null | undefined>([
    ['1', 'Payments'],
    ['2', 'Platform'],
    ['3', 'Platform'],
  ]);

  it('default sort = findings desc (riskiest first, severity-weighted)', () => {
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, base))).toEqual(['2', '1', '3']);
  });

  it('sorts by last scan ascending', () => {
    const rows = filterAndSortOrgProjects(projects, teamNameById, { ...base, sort: { key: 'lastScan', dir: 'asc' } });
    expect(ids(rows)).toEqual(['1', '3', '2']);
  });

  it('sorts by ignored descending', () => {
    const rows = filterAndSortOrgProjects(projects, teamNameById, { ...base, sort: { key: 'ignored', dir: 'desc' } });
    expect(ids(rows)).toEqual(['1', '3', '2']);
  });

  it('sorts by project name ascending', () => {
    const rows = filterAndSortOrgProjects(projects, teamNameById, { ...base, sort: { key: 'project', dir: 'asc' } });
    expect(ids(rows)).toEqual(['2', '1', '3']); // auth-svc, checkout-svc, metrics
  });

  it('search matches project name, team, or repo (case-insensitive)', () => {
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, search: 'AUTH' }))).toEqual(['2']);
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, search: 'payments' }))).toEqual(['1']);
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, search: 'other/' }))).toEqual(['3']);
  });

  it('team filter keeps only the selected teams', () => {
    const rows = filterAndSortOrgProjects(projects, teamNameById, { ...base, teamFilter: ['Platform'] });
    expect(ids(rows).sort()).toEqual(['2', '3']);
  });

  it('scanner filter keeps projects with ANY selected scanner', () => {
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, scannerFilter: ['dast'] }))).toEqual(['1']);
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, scannerFilter: ['infra'] }))).toEqual(['2']);
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, scannerFilter: ['dast', 'infra'] })).sort()).toEqual(['1', '2']);
  });

  it('scanner filter also matches a selected framework (OR with infra/dast)', () => {
    const frameworkById = new Map<string, string | null | undefined>([
      ['1', 'express'],
      ['2', 'django'],
      ['3', 'express'],
    ]);
    // framework token alone
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, frameworkById, scannerFilter: ['express'] })).sort()).toEqual(['1', '3']);
    // framework OR a coverage flag — django projects OR anything with DAST
    expect(ids(filterAndSortOrgProjects(projects, teamNameById, { ...base, frameworkById, scannerFilter: ['django', 'dast'] })).sort()).toEqual(['1', '2']);
    // no frameworkById passed → framework tokens simply never match
    expect(filterAndSortOrgProjects(projects, teamNameById, { ...base, scannerFilter: ['express'] })).toEqual([]);
  });

  it('stacks search + team + scanner (AND across facets)', () => {
    const rows = filterAndSortOrgProjects(projects, teamNameById, {
      ...base,
      search: 'svc',
      teamFilter: ['Platform'],
      scannerFilter: ['infra'],
    });
    expect(ids(rows)).toEqual(['2']); // auth-svc: name has "svc", team Platform, has container
  });

  it('returns [] when nothing matches', () => {
    expect(filterAndSortOrgProjects(projects, teamNameById, { ...base, search: 'zzz' })).toEqual([]);
  });
});
