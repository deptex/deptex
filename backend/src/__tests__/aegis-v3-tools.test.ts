import {
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
  supabase,
} from '../test/mocks/supabaseSingleton';

import { ALL_AEGIS_TOOLS } from '../lib/aegis-v3/tools';
import type { AegisToolContext, AegisToolEntry } from '../lib/aegis-v3/tool-types';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const THREAD_ID = '00000000-0000-0000-0000-0000000000aa';
const PROJECT_ID = '00000000-0000-0000-0000-000000000111';
const OTHER_ORG_ID = '00000000-0000-0000-0000-000000000222';
const PD_ID = '00000000-0000-0000-0000-000000000333';
const VULN_ID = '00000000-0000-0000-0000-000000000444';

function makeCtx(): AegisToolContext {
  return {
    orgId: ORG_ID,
    userId: USER_ID,
    threadId: THREAD_ID,
    operatingMode: 'propose',
    supabase: supabase as unknown as AegisToolContext['supabase'],
  };
}

function tool(name: string): AegisToolEntry<any, any> {
  const t = ALL_AEGIS_TOOLS.find((x) => x.name === name);
  if (!t) throw new Error(`tool not found: ${name}`);
  return t as AegisToolEntry<any, any>;
}

jest.mock('../lib/latest-safe-version', () => ({
  calculateLatestSafeVersion: jest.fn(),
}));
import { calculateLatestSafeVersion } from '../lib/latest-safe-version';

jest.mock('../lib/active-extraction', () => ({
  NO_ACTIVE_RUN: '__no_active_run__',
  getActiveExtractionId: jest.fn().mockResolvedValue(null),
}));

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  (calculateLatestSafeVersion as jest.Mock).mockReset();
});

describe('registry shape', () => {
  it('exposes 12 read-only tools with safe danger and no permission gate', () => {
    expect(ALL_AEGIS_TOOLS).toHaveLength(12);
    const names = ALL_AEGIS_TOOLS.map((t) => t.name).sort();
    expect(names).toEqual(
      [
        'analyze_upgrade_path',
        'check_cisa_kev',
        'get_epss_score',
        'get_package_reputation',
        'get_project_summary',
        'get_project_vulnerabilities',
        'get_reachability_flows',
        'get_security_posture',
        'get_vulnerability_detail',
        'list_policies',
        'list_project_dependencies',
        'list_projects',
      ].sort(),
    );
    for (const t of ALL_AEGIS_TOOLS) {
      expect(t.danger).toBe('safe');
      expect(t.permission).toBeUndefined();
    }
  });
});

describe('list_projects', () => {
  it('returns rows scoped to ctx.orgId, mapped to a flat shape', async () => {
    setTableResponse('projects', 'then', {
      data: [
        {
          id: 'p1',
          name: 'Web',
          health_score: 90,
          status_id: 's1',
          framework: 'next',
          organization_statuses: { name: 'OK' },
          project_repositories: [{ status: 'connected', repo_full_name: 'org/web' }],
        },
      ],
      error: null,
    });
    const out = await tool('list_projects').execute({}, makeCtx());
    expect(out).toEqual({
      projects: [
        {
          id: 'p1',
          name: 'Web',
          health_score: 90,
          status: 'OK',
          framework: 'next',
          repo_status: 'connected',
          repo_full_name: 'org/web',
        },
      ],
    });
  });

  it('returns empty when teamId filter has no matching projects', async () => {
    setTableResponse('project_teams', 'then', { data: [], error: null });
    const out = await tool('list_projects').execute({ teamId: 'team-x' }, makeCtx());
    expect(out).toEqual({ projects: [] });
  });
});

describe('get_project_summary', () => {
  it('returns project not found when project missing', async () => {
    setTableResponse('projects', 'single', { data: null, error: null });
    const out = await tool('get_project_summary').execute({ projectId: PROJECT_ID }, makeCtx());
    expect(out).toEqual({ error: 'Project not found' });
  });

  it('rejects projects in another organization', async () => {
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, name: 'X', organization_id: OTHER_ORG_ID, health_score: 50 },
      error: null,
    });
    const out = await tool('get_project_summary').execute({ projectId: PROJECT_ID }, makeCtx());
    expect(out).toEqual({ error: 'Project not in current organization' });
  });
});

describe('list_project_dependencies', () => {
  it('returns 404 when project missing', async () => {
    setTableResponse('projects', 'single', { data: null, error: null });
    const out = await tool('list_project_dependencies').execute(
      { projectId: PROJECT_ID },
      makeCtx(),
    );
    expect(out).toEqual({ error: 'Project not found' });
  });

  it('rejects cross-org access', async () => {
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: OTHER_ORG_ID },
      error: null,
    });
    const out = await tool('list_project_dependencies').execute(
      { projectId: PROJECT_ID },
      makeCtx(),
    );
    expect(out).toEqual({ error: 'Project not in current organization' });
  });

  it('joins reputation data when deps exist', async () => {
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    setTableResponse('project_dependencies', 'then', {
      data: [
        {
          id: 'd1',
          name: 'lodash',
          version: '4.17.20',
          license: 'MIT',
          is_direct: true,
          source: 'package.json',
          is_outdated: true,
          versions_behind: 5,
        },
      ],
      error: null,
    });
    setTableResponse('dependencies', 'then', {
      data: [
        {
          name: 'lodash',
          openssf_score: 7.5,
          score: 95,
          is_malicious: false,
          latest_version: '4.17.21',
          weekly_downloads: 9000000,
        },
      ],
      error: null,
    });
    const out = (await tool('list_project_dependencies').execute(
      { projectId: PROJECT_ID },
      makeCtx(),
    )) as any;
    expect(out.totalReturned).toBe(1);
    expect(out.dependencies[0]).toMatchObject({
      name: 'lodash',
      isDirect: true,
      latestVersion: '4.17.21',
      openssfScore: 7.5,
      reputationScore: 95,
      isMalicious: false,
    });
  });
});

describe('get_project_vulnerabilities', () => {
  it('rejects cross-org access', async () => {
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: OTHER_ORG_ID },
      error: null,
    });
    const out = await tool('get_project_vulnerabilities').execute(
      { projectId: PROJECT_ID },
      makeCtx(),
    );
    expect(out).toEqual({ error: 'Project not in current organization' });
  });

  it('returns empty array when there are no vulnerabilities', async () => {
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    setTableResponse('project_dependency_vulnerabilities', 'then', { data: [], error: null });
    const out = await tool('get_project_vulnerabilities').execute(
      { projectId: PROJECT_ID },
      makeCtx(),
    );
    expect(out).toEqual({ vulnerabilities: [], totalReturned: 0 });
  });

  it('hydrates dependency info for each vulnerability', async () => {
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    pushTableResponse('project_dependency_vulnerabilities', { data: undefined, error: null });
    setTableResponse('project_dependency_vulnerabilities', 'then', {
      data: [
        {
          id: VULN_ID,
          osv_id: 'GHSA-aaaa',
          severity: 'high',
          summary: 'XSS',
          aliases: ['CVE-2024-1', 'GHSA-aaaa'],
          fixed_versions: ['1.2.3'],
          is_reachable: true,
          reachability_level: 'function',
          epss_score: 0.5,
          cvss_score: 7.1,
          cisa_kev: false,
          depscore: 88,
          published_at: '2024-01-01',
          project_dependency_id: PD_ID,
        },
      ],
      error: null,
    });
    setTableResponse('project_dependencies', 'then', {
      data: [{ id: PD_ID, name: 'react', version: '18.0.0' }],
      error: null,
    });

    const out = (await tool('get_project_vulnerabilities').execute(
      { projectId: PROJECT_ID },
      makeCtx(),
    )) as any;
    expect(out.totalReturned).toBe(1);
    expect(out.vulnerabilities[0]).toMatchObject({
      osvId: 'GHSA-aaaa',
      cveAliases: ['CVE-2024-1'],
      severity: 'high',
      isKev: false,
      isReachable: true,
      reachabilityLevel: 'function',
      depscore: 88,
      dependency: { id: PD_ID, name: 'react', version: '18.0.0' },
    });
  });
});

describe('get_security_posture', () => {
  it('returns zeros when org has no projects', async () => {
    setTableResponse('projects', 'then', { data: [], error: null });
    const out = await tool('get_security_posture').execute({}, makeCtx());
    expect(out).toEqual({ projectCount: 0, vulnCounts: null });
  });

  it('aggregates vuln counts and reachable totals', async () => {
    setTableResponse('projects', 'then', {
      data: [
        { id: 'p1', health_score: 80, status_violations: [], status_id: 's1' },
        { id: 'p2', health_score: 60, status_violations: ['banned-license'], status_id: 's2' },
      ],
      error: null,
    });
    setTableResponse('project_dependency_vulnerabilities', 'then', {
      data: [
        { severity: 'critical', is_reachable: true, cisa_kev: true, depscore: 95 },
        { severity: 'high', is_reachable: false, cisa_kev: false, depscore: 70 },
        { severity: 'low', is_reachable: false, cisa_kev: false, depscore: 10 },
      ],
      error: null,
    });
    const out = (await tool('get_security_posture').execute({}, makeCtx())) as any;
    expect(out.projectCount).toBe(2);
    expect(out.vulnCounts).toEqual({ critical: 1, high: 1, medium: 0, low: 1 });
    expect(out.reachableVulnCount).toBe(1);
    expect(out.kevVulnCount).toBe(1);
    expect(out.criticalReachableCount).toBe(1);
    expect(out.highestDepscore).toBe(95);
    expect(out.averageHealthScore).toBe(70);
    expect(out.projectsInViolation).toBe(1);
  });
});

describe('get_vulnerability_detail', () => {
  it('errors when no lookup id is provided', async () => {
    const out = await tool('get_vulnerability_detail').execute({}, makeCtx());
    expect(out).toEqual({ error: 'Provide cveId, osvId, or vulnerabilityId.' });
  });

  it('returns not-found when no rows match', async () => {
    setTableResponse('projects', 'then', { data: [{ id: 'p1', name: 'Web' }], error: null });
    setTableResponse('project_dependency_vulnerabilities', 'then', { data: [], error: null });
    const out = await tool('get_vulnerability_detail').execute({ osvId: 'GHSA-zzzz' }, makeCtx());
    expect(out).toEqual({ error: 'Vulnerability not found in this organization' });
  });
});

describe('get_reachability_flows', () => {
  it('returns 404 when vulnerability not found', async () => {
    setTableResponse('project_dependency_vulnerabilities', 'single', {
      data: null,
      error: null,
    });
    const out = await tool('get_reachability_flows').execute(
      { vulnerabilityId: VULN_ID },
      makeCtx(),
    );
    expect(out).toEqual({ error: 'Vulnerability not found' });
  });

  it('rejects cross-org access via the project lookup', async () => {
    setTableResponse('project_dependency_vulnerabilities', 'single', {
      data: {
        id: VULN_ID,
        project_id: PROJECT_ID,
        osv_id: 'GHSA-aaaa',
        reachability_level: 'function',
        reachability_details: null,
        project_dependency_id: PD_ID,
      },
      error: null,
    });
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: OTHER_ORG_ID },
      error: null,
    });
    const out = await tool('get_reachability_flows').execute(
      { vulnerabilityId: VULN_ID },
      makeCtx(),
    );
    expect(out).toEqual({ error: 'Project not in current organization' });
  });
});

describe('check_cisa_kev', () => {
  it('errors when org has no projects', async () => {
    setTableResponse('projects', 'then', { data: [], error: null });
    const out = await tool('check_cisa_kev').execute({ cveOrOsvId: 'CVE-2024-1' }, makeCtx());
    expect(out).toEqual({ error: 'No projects in this organization' });
  });

  it('returns isKev=true when any matched row is on the KEV list', async () => {
    pushTableResponse('projects', { data: undefined, error: null });
    setTableResponse('projects', 'then', {
      data: [{ id: 'p1' }, { id: 'p2' }],
      error: null,
    });
    setTableResponse('project_dependency_vulnerabilities', 'then', {
      data: [
        { osv_id: 'GHSA-aaaa', cisa_kev: false, aliases: ['CVE-2024-1'] },
        { osv_id: 'GHSA-aaaa', cisa_kev: true, aliases: ['CVE-2024-1'] },
      ],
      error: null,
    });
    const out = await tool('check_cisa_kev').execute({ cveOrOsvId: 'CVE-2024-1' }, makeCtx());
    expect(out).toEqual({ queryId: 'CVE-2024-1', isKev: true, osvId: 'GHSA-aaaa' });
  });
});

describe('get_epss_score', () => {
  it('returns the highest epss score across matched rows', async () => {
    setTableResponse('projects', 'then', { data: [{ id: 'p1' }], error: null });
    setTableResponse('project_dependency_vulnerabilities', 'then', {
      data: [
        { osv_id: 'GHSA-aaaa', epss_score: 0.4, aliases: [] },
        { osv_id: 'GHSA-aaaa', epss_score: 0.7, aliases: [] },
      ],
      error: null,
    });
    const out = await tool('get_epss_score').execute({ cveOrOsvId: 'GHSA-aaaa' }, makeCtx());
    expect(out).toEqual({
      queryId: 'GHSA-aaaa',
      osvId: 'GHSA-aaaa',
      epssScore: 0.7,
      epssPercentile: 70,
    });
  });

  it('errors when no rows match the id', async () => {
    setTableResponse('projects', 'then', { data: [{ id: 'p1' }], error: null });
    setTableResponse('project_dependency_vulnerabilities', 'then', { data: [], error: null });
    const out = (await tool('get_epss_score').execute(
      { cveOrOsvId: 'GHSA-missing' },
      makeCtx(),
    )) as any;
    expect(out.error).toContain('No EPSS data');
  });
});

describe('get_package_reputation', () => {
  it('returns reputation snapshot for a known package', async () => {
    setTableResponse('dependencies', 'maybeSingle', {
      data: {
        id: 'dep-1',
        name: 'lodash',
        status: 'analyzed',
        score: 95,
        openssf_score: 7.5,
        openssf_penalty: 1,
        popularity_penalty: 0,
        maintenance_penalty: 0,
        weekly_downloads: 9000000,
        last_published_at: '2024-01-01',
        releases_last_12_months: 12,
        github_url: 'https://github.com/lodash/lodash',
        latest_version: '4.17.21',
        latest_release_date: '2024-01-01',
        description: 'A modern utility library.',
        is_malicious: false,
        license: 'MIT',
      },
      error: null,
    });
    const out = (await tool('get_package_reputation').execute(
      { packageName: 'lodash' },
      makeCtx(),
    )) as any;
    expect(out).toMatchObject({
      name: 'lodash',
      reputationScore: 95,
      openssfScore: 7.5,
      isMalicious: false,
      scorePenalties: { openssf: 1, popularity: 0, maintenance: 0 },
    });
  });

  it('returns not-found error for an unknown package', async () => {
    setTableResponse('dependencies', 'maybeSingle', { data: null, error: null });
    const out = (await tool('get_package_reputation').execute(
      { packageName: 'nope' },
      makeCtx(),
    )) as any;
    expect(out.error).toContain('not found');
  });
});

describe('analyze_upgrade_path', () => {
  it('rejects cross-org access via the project lookup', async () => {
    pushTableResponse('project_dependencies', {
      data: { id: PD_ID, project_id: PROJECT_ID, name: 'react', version: '18.0.0' },
      error: null,
    });
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: OTHER_ORG_ID },
      error: null,
    });
    const out = await tool('analyze_upgrade_path').execute(
      { projectDependencyId: PD_ID },
      makeCtx(),
    );
    expect(out).toEqual({ error: 'Project not in current organization' });
  });

  it('delegates to calculateLatestSafeVersion and surfaces the result', async () => {
    setTableResponse('project_dependencies', 'single', {
      data: { id: PD_ID, project_id: PROJECT_ID, name: 'react', version: '18.0.0' },
      error: null,
    });
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    (calculateLatestSafeVersion as jest.Mock).mockResolvedValueOnce({
      safeVersion: '18.2.0',
      safeVersionId: 'v-id',
      isCurrent: false,
      severity: 'high',
      versionsChecked: 7,
      message: null,
    });
    const out = (await tool('analyze_upgrade_path').execute(
      { projectDependencyId: PD_ID },
      makeCtx(),
    )) as any;
    expect(out).toEqual({
      packageName: 'react',
      currentVersion: '18.0.0',
      safeVersion: '18.2.0',
      isCurrent: false,
      severityThreshold: 'high',
      versionsChecked: 7,
      message: null,
    });
    expect(calculateLatestSafeVersion).toHaveBeenCalledWith({
      organizationId: ORG_ID,
      projectId: PROJECT_ID,
      projectDependencyId: PD_ID,
      severity: 'high',
    });
  });
});

describe('list_policies', () => {
  it('returns empty summaries when no policy rows are configured', async () => {
    setTableResponse('organization_package_policies', 'maybeSingle', { data: null, error: null });
    setTableResponse('organization_status_codes', 'maybeSingle', { data: null, error: null });
    setTableResponse('organization_pr_checks', 'maybeSingle', { data: null, error: null });
    setTableResponse('organization_statuses', 'then', { data: [], error: null });
    const out = (await tool('list_policies').execute({}, makeCtx())) as any;
    expect(out.packagePolicy.configured).toBe(false);
    expect(out.projectStatusPolicy.configured).toBe(false);
    expect(out.pullRequestCheck.configured).toBe(false);
    expect(out.availableStatuses).toEqual([]);
  });

  it('summarizes configured policies with line counts and previews', async () => {
    const code = "if (dep.openssf_score < 5) return 'block';\nallow();\n";
    setTableResponse('organization_package_policies', 'maybeSingle', {
      data: { package_policy_code: code, updated_at: '2024-04-01T00:00:00Z' },
      error: null,
    });
    setTableResponse('organization_status_codes', 'maybeSingle', { data: null, error: null });
    setTableResponse('organization_pr_checks', 'maybeSingle', { data: null, error: null });
    setTableResponse('organization_statuses', 'then', {
      data: [
        { name: 'OK', is_passing: true, rank: 0, description: 'Healthy' },
        { name: 'Warning', is_passing: false, rank: 1, description: null },
      ],
      error: null,
    });
    const out = (await tool('list_policies').execute({}, makeCtx())) as any;
    expect(out.packagePolicy).toMatchObject({
      configured: true,
      updatedAt: '2024-04-01T00:00:00Z',
      lines: 3,
    });
    expect(out.packagePolicy.preview).toContain("openssf_score");
    expect(out.availableStatuses).toHaveLength(2);
    expect(out.availableStatuses[0].isPassing).toBe(true);
  });
});
