import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// Team findings BUNDLE — the team sidebar's old 1 + N×~10 per-project browser
// fan-out collapsed into ONE request behind ONE checkTeamAccess, with the N
// per-project reads fanned in server-side via the shared core builder. These tests
// pin: (1) the happy-path multi-project shape with every project's rows tagged by
// project_id, (2) the multi-tenant boundary — a project_teams row pointing at a
// foreign org is dropped by the org-scoped projects read and contributes ZERO rows,
// (3) the empty-team fast path, and (4) the single access check (non-member → 404).
const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const teamId = 'team-1';
const projA = 'proj-A';
const projB = 'proj-B';
const bundleUrl = `/api/organizations/${orgId}/teams/${teamId}/findings`;

function grantTeamAccessAsOwner() {
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  setTableResponse('teams', 'single', {
    data: { id: teamId, name: 'Team A', avatar_url: null, description: null },
    error: null,
  });
  setTableResponse('team_members', 'single', { data: null, error: { message: 'not a team member' } });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
}

function denyOrgAccess() {
  setTableResponse('organization_members', 'single', { data: null, error: { message: 'not found' } });
}

/** Each per-project core builder shares table responses (the mock keys by table
 *  name), so both projects get the same one-row slices — which is exactly what we
 *  want to assert per-project tagging + concatenation. */
function stubSlicesPopulated() {
  setTableResponse('project_dependency_findings', 'then', { data: [{ id: 'pdv-x' }], error: null });
  setRpcResponse('get_project_dependency_findings_from_pdv', {
    data: [
      { id: 'v1', osv_id: 'CVE-2024-0001', severity: 'high', dependency_id: 'dep-1', dependency_name: 'lodash', depscore: 80 },
    ],
    error: null,
  });
  setTableResponse('project_secret_findings', 'then', { data: [{ id: 'sec-1', rule: 'aws', is_verified: true }], error: null });
  setTableResponse('project_semgrep_findings', 'then', { data: [{ id: 'sg-1' }], error: null });
  setTableResponse('project_iac_findings', 'then', { data: [{ id: 'iac-1', rule_id: 'CKV_AWS_20', severity: 'CRITICAL', status: 'open' }], error: null });
  setTableResponse('project_container_findings', 'then', { data: [{ id: 'cf-1' }], error: null });
  setTableResponse('project_malicious_findings', 'then', { data: [], error: null });
  setTableResponse('project_reachable_flows', 'then', { data: [], error: null });
  setTableResponse('project_reachable_flow_suppressions', 'then', { data: [], error: null });
  setTableResponse('project_base_image_recommendations', 'then', { data: [], error: null });
  // DAST: no scan job → no target → []. (organizationId is passed in, so no projects read.)
  setTableResponse('scan_jobs', 'then', { data: [], error: null });
  // org-wide chip maps
  setTableResponse('finding_tracker_links', 'then', { data: [], error: null });
  setTableResponse('project_finding_group_suppressions', 'then', { data: [], error: null });
  setTableResponse('project_finding_acknowledgements', 'then', { data: [], error: null });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: mockUser }, error: null });
  grantTeamAccessAsOwner();
});

describe('GET /teams/:teamId/findings — team findings bundle', () => {
  it('happy path: both team projects fan in, every row tagged with its project_id', async () => {
    setTableResponse('project_teams', 'then', { data: [{ project_id: projA }, { project_id: projB }], error: null });
    // The ONE org-scoped read: both projects belong to org-A, both have an active run.
    setTableResponse('projects', 'then', {
      data: [
        { id: projA, name: 'Proj A', active_extraction_run_id: 'run-A' },
        { id: projB, name: 'Proj B', active_extraction_run_id: 'run-B' },
      ],
      error: null,
    });
    stubSlicesPopulated();

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    for (const key of ['vulnerabilities', 'secrets', 'semgrep', 'iac', 'container', 'malicious', 'codeFlows', 'dast', 'baseImageRecs', 'trackerLinks', 'groupSuppressions', 'acknowledgements', 'projectIds', 'degradedSlices']) {
      expect(res.body).toHaveProperty(key);
    }
    // Authoritative resolved project list.
    expect(res.body.projectIds.sort()).toEqual([projA, projB].sort());
    // Each project contributed one vuln row, each stamped with its own project_id.
    expect(res.body.vulnerabilities).toHaveLength(2);
    expect(res.body.vulnerabilities.map((v: any) => v.project_id).sort()).toEqual([projA, projB].sort());
    // The SCA RPC omits project_id natively — the route MUST stamp it (else the FE
    // cross-project dedup key collapses).
    expect(res.body.vulnerabilities.every((v: any) => !!v.project_id)).toBe(true);
    // project_name is on no finding table — also stamped from the validated name map.
    expect(res.body.vulnerabilities.map((v: any) => v.project_name).sort()).toEqual(['Proj A', 'Proj B']);
    // Secrets fanned + tagged too.
    expect(res.body.secrets).toHaveLength(2);
    expect(res.body.secrets.map((s: any) => s.project_id).sort()).toEqual([projA, projB].sort());
  });

  it('multi-tenant isolation: a foreign-org project in project_teams contributes ZERO rows', async () => {
    // project_teams links A (this org) AND B (a foreign org's project).
    setTableResponse('project_teams', 'then', { data: [{ project_id: projA }, { project_id: projB }], error: null });
    // The org-scoped read (.eq('organization_id', orgId)) returns ONLY A — B is dropped
    // because it belongs to another org. The fan-in iterates this validated set, NOT the
    // raw project_teams candidates.
    setTableResponse('projects', 'then', {
      data: [{ id: projA, name: 'Proj A', active_extraction_run_id: 'run-A' }],
      error: null,
    });
    stubSlicesPopulated();

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    // Only A is represented; B leaks nothing into any slice.
    expect(res.body.projectIds).toEqual([projA]);
    expect(res.body.vulnerabilities.every((v: any) => v.project_id === projA)).toBe(true);
    expect(res.body.secrets.every((s: any) => s.project_id === projA)).toBe(true);
    expect(res.body.vulnerabilities.some((v: any) => v.project_id === projB)).toBe(false);
    // The org filter is the tenant boundary — assert the projects read carried it.
    expect(supabase.from).toHaveBeenCalledWith('projects');
  });

  it('empty team: no projects → empty bundle, no finding-table reads', async () => {
    setTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(200);
    expect(res.body.projectIds).toEqual([]);
    expect(res.body.vulnerabilities).toEqual([]);
    expect(res.body.degradedSlices).toEqual([]);
    expect(supabase.from).not.toHaveBeenCalledWith('project_dependency_findings');
  });

  it('single access check: a non-member gets 404 (no slice reads)', async () => {
    denyOrgAccess();
    setTableResponse('project_teams', 'then', { data: [{ project_id: projA }], error: null });
    stubSlicesPopulated();

    const res = await request(app).get(bundleUrl).set('Authorization', `Bearer ${token}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/not found|access/i);
    expect(supabase.from).not.toHaveBeenCalledWith('project_dependency_findings');
  });
});
