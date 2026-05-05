import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

const mockUser = { id: 'user-1', email: 'henry@example.com' };
const token = 'valid-token';
const orgId = 'org-A';
const projectId = 'proj-1';
const findingId = 'finding-1';

function grantOrgOwner() {
  setTableResponse('organization_members', 'single', {
    data: { role: 'owner' },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
}

function denyOrgAccess() {
  setTableResponse('organization_members', 'single', {
    data: null,
    error: { message: 'not found' },
  });
}

function grantProjectMemberOnly() {
  // Member of org without org-wide permission, but is a direct project member
  // → can list/read but not manage.
  setTableResponse('organization_members', 'single', {
    data: { role: 'member' },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: false }, display_order: 0 },
    error: null,
  });
  setTableResponse('project_members', 'single', {
    data: { role_id: 'role-1' },
    error: null,
  });
  setTableResponse('team_members', 'then', { data: [], error: null });
  setTableResponse('project_teams', 'then', { data: [], error: null });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  // Default: org owner with full manage perms (overridable per-test).
  setTableResponse('organization_members', 'single', {
    data: { role: 'owner' },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
});

describe('scanner-findings tenant isolation (all 7 endpoints)', () => {
  it.each([
    ['GET', `/api/organizations/${orgId}/projects/${projectId}/iac-findings`],
    ['PATCH', `/api/organizations/${orgId}/projects/${projectId}/iac-findings/${findingId}/ignore`],
    ['PATCH', `/api/organizations/${orgId}/projects/${projectId}/iac-findings/${findingId}/risk-accept`],
    ['GET', `/api/organizations/${orgId}/projects/${projectId}/container-findings`],
    ['PATCH', `/api/organizations/${orgId}/projects/${projectId}/container-findings/${findingId}/ignore`],
    ['PATCH', `/api/organizations/${orgId}/projects/${projectId}/container-findings/${findingId}/risk-accept`],
    ['GET', `/api/organizations/${orgId}/projects/${projectId}/scanner-summary`],
  ])('returns 404 when caller is not in the org (%s %s)', async (method, url) => {
    denyOrgAccess();
    const req =
      method === 'GET'
        ? request(app).get(url)
        : request(app).patch(url).send({});
    const res = await req.set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/permission|access|not found/i);
  });

  it.each([
    `/api/organizations/${orgId}/projects/${projectId}/iac-findings/${findingId}/ignore`,
    `/api/organizations/${orgId}/projects/${projectId}/iac-findings/${findingId}/risk-accept`,
    `/api/organizations/${orgId}/projects/${projectId}/container-findings/${findingId}/ignore`,
    `/api/organizations/${orgId}/projects/${projectId}/container-findings/${findingId}/risk-accept`,
  ])('returns 403 on mutation when caller has read access but no manage permission (%s)', async (url) => {
    grantProjectMemberOnly();
    // Mutation routes call checkProjectManagePermission AFTER checkProjectAccess.
    // checkProjectAccess returns hasAccess=true via project_members row, then the
    // manage check must read organization_members + organization_roles again.
    pushTableResponse('organization_members', 'single', {
      data: { role: 'member' },
      error: null,
    });
    pushTableResponse('organization_roles', 'single', {
      data: { permissions: { manage_teams_and_projects: false } },
      error: null,
    });
    pushTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app)
      .patch(url)
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/permission|manage/i);
  });
});

describe('scanner-findings happy paths', () => {
  it('lists IaC findings, filtered by severity', async () => {
    setTableResponse('projects', 'single', {
      data: { active_extraction_run_id: 'run-1' },
      error: null,
    });
    setTableResponse('project_iac_findings', 'count_head', {
      data: null,
      error: null,
      count: 1,
    });
    setTableResponse('project_iac_findings', 'then', {
      data: [
        {
          id: findingId,
          rule_id: 'CKV_AWS_20',
          framework: 'terraform',
          severity: 'CRITICAL',
          status: 'open',
        },
      ],
      error: null,
    });

    const res = await request(app)
      .get(
        `/api/organizations/${orgId}/projects/${projectId}/iac-findings?severity=CRITICAL`
      )
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0].rule_id).toBe('CKV_AWS_20');
  });

  it.each([
    'terraform',
    'kubernetes',
    'dockerfile',
    'helm',
    'cloudformation',
    'arm',
    'bicep',
    'serverless',
    'github_actions',
  ])('accepts framework=%s on the iac-findings list filter', async (framework) => {
    setTableResponse('projects', 'single', {
      data: { active_extraction_run_id: 'run-1' },
      error: null,
    });
    setTableResponse('project_iac_findings', 'count_head', {
      data: null,
      error: null,
      count: 0,
    });
    setTableResponse('project_iac_findings', 'then', {
      data: [],
      error: null,
    });

    const res = await request(app)
      .get(
        `/api/organizations/${orgId}/projects/${projectId}/iac-findings?framework=${framework}`
      )
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ data: [], total: 0 });
  });

  it('ignores an unknown framework filter value (does not 400)', async () => {
    // The filter is silently dropped when the value is outside the v2 set —
    // unknown values fall through and return the unfiltered (project + run)
    // row set rather than failing the request.
    setTableResponse('projects', 'single', {
      data: { active_extraction_run_id: 'run-1' },
      error: null,
    });
    setTableResponse('project_iac_findings', 'count_head', {
      data: null,
      error: null,
      count: 0,
    });
    setTableResponse('project_iac_findings', 'then', {
      data: [],
      error: null,
    });

    const res = await request(app)
      .get(
        `/api/organizations/${orgId}/projects/${projectId}/iac-findings?framework=ansible`
      )
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  it('toggles IaC ignore status', async () => {
    // Default beforeEach already grants org owner + manage perms.
    // The mock's `.then` is shared with the data list endpoint, so the toggle
    // route reads `count` off the awaited builder which the mock can't fully
    // simulate; the test asserts only that the auth path produces a non-error
    // response shape.
    setTableResponse('project_iac_findings', 'then', {
      data: [{ id: findingId }],
      error: null,
      count: 1,
    } as any);

    const res = await request(app)
      .patch(
        `/api/organizations/${orgId}/projects/${projectId}/iac-findings/${findingId}/ignore`
      )
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(200);
    expect(res.body.status).toBe('ignored');
  });

  it('returns scanner-summary with the expected response shape', async () => {
    // The mock queryBuilder shares `_table` across calls, so the route's
    // Promise.all over two finding tables can't distinguish data per table.
    // We assert the response *shape* and infra/last-scan plumbing instead of
    // per-table counts; counts are exercised by the e2e fixture work in M5.
    setTableResponse('projects', 'single', {
      data: {
        active_extraction_run_id: 'run-1',
        infra_types: ['terraform', 'dockerfile'],
      },
      error: null,
    });
    setTableResponse('scan_jobs', 'maybeSingle', {
      data: { completed_at: '2026-04-29T00:00:00Z' },
      error: null,
    });

    const res = await request(app)
      .get(`/api/organizations/${orgId}/projects/${projectId}/scanner-summary`)
      .set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({
      iac: expect.objectContaining({
        critical: expect.any(Number),
        high: expect.any(Number),
        ignored: expect.any(Number),
      }),
      container: expect.objectContaining({
        critical: expect.any(Number),
        ignored: expect.any(Number),
      }),
      infra_types: ['terraform', 'dockerfile'],
      last_scan_at: '2026-04-29T00:00:00Z',
      skipped_images: [],
    });
  });
});
