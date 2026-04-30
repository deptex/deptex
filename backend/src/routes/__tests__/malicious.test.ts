import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
  setRpcResponse,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

jest.mock('../../lib/active-extraction', () => ({
  getActiveExtractionId: jest.fn().mockResolvedValue('run-1'),
}));

const ORG_A = 'org-a';
const ORG_B = 'org-b';
const PROJECT_A = 'proj-a';
const PROJECT_B = 'proj-b';
const FINDING_A = 'finding-a';
const FINDING_B = 'finding-b';

const userInOrgA = { id: 'user-a', email: 'a@example.com' };
const TOKEN = 'valid-token';

function grantOrgOwnerAccess(role: string = 'owner') {
  setTableResponse('organization_members', 'single', { data: { role }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });
}

function denyOrgMembership() {
  setTableResponse('organization_members', 'single', { data: null, error: { message: 'not a member' } });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: userInOrgA }, error: null });
});

describe('GET /api/organizations/:id/projects/:projectId/malicious-findings', () => {
  it('returns the project findings list scoped to the URL org', async () => {
    grantOrgOwnerAccess();
    setTableResponse('project_malicious_findings', 'then', {
      data: [
        { id: FINDING_A, project_id: PROJECT_A, organization_id: ORG_A, project_dependency_id: 'pd-1', dependency_id: 'dep-1', rule_id: 'guarddog/npm-install-script', scanner: 'guarddog', severity: 'high', message: 'install hook ran curl', depscore: null, suppressed: false, risk_accepted: false, created_at: '2026-04-30T00:00:00Z', extraction_run_id: 'run-1' },
      ],
      error: null,
    });
    setTableResponse('project_dependencies', 'then', { data: [{ id: 'pd-1', version: '1.2.3', dependency_id: 'dep-1' }], error: null });
    setTableResponse('dependencies', 'then', { data: [{ id: 'dep-1', name: 'evil-pkg', ecosystem: 'npm' }], error: null });

    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/projects/${PROJECT_A}/malicious-findings`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.data).toHaveLength(1);
    expect(res.body.data[0].package_name).toBe('evil-pkg');
    expect(res.body.data[0].ecosystem).toBe('npm');
  });

  it('returns 404 when the user is not a member of the URL org (cross-org)', async () => {
    denyOrgMembership();

    const res = await request(app)
      .get(`/api/organizations/${ORG_B}/projects/${PROJECT_B}/malicious-findings`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/Organization not found/i);
  });

  it('returns 403 when the user is a member of the org but not the project', async () => {
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
    setTableResponse('project_members', 'single', { data: null, error: null });
    setTableResponse('team_members', 'then', { data: [], error: null });
    setTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/projects/${PROJECT_A}/malicious-findings`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(403);
  });
});

describe('PATCH /api/organizations/:id/projects/:projectId/malicious-findings/:findingId', () => {
  it('suppresses a finding when the user has manage permission', async () => {
    grantOrgOwnerAccess();
    setTableResponse('project_malicious_findings', 'maybeSingle', {
      data: { id: FINDING_A, project_id: PROJECT_A, organization_id: ORG_A },
      error: null,
    });
    setTableResponse('project_malicious_findings', 'then', { data: null, error: null });
    setTableResponse('project_malicious_findings', 'single', { data: { dependency_id: 'dep-1' }, error: null });
    setRpcResponse('recompute_dependency_is_malicious', { data: null, error: null });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_A}/projects/${PROJECT_A}/malicious-findings/${FINDING_A}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ suppressed: true, suppressed_reason: 'internal allowlist' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
  });

  it('returns 403 when the user lacks manage permission', async () => {
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: false } }, error: null });
    setTableResponse('project_members', 'single', { data: { role_id: 'reader' }, error: null });
    setTableResponse('project_teams', 'then', { data: [{ is_owner: true, team_id: 'team-1' }], error: null });
    setTableResponse('team_members', 'single', { data: { role: 'viewer' }, error: null });
    setTableResponse('team_roles', 'single', { data: { permissions: { manage_projects: false } }, error: null });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_A}/projects/${PROJECT_A}/malicious-findings/${FINDING_A}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ suppressed: true });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/manage/i);
  });

  it('returns 404 when the finding belongs to a different project', async () => {
    grantOrgOwnerAccess();
    setTableResponse('project_malicious_findings', 'maybeSingle', {
      data: { id: FINDING_A, project_id: 'some-other-project', organization_id: ORG_A },
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_A}/projects/${PROJECT_A}/malicious-findings/${FINDING_A}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ suppressed: true });

    expect(res.status).toBe(404);
  });

  it('returns 404 when the finding belongs to a different org (defence-in-depth)', async () => {
    grantOrgOwnerAccess();
    setTableResponse('project_malicious_findings', 'maybeSingle', {
      data: { id: FINDING_A, project_id: PROJECT_A, organization_id: ORG_B },
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_A}/projects/${PROJECT_A}/malicious-findings/${FINDING_A}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ suppressed: true });

    expect(res.status).toBe(404);
  });
});

describe('Internal routes', () => {
  it('rejects feed-sync without INTERNAL_API_KEY', async () => {
    const res = await request(app)
      .post('/api/internal/malicious/feed-sync/osv')
      .send({});
    expect(res.status).toBe(401);
  });

  it('rejects unknown sources with 400', async () => {
    process.env.INTERNAL_API_KEY = 'test-internal-key';
    const res = await request(app)
      .post('/api/internal/malicious/feed-sync/aikido')
      .set('X-Internal-Api-Key', 'test-internal-key');
    expect(res.status).toBe(400);
  });
});

describe('Helper-import drift guard', () => {
  it('imports checkProjectAccess and checkProjectManagePermission from the shared module', () => {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const sharedModule = require('../project-access');
    expect(typeof sharedModule.checkProjectAccess).toBe('function');
    expect(typeof sharedModule.checkProjectManagePermission).toBe('function');
  });
});
