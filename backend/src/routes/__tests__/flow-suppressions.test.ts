/**
 * Phase 6.5 hardening — POST/DELETE flow-suppression route tests.
 *
 * These cover the cross-tenant fix from /criticalreview P0 #1 (assertProjectInOrg
 * runs BEFORE checkProjectAccess, so a member of org A cannot suppress a flow
 * on a project that lives in org B), the anti-enumeration 404 on hash miss,
 * the 400 non-hex hash guard, and the idempotent upsert path.
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

const USER = { id: 'user-1', email: 'henry@example.com' };
const TOKEN = 'valid-token';
const ORG_ID = 'org-A';
const OTHER_ORG_ID = 'org-B';
const PROJECT_ID = 'proj-1';
const VALID_HASH = 'a'.repeat(64);

function asOrgOwner() {
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 0 },
    error: null,
  });
}

function asProjectMemberOnly() {
  // Member of org without manage perms; has project_members row → read access
  // but checkProjectManagePermission still fails (no owner team membership).
  setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: false }, display_order: 0 },
    error: null,
  });
  setTableResponse('project_members', 'single', { data: { role_id: 'role-1' }, error: null });
  setTableResponse('team_members', 'then', { data: [], error: null });
  setTableResponse('project_teams', 'then', { data: [], error: null });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: USER },
    error: null,
  });
});

describe('POST /api/organizations/:id/projects/:projectId/flow-suppressions', () => {
  it('400 when flow_signature_hash is not 64-char hex', async () => {
    asOrgOwner();
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: 'not-hex' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/64-character hex/);
  });

  it('400 when suppressed_reason is non-string', async () => {
    asOrgOwner();
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: VALID_HASH, suppressed_reason: 123 });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/suppressed_reason/);
  });

  it('404 when project lives in a different org (cross-tenant fix)', async () => {
    // Caller is owner of ORG_ID; project actually belongs to OTHER_ORG_ID.
    // assertProjectInOrg must reject BEFORE checkProjectAccess can pass.
    asOrgOwner();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: OTHER_ORG_ID },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: VALID_HASH });

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/Project not found/i);
  });

  it('404 when projects row is missing entirely (anti-enumeration)', async () => {
    asOrgOwner();
    setTableResponse('projects', 'single', { data: null, error: { message: 'not found' } });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: VALID_HASH });

    expect(res.status).toBe(404);
  });

  it('403 when caller has read access but no manage_projects permission', async () => {
    asProjectMemberOnly();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: VALID_HASH });

    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/manage_projects|manage_teams_and_projects/);
  });

  it('404 anti-enumeration when hash is not present on any flow in this project', async () => {
    asOrgOwner();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    setTableResponse('project_reachable_flows', 'then', { data: [], error: null });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: VALID_HASH });

    expect(res.status).toBe(404);
    expect(res.body.error).toMatch(/Flow not found/);
  });

  it('200 idempotent upsert on happy path', async () => {
    asOrgOwner();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    setTableResponse('project_reachable_flows', 'then', {
      data: [{ id: 'flow-1' }],
      error: null,
    });
    const insertedRow = {
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      flow_signature_hash: VALID_HASH,
      suppressed_by: USER.id,
      suppressed_reason: 'false positive',
    };
    setTableResponse('project_reachable_flow_suppressions', 'single', {
      data: insertedRow,
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ flow_signature_hash: VALID_HASH, suppressed_reason: 'false positive' });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.suppression).toEqual(insertedRow);
    // Idempotency invariant: upsert is invoked with onConflict on
    // (project_id, flow_signature_hash) so a re-suppress is a no-op write.
    expect(queryBuilder.upsert).toHaveBeenCalledWith(
      expect.objectContaining({
        organization_id: ORG_ID,
        project_id: PROJECT_ID,
        flow_signature_hash: VALID_HASH,
      }),
      expect.objectContaining({ onConflict: 'project_id,flow_signature_hash' }),
    );
  });
});

describe('DELETE /api/organizations/:id/projects/:projectId/flow-suppressions/:hash', () => {
  it('400 when path :hash is not 64-char hex', async () => {
    asOrgOwner();
    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions/zzzz`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/64-character hex/);
  });

  it('404 when project lives in a different org (cross-tenant fix)', async () => {
    asOrgOwner();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: OTHER_ORG_ID },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions/${VALID_HASH}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(404);
  });

  it('403 when caller has read access but no manage_projects permission', async () => {
    asProjectMemberOnly();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions/${VALID_HASH}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(403);
  });

  it('200 on happy path', async () => {
    asOrgOwner();
    setTableResponse('projects', 'single', {
      data: { id: PROJECT_ID, organization_id: ORG_ID },
      error: null,
    });
    // The DELETE chain resolves through .then(); registry default returns
    // {data: [], error: null} which the route treats as success.
    setTableResponse('project_reachable_flow_suppressions', 'then', {
      data: [],
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions/${VALID_HASH}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    // Verify the DELETE was scoped to (project_id, flow_signature_hash) — the
    // org_id intentionally isn't in this WHERE because assertProjectInOrg
    // already proved the project belongs to :id.
    expect(queryBuilder.delete).toHaveBeenCalled();
    expect(queryBuilder.eq).toHaveBeenCalledWith('project_id', PROJECT_ID);
    expect(queryBuilder.eq).toHaveBeenCalledWith('flow_signature_hash', VALID_HASH);
  });
});

describe('Auth gate', () => {
  it('401 without Bearer token (POST)', async () => {
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions`)
      .send({ flow_signature_hash: VALID_HASH });
    expect(res.status).toBe(401);
  });

  it('401 without Bearer token (DELETE)', async () => {
    const res = await request(app).delete(
      `/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/flow-suppressions/${VALID_HASH}`,
    );
    expect(res.status).toBe(401);
  });
});
