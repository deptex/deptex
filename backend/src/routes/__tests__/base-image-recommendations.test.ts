import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
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
const recId = 'rec-1';

const RECS_BASE = `/api/organizations/${orgId}/projects/${projectId}/base-image-recommendations`;
const DISMISS_URL = `${RECS_BASE}/${recId}/dismiss`;
const SUGGEST_URL = `/api/organizations/${orgId}/projects/${projectId}/base-image-suggestions`;

// ---- mock-state helpers ----------------------------------------------------

/** projectBelongsToOrg bind used by checkProjectAccess + checkProjectManagePermission. */
function bindProjectToOrg(orgForProject = orgId) {
  setTableResponse('projects', 'maybeSingle', {
    data: { organization_id: orgForProject },
    error: null,
  });
}

/** assertProjectInOrg + getActiveExtractionId both read projects.single(). */
function setProjectSingle(data: Record<string, unknown> | null, error: unknown = null) {
  setTableResponse('projects', 'single', { data, error });
}

function setOrgRole(perms: Record<string, boolean>, role = 'owner') {
  setTableResponse('organization_members', 'single', { data: { role }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: perms, display_order: 0 },
    error: null,
  });
}

function denyOrgMembership() {
  setTableResponse('organization_members', 'single', {
    data: null,
    error: { message: 'not found' },
  });
}

function grantTeamViewer() {
  // Org member without org-wide perms, reaches the project via a team.
  // checkProjectAccess succeeds because the project_teams join matches; the
  // manage-permission gate still fails because the team has no is_owner flag.
  setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: false }, display_order: 0 },
    error: null,
  });
  setTableResponse('project_members', 'single', { data: null, error: { message: 'none' } });
  setTableResponse('team_members', 'then', { data: [{ team_id: 'team-1' }], error: null });
  setTableResponse('project_teams', 'then', { data: [{ team_id: 'team-1' }], error: null });
}

function loadRecommendation(data: Record<string, unknown> | null) {
  setTableResponse('project_base_image_recommendations', 'maybeSingle', { data, error: null });
}

const validRecRow = {
  id: recId,
  project_id: projectId,
  dockerfile_path: 'Dockerfile',
  recommended_image: 'cgr.dev/chainguard/node:20',
};

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  bindProjectToOrg(orgId);
  setOrgRole({ manage_teams_and_projects: true }, 'owner');
  setProjectSingle({ id: projectId, organization_id: orgId, active_extraction_run_id: 'run-1' });
  setTableResponse('project_base_image_recommendations', 'then', { data: [], error: null });
  setTableResponse('activities', 'then', { data: null, error: null });
});

// ============================================================
// GET — list recommendations
// ============================================================

describe('GET base-image-recommendations', () => {
  it('returns the active recommendations for the project', async () => {
    setTableResponse('project_base_image_recommendations', 'then', {
      data: [{ id: recId, dockerfile_path: 'Dockerfile', recommended_image: 'cgr.dev/chainguard/node:20' }],
      error: null,
    });
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.recommendations).toHaveLength(1);
  });

  it('returns an empty list when the project has no active extraction', async () => {
    setProjectSingle({ id: projectId, organization_id: orgId, active_extraction_run_id: null });
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
    expect(res.body.recommendations).toEqual([]);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await request(app).get(RECS_BASE);
    expect(res.status).toBe(401);
  });

  it('returns 404 when the caller is not a member of the org', async () => {
    denyOrgMembership();
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('allows a team-scoped viewer to list recommendations', async () => {
    grantTeamViewer();
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  it('returns 500 when the recommendations query fails', async () => {
    setTableResponse('project_base_image_recommendations', 'then', {
      data: null,
      error: { message: 'db down' },
    });
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(500);
  });

  it('does not leak the raw database error to the client', async () => {
    setTableResponse('project_base_image_recommendations', 'then', {
      data: null,
      error: { message: 'connection string secret leaked' },
    });
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(JSON.stringify(res.body)).not.toMatch(/secret leaked/);
  });
});

// ============================================================
// POST — dismiss
// ============================================================

describe('POST dismiss', () => {
  it('dismisses a recommendation and writes an activity log', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    const activitySpy = jest.spyOn(supabase, 'from');
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(activitySpy).toHaveBeenCalledWith('activities');
  });

  it('rejects an unauthenticated request', async () => {
    const res = await request(app).post(DISMISS_URL).send({});
    expect(res.status).toBe(401);
  });

  it('returns 404 when the recommendation id does not exist', async () => {
    loadRecommendation(null);
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(404);
  });

  it('returns 404 when the recommendation belongs to a project in another org', async () => {
    loadRecommendation(validRecRow);
    // assertProjectInOrg sees the project under a DIFFERENT org.
    setProjectSingle({ id: projectId, organization_id: 'org-B' });
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(404);
  });

  it('returns 404 when the URL projectId does not match the recommendation row', async () => {
    loadRecommendation({ ...validRecRow, project_id: 'proj-OTHER' });
    setProjectSingle({ id: 'proj-OTHER', organization_id: orgId });
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(404);
  });

  it('returns 403 when a member lacks manage_teams_and_projects', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    setOrgRole({ manage_teams_and_projects: false }, 'member');
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/permission/i);
  });

  it('allows a non-owner role that does carry manage_teams_and_projects', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    setOrgRole({ manage_teams_and_projects: true }, 'member');
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(200);
  });

  it('returns 500 when the update fails', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    setTableResponse('project_base_image_recommendations', 'then', {
      data: null,
      error: { message: 'update failed' },
    });
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(500);
  });
});

// ============================================================
// POST — suggest
// ============================================================

describe('POST base-image-suggestions', () => {
  it('logs a catalog-suggestion request', async () => {
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('returns 403 when a member lacks manage_teams_and_projects', async () => {
    setOrgRole({ manage_teams_and_projects: false }, 'member');
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(403);
    expect(res.body.error).toMatch(/permission/i);
  });

  it('allows a non-owner role that does carry manage_teams_and_projects', async () => {
    setOrgRole({ manage_teams_and_projects: true }, 'member');
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(200);
  });

  it('rejects a missing source_image', async () => {
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('rejects an over-long source_image', async () => {
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'x'.repeat(600) });
    expect(res.status).toBe(400);
  });

  it('rejects an unauthenticated request', async () => {
    const res = await request(app).post(SUGGEST_URL).send({ source_image: 'a/b:1' });
    expect(res.status).toBe(401);
  });

  it('returns 404 when the caller has no project access', async () => {
    denyOrgMembership();
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'a/b:1' });
    expect(res.status).toBe(404);
  });
});

// ============================================================
// Mandatory cross-tenant isolation matrix (5 patterns x 3 routes)
// ============================================================

describe('cross-tenant isolation', () => {
  // Pattern 1 — caller authenticated but not a member of the URL's org.
  it('GET: rejects a caller who is not in the org (pattern 1)', async () => {
    denyOrgMembership();
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('dismiss: rejects a caller who is not in the org (pattern 1)', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    denyOrgMembership(); // checkProjectManagePermission fails -> 403
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(403);
  });

  it('suggest: rejects a caller who is not in the org (pattern 1)', async () => {
    denyOrgMembership();
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(404);
  });

  // Pattern 2 — URL orgId is the caller's, but the projectId lives in another org.
  it('GET: rejects when the URL project belongs to a different org (pattern 2)', async () => {
    bindProjectToOrg('org-B'); // projectBelongsToOrg mismatch
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  it('dismiss: rejects when the recommendation project is in a different org (pattern 2)', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: 'org-B' }); // assertProjectInOrg mismatch
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(404);
  });

  it('suggest: rejects when the URL project belongs to a different org (pattern 2)', async () => {
    // projectBelongsToOrg fails first inside checkProjectAccess.
    bindProjectToOrg('org-B');
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(404);
  });

  // Pattern 3 — recommendation id from another project (dismiss-specific).
  it('dismiss: rejects a recommendation id whose project is not the URL project (pattern 3)', async () => {
    loadRecommendation({ ...validRecRow, project_id: 'proj-victim' });
    setProjectSingle({ id: 'proj-victim', organization_id: orgId });
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(404);
  });

  it('GET: a sibling project id in the same org still requires membership (pattern 3)', async () => {
    bindProjectToOrg(orgId);
    denyOrgMembership();
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(404);
  });

  // Pattern 4 — viewer-level access cannot perform the privileged action.
  it('dismiss: a viewer without manage_teams_and_projects is rejected (pattern 4)', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    setOrgRole({ manage_teams_and_projects: false }, 'member');
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(403);
  });

  it('suggest: a viewer without manage_teams_and_projects is rejected (pattern 4)', async () => {
    setOrgRole({ manage_teams_and_projects: false }, 'member');
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(403);
  });

  it('GET: a viewer WITHOUT org-wide perms but in a project team can still read (pattern 4)', async () => {
    grantTeamViewer();
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });

  // Pattern 5 — correctly-permissioned caller succeeds.
  it('dismiss: a caller with manage_teams_and_projects succeeds (pattern 5)', async () => {
    loadRecommendation(validRecRow);
    setProjectSingle({ id: projectId, organization_id: orgId });
    setOrgRole({ manage_teams_and_projects: true }, 'member');
    const res = await request(app).post(DISMISS_URL).set('Authorization', `Bearer ${token}`).send({});
    expect(res.status).toBe(200);
  });

  it('suggest: a caller with manage_teams_and_projects succeeds (pattern 5)', async () => {
    setOrgRole({ manage_teams_and_projects: true }, 'member');
    const res = await request(app)
      .post(SUGGEST_URL)
      .set('Authorization', `Bearer ${token}`)
      .send({ source_image: 'acme/internal:1.0' });
    expect(res.status).toBe(200);
  });

  it('GET: an org owner succeeds (pattern 5)', async () => {
    const res = await request(app).get(RECS_BASE).set('Authorization', `Bearer ${token}`);
    expect(res.status).toBe(200);
  });
});
