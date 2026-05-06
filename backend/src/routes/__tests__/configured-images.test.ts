/**
 * Routes for /api/organizations/:id/projects/:projectId/configured-images.
 *
 * Covers (per plan §M11 Acceptance):
 *   - GET list with cred-display join
 *   - POST create + image_reference regex validation
 *   - PATCH toggle enabled / swap cred (same-org)
 *   - DELETE
 *   - RBAC: 403 without checkProjectManagePermission
 *   - cred-from-other-org rejected with 400 cred_wrong_org (not 500)
 *   - 21st enabled POST returns 400 image_cap_reached
 *   - PATCH with extra key returns 400 unknown_field
 *   - PATCH flipping enabled true past the cap returns 400 image_cap_reached
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';
import { createActivity } from '../../lib/activities';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));
jest.mock('../../lib/activities', () => ({ createActivity: jest.fn() }));

const ORG_ID = 'org-1';
const PROJECT_ID = 'proj-x';
const USER = { id: 'user-1', email: 'a@b.com' };
const TOKEN = 'valid-token';

function setProjectManagePerm() {
  // checkProjectManagePermission: org_members -> 'admin' short-circuits true
  setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
}

function setProjectAccess() {
  // checkProjectAccess: org_members -> 'admin' short-circuits orgManageTeams
  setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 1 },
    error: null,
  });
}

function setNoMember() {
  setTableResponse('organization_members', 'single', { data: null, error: null });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
});

// ===========================================================================
// GET
// ===========================================================================
describe('GET /api/organizations/:id/projects/:projectId/configured-images', () => {
  it('returns rows with credentials_display when a cred is attached', async () => {
    setProjectAccess();
    setTableResponse('project_configured_images', 'then', {
      data: [
        {
          id: 'i1', project_id: PROJECT_ID, organization_id: ORG_ID,
          image_reference: 'ghcr.io/foo/bar:1.0', credentials_id: 'c1', enabled: true,
          created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
        },
        {
          id: 'i2', project_id: PROJECT_ID, organization_id: ORG_ID,
          image_reference: 'docker.io/library/postgres:15', credentials_id: null, enabled: true,
          created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
        },
      ],
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'then', {
      data: [{ id: 'c1', display_name: 'GHCR org token', registry_type: 'ghcr' }],
      error: null,
    });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    expect(res.body[0].credentials_display).toEqual({ display_name: 'GHCR org token', registry_type: 'ghcr' });
    expect(res.body[1].credentials_display).toBeNull();
    // Tenancy: every list query carries .eq('project_id', PROJECT_ID).
    expect(queryBuilder.eq).toHaveBeenCalledWith('project_id', PROJECT_ID);
  });

  it('returns 404 to a non-member', async () => {
    setNoMember();
    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });
});

// ===========================================================================
// POST
// ===========================================================================
describe('POST /api/organizations/:id/projects/:projectId/configured-images', () => {
  function seedSuccessfulInsert() {
    // Project resolution.
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    // Insert returning row.
    pushTableResponse('project_configured_images', {
      data: {
        id: 'i-new', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'ghcr.io/foo/bar:1.0', credentials_id: null, enabled: true,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      },
      error: null,
    });
    // Cred-display join (no creds attached → empty result).
    setTableResponse('organization_registry_credentials', 'then', { data: [], error: null });
    // Cap check — under cap.
    setTableResponse('project_configured_images', 'then', { data: [{ id: 'i-existing' }], error: null });
  }

  it('creates a public image (no cred)', async () => {
    setProjectManagePerm();
    seedSuccessfulInsert();

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'ghcr.io/foo/bar:1.0' });

    expect(res.status).toBe(201);
    expect(res.body.id).toBe('i-new');
    expect(res.body.credentials_display).toBeNull();
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'configured_image_created',
    }));
  });

  it('creates a private image with same-org cred', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    // Cred-org match check.
    pushTableResponse('organization_registry_credentials', { data: { id: 'c1', organization_id: ORG_ID }, error: null });
    setTableResponse('project_configured_images', 'then', { data: [], error: null }); // cap
    pushTableResponse('project_configured_images', {
      data: {
        id: 'i-new', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'myorg.azurecr.io/foo:tag', credentials_id: 'c1', enabled: true,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      },
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'then', {
      data: [{ id: 'c1', display_name: 'Prod ACR', registry_type: 'acr' }],
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'myorg.azurecr.io/foo:tag', credentials_id: 'c1' });

    expect(res.status).toBe(201);
    expect(res.body.credentials_id).toBe('c1');
    expect(res.body.credentials_display.registry_type).toBe('acr');
  });

  it('rejects a cred from another org with 400 cred_wrong_org (not 500)', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    // Cred-org mismatch — DIFFERENT org.
    pushTableResponse('organization_registry_credentials', {
      data: { id: 'c-other', organization_id: 'org-OTHER' },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'foo:bar', credentials_id: 'c-other' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cred_wrong_org');
    expect(createActivity).not.toHaveBeenCalled();
  });

  it('rejects malformed image_reference with 400', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'NOT VALID with spaces!!!' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/docker-pullable shape/);
  });

  it('returns 400 image_cap_reached on the 21st enabled image', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    // Cap probe — already 20 enabled rows.
    setTableResponse('project_configured_images', 'then', {
      data: Array.from({ length: 20 }, (_, i) => ({ id: `i-${i}` })),
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'foo:21' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('image_cap_reached');
    expect(res.body.message).toMatch(/limit of 20/);
  });

  it('skips the cap check when posting with enabled=false', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    // 20 enabled rows already, but the new one is disabled.
    setTableResponse('project_configured_images', 'then', {
      data: Array.from({ length: 20 }, (_, i) => ({ id: `i-${i}` })),
      error: null,
    });
    pushTableResponse('project_configured_images', {
      data: {
        id: 'i-disabled', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'foo:bar', credentials_id: null, enabled: false,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      },
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'then', { data: [], error: null });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'foo:bar', enabled: false });

    expect(res.status).toBe(201);
  });

  it('returns 403 without manage permission', async () => {
    // checkProjectManagePermission: 'member' role, no manage_teams_and_projects, no project membership.
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
    setTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'foo:bar' });

    expect(res.status).toBe(403);
  });
});

// ===========================================================================
// PATCH
// ===========================================================================
describe('PATCH /api/organizations/:id/projects/:projectId/configured-images/:imageId', () => {
  it('toggles enabled', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    pushTableResponse('project_configured_images', {
      data: {
        id: 'i1', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'foo:bar', credentials_id: null, enabled: false,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T01:00:00Z',
      },
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'then', { data: [], error: null });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ enabled: false });

    expect(res.status).toBe(200);
    expect(res.body.enabled).toBe(false);
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'configured_image_updated',
    }));
  });

  it('swaps to a same-org cred', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    // Cred-org match.
    pushTableResponse('organization_registry_credentials', {
      data: { id: 'c2', organization_id: ORG_ID }, error: null,
    });
    pushTableResponse('project_configured_images', {
      data: {
        id: 'i1', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'foo:bar', credentials_id: 'c2', enabled: true,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T01:00:00Z',
      },
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'then', {
      data: [{ id: 'c2', display_name: 'NEW Cred', registry_type: 'ghcr' }],
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ credentials_id: 'c2' });

    expect(res.status).toBe(200);
    expect(res.body.credentials_id).toBe('c2');
  });

  it('rejects an unknown field with 400', async () => {
    setProjectManagePerm();
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ enabled: true, image_reference: 'sneaky:x' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unknown_field');
    expect(res.body.field).toBe('image_reference');
  });

  it('rejects a cross-org cred swap with 400 cred_wrong_org', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    pushTableResponse('organization_registry_credentials', {
      data: { id: 'c-other', organization_id: 'org-OTHER' }, error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ credentials_id: 'c-other' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('cred_wrong_org');
  });

  it('blocks flipping enabled true past the cap', async () => {
    setProjectManagePerm();
    pushTableResponse('projects', { data: { id: PROJECT_ID, organization_id: ORG_ID }, error: null });
    setTableResponse('project_configured_images', 'then', {
      data: Array.from({ length: 20 }, (_, i) => ({ id: `i-${i}` })),
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ enabled: true });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('image_cap_reached');
  });
});

// ===========================================================================
// DELETE
// ===========================================================================
describe('DELETE /api/organizations/:id/projects/:projectId/configured-images/:imageId', () => {
  it('deletes the image', async () => {
    setProjectManagePerm();
    setTableResponse('project_configured_images', 'single', {
      data: { id: 'i1', image_reference: 'foo:bar' },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/deleted/);
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'configured_image_deleted',
    }));
  });
});
