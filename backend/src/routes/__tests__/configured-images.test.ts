/**
 * Routes for /api/organizations/:id/projects/:projectId/configured-images.
 *
 * Covers (per plan §M11 Acceptance + post-review hardening):
 *   - GET list with cred-display join
 *   - POST create + image_reference regex/host validation
 *   - PATCH toggle enabled / swap cred (same-org)
 *   - DELETE
 *   - RBAC: 403 without checkProjectManagePermission on POST/PATCH/DELETE
 *   - cred-from-other-org rejected with 400 cred_wrong_org (not 500)
 *   - 21st enabled POST returns 400 image_cap_reached (now via RPC)
 *   - PATCH with extra key returns 400 unknown_field
 *   - PATCH flipping enabled true past the cap returns 400 image_cap_reached
 *   - cross-tenant DELETE/GET via projectId tampering returns 404 (project↔org bind)
 *   - image_reference with internal host returns 400 image_reference_host_blocked
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  pushTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';
import { createActivity } from '../../lib/activities';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));
jest.mock('../../lib/activities', () => ({ createActivity: jest.fn() }));

// validateImageRefHost performs DNS lookups; stub to deterministic results in
// tests so cases pass offline and don't depend on the real registry hostnames
// resolving cleanly. Specific tests can override the mock.
jest.mock('../../lib/image-ref-guard', () => ({
  validateImageRefHost: jest.fn((ref: string) => {
    if (ref.startsWith('127.') || ref.startsWith('169.254.') || ref.includes('.internal/')) {
      return Promise.resolve({ valid: false, reason: `host blocked: ${ref}` });
    }
    return Promise.resolve({ valid: true, host: 'public.example.com', addresses: ['1.2.3.4'] });
  }),
}));

const ORG_ID = 'org-1';
const PROJECT_ID = 'proj-x';
const USER = { id: 'user-1', email: 'a@b.com' };
const TOKEN = 'valid-token';

/**
 * project↔org bind passes; the member's role bundle carries
 * manage_teams_and_projects, which approves checkProjectManagePermission.
 * (The legacy role-NAME `admin` short-circuit was removed — a role named
 * "admin" only passes via its permissions JSONB now.)
 */
function setProjectManagePerm() {
  pushTableResponse('projects', { data: { organization_id: ORG_ID }, error: null });
  setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true } },
    error: null,
  });
}

/** project↔org bind passes; manage_teams_and_projects approves checkProjectAccess. */
function setProjectAccess() {
  pushTableResponse('projects', { data: { organization_id: ORG_ID }, error: null });
  setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_teams_and_projects: true }, display_order: 1 },
    error: null,
  });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();
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
    expect(queryBuilder.eq).toHaveBeenCalledWith('project_id', PROJECT_ID);
  });

  it('returns 404 to a non-member', async () => {
    pushTableResponse('projects', { data: { organization_id: ORG_ID }, error: null });
    setTableResponse('organization_members', 'single', { data: null, error: null });
    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });

  it('returns 404 when projectId belongs to another org (cross-tenant param tampering)', async () => {
    // checkProjectAccess's projectBelongsToOrg lookup finds the project but in
    // a DIFFERENT org → bind fails → returns 404 before any data leak.
    pushTableResponse('projects', { data: { organization_id: 'org-OTHER' }, error: null });

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
  it('creates a public image (no cred)', async () => {
    setProjectManagePerm();
    setRpcResponse('insert_configured_image_with_cap', {
      data: [{
        id: 'i-new', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'ghcr.io/foo/bar:1.0', credentials_id: null, enabled: true,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      }],
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'then', { data: [], error: null });

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
    pushTableResponse('organization_registry_credentials', { data: { id: 'c1', organization_id: ORG_ID }, error: null });
    setRpcResponse('insert_configured_image_with_cap', {
      data: [{
        id: 'i-new', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'myorg.azurecr.io/foo:tag', credentials_id: 'c1', enabled: true,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      }],
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

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'NOT VALID with spaces!!!' });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/docker-pullable shape/);
  });

  it('rejects an internal-host image_reference with 400 image_reference_host_blocked', async () => {
    setProjectManagePerm();

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: '169.254.169.254/foo/bar:tag' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('image_reference_host_blocked');
  });

  it('returns 400 image_cap_reached on the 21st enabled image (RPC raises)', async () => {
    setProjectManagePerm();
    setRpcResponse('insert_configured_image_with_cap', {
      data: null,
      error: { message: 'image_cap_reached' },
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'foo:21' });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('image_cap_reached');
    expect(res.body.message).toMatch(/limit of 20/);
  });

  it('creates a disabled image (cap not consumed at the RPC layer)', async () => {
    setProjectManagePerm();
    setRpcResponse('insert_configured_image_with_cap', {
      data: [{
        id: 'i-disabled', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'foo:bar', credentials_id: null, enabled: false,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      }],
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
    pushTableResponse('projects', { data: { organization_id: ORG_ID }, error: null });
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
    setTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ image_reference: 'foo:bar' });

    expect(res.status).toBe(403);
  });

  it('returns 403 when projectId belongs to another org', async () => {
    // org-A admin token, but the project belongs to org-OTHER. project↔org
    // bind in checkProjectManagePermission rejects → 403.
    pushTableResponse('projects', { data: { organization_id: 'org-OTHER' }, error: null });

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
    setRpcResponse('update_configured_image_with_cap', {
      data: [{
        id: 'i1', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'foo:bar', credentials_id: null, enabled: false,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T01:00:00Z',
      }],
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
    pushTableResponse('organization_registry_credentials', {
      data: { id: 'c2', organization_id: ORG_ID }, error: null,
    });
    setRpcResponse('update_configured_image_with_cap', {
      data: [{
        id: 'i1', project_id: PROJECT_ID, organization_id: ORG_ID,
        image_reference: 'foo:bar', credentials_id: 'c2', enabled: true,
        created_by: USER.id, created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T01:00:00Z',
      }],
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

  it('blocks flipping enabled true past the cap (RPC raises)', async () => {
    setProjectManagePerm();
    setRpcResponse('update_configured_image_with_cap', {
      data: null,
      error: { message: 'image_cap_reached' },
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ enabled: true });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe('image_cap_reached');
  });

  it('returns 403 without manage permission', async () => {
    pushTableResponse('projects', { data: { organization_id: ORG_ID }, error: null });
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
    setTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ enabled: false });

    expect(res.status).toBe(403);
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

  it('returns 403 without manage permission', async () => {
    // Was the missing 403 case from the critical review.
    pushTableResponse('projects', { data: { organization_id: ORG_ID }, error: null });
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
    setTableResponse('project_teams', 'then', { data: [], error: null });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(403);
  });

  it('returns 403 when projectId belongs to another org (cross-tenant DELETE)', async () => {
    // The P0 from the critical review: org-A admin attempting DELETE on an
    // image whose project lives in org-OTHER. project↔org bind rejects.
    pushTableResponse('projects', { data: { organization_id: 'org-OTHER' }, error: null });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/projects/${PROJECT_ID}/configured-images/i1`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(403);
  });
});
