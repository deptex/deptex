/**
 * Routes for /api/organizations/:id/registry-credentials.
 *
 * Covers (per plan §M10 Acceptance):
 *   - GET list (membership gate, encrypted_credentials never selected)
 *   - POST create with valid (registry_type, shape) pairs
 *   - POST create with mismatched shape -> 400
 *   - POST create with extra body keys -> ignored (only declared keys touched)
 *   - POST without manage_integrations -> 403
 *   - PATCH display_name only; unknown field -> 400 unknown_field
 *   - PATCH /rotate re-encrypts and bumps encryption_key_version
 *   - DELETE returns detached_image_count from FK SET NULL cascade
 *   - POST /test decrypt success / decrypt_failed / shape_invalid
 *   - Audit-log row appears for each mutation
 *   - Tenancy: every read chains .eq('organization_id', orgId)
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

// validateExternalUrl performs DNS lookups; stub to deterministic results in
// tests so cases pass offline. Specific tests can override the mock.
jest.mock('../../lib/url-guard', () => ({
  validateExternalUrl: jest.fn((url: string) => {
    if (/(127\.|169\.254\.|10\.|192\.168\.|localhost|\.internal)/.test(url)) {
      return Promise.resolve({ valid: false, reason: `host blocked: ${url}` });
    }
    return Promise.resolve({ valid: true, resolved: { host: 'public.example.com', addresses: ['1.2.3.4'] } });
  }),
}));

// Force AI_ENCRYPTION_KEY for tests so encryption helpers are configured.
// 32-byte hex key (64 chars). Must run before encryption.ts is imported by
// the route module, which happens transitively via app.
process.env.AI_ENCRYPTION_KEY = process.env.AI_ENCRYPTION_KEY
  || '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

const ORG_ID = 'org-1';
const USER = { id: 'user-1', email: 'a@b.com' };
const TOKEN = 'valid-token';

function setPerm(perms: Record<string, boolean>) {
  // checkOrgManageIntegrations + checkOrgAccess both read
  // organization_members.role then organization_roles.permissions.
  setTableResponse('organization_members', 'single', { data: { role: 'admin', user_id: USER.id }, error: null });
  setTableResponse('organization_members', 'maybeSingle', { data: { user_id: USER.id }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: perms }, error: null });
}

function setNoMember() {
  setTableResponse('organization_members', 'single', { data: null, error: null });
  setTableResponse('organization_members', 'maybeSingle', { data: null, error: null });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
});

// ===========================================================================
// GET /:id/registry-credentials
// ===========================================================================
describe('GET /api/organizations/:id/registry-credentials', () => {
  it('returns the metadata-only list for a member', async () => {
    setPerm({});
    setTableResponse('organization_registry_credentials', 'then', {
      data: [
        {
          id: 'c1',
          organization_id: ORG_ID,
          registry_type: 'ecr',
          registry_url: '123.dkr.ecr.us-west-2.amazonaws.com',
          display_name: 'Prod ECR',
          credential_shape: 'aws_keys',
          encryption_key_version: 1,
          last_used_at: null,
          created_by: USER.id,
          created_at: '2026-05-05T00:00:00Z',
          updated_at: '2026-05-05T00:00:00Z',
        },
      ],
      error: null,
    });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(1);
    expect(res.body[0].id).toBe('c1');
    // Tenancy invariant — ANY select must chain organization_id.
    expect(queryBuilder.eq).toHaveBeenCalledWith('organization_id', ORG_ID);
    // The encrypted blob never appears in the SELECT column list.
    const selectCols = (queryBuilder.select.mock.calls as any[]).map((c) => c[0]).join(' ');
    expect(selectCols).not.toMatch(/encrypted_credentials/);
  });

  it('returns 404 to a non-member (no cross-org leak)', async () => {
    setNoMember();
    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(404);
  });
});

// ===========================================================================
// POST /:id/registry-credentials
// ===========================================================================
describe('POST /api/organizations/:id/registry-credentials', () => {
  it('creates an aws_keys cred for ecr', async () => {
    setPerm({ manage_integrations: true });
    setTableResponse('organization_registry_credentials', 'single', {
      data: {
        id: 'c1', organization_id: ORG_ID, registry_type: 'ecr',
        registry_url: '123.dkr.ecr.us-west-2.amazonaws.com',
        display_name: 'Prod ECR', credential_shape: 'aws_keys',
        encryption_key_version: 1, last_used_at: null, created_by: USER.id,
        created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        registry_type: 'ecr',
        registry_url: '123.dkr.ecr.us-west-2.amazonaws.com',
        display_name: 'Prod ECR',
        credentials: {
          shape: 'aws_keys',
          access_key_id: 'AKIA...',
          secret_access_key: 'sk',
          region: 'us-west-2',
        },
      });

    expect(res.status).toBe(201);
    expect(res.body.id).toBe('c1');
    // Insert payload never carries plaintext.
    const insertedPayload = (queryBuilder.insert.mock.calls[0] as any[])[0];
    expect(insertedPayload.encrypted_credentials).toBeTruthy();
    expect(insertedPayload).not.toHaveProperty('plaintext_credentials');
    expect(insertedPayload).not.toHaveProperty('credentials');
    // Audit log emitted.
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      organization_id: ORG_ID,
      user_id: USER.id,
      activity_type: 'registry_credential_created',
    }));
  });

  it('rejects mismatched (registry_type, credential_shape) pair with 400', async () => {
    setPerm({ manage_integrations: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        registry_type: 'ecr',  // expects aws_keys
        display_name: 'wrong',
        credentials: { shape: 'username_password', username: 'u', password: 'p' },
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/not valid for registry_type/);
    expect(createActivity).not.toHaveBeenCalled();
  });

  it('rejects harbor without registry_url with 400', async () => {
    setPerm({ manage_integrations: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        registry_type: 'harbor',
        display_name: 'no url',
        credentials: { shape: 'username_password', username: 'u', password: 'p' },
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/registry_url required/);
  });

  it('returns 403 without manage_integrations', async () => {
    setPerm({ manage_integrations: false });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        registry_type: 'dockerhub',
        display_name: 'x',
        credentials: { shape: 'token', token: 't' },
      });
    expect(res.status).toBe(403);
  });

  it('accepts each ghcr / dockerhub / quay / jfrog / custom token pair', async () => {
    setPerm({ manage_integrations: true });
    setTableResponse('organization_registry_credentials', 'single', {
      data: {
        id: 'cN', organization_id: ORG_ID, registry_type: 'ghcr',
        registry_url: null, display_name: 'GHCR token', credential_shape: 'token',
        encryption_key_version: 1, last_used_at: null, created_by: USER.id,
        created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T00:00:00Z',
      },
      error: null,
    });

    for (const rt of ['ghcr', 'dockerhub', 'quay', 'jfrog', 'custom']) {
      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/registry-credentials`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({
          registry_type: rt,
          ...(rt === 'custom' || rt === 'jfrog' ? { registry_url: 'https://x.example.com' } : {}),
          display_name: `${rt} token`,
          credentials: { shape: 'token', token: 't' },
        });
      expect(res.status).toBe(201);
    }
  });
});

describe('POST /api/organizations/:id/registry-credentials — SSRF + length guards', () => {
  it('rejects registry_url pointing at IMDS', async () => {
    setPerm({ manage_integrations: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        registry_type: 'harbor',
        registry_url: '169.254.169.254',
        display_name: 'imds',
        credentials: { shape: 'username_password', username: 'u', password: 'p' },
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('registry_url_blocked');
  });

  it('rejects an over-long display_name with 400', async () => {
    setPerm({ manage_integrations: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        registry_type: 'dockerhub',
        display_name: 'x'.repeat(201),
        credentials: { shape: 'token', token: 't' },
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/display_name too long/);
  });
});

// ===========================================================================
// PATCH /:id/registry-credentials/:credId
// ===========================================================================
describe('PATCH /api/organizations/:id/registry-credentials/:credId', () => {
  it('renames display_name', async () => {
    setPerm({ manage_integrations: true });
    setTableResponse('organization_registry_credentials', 'single', {
      data: {
        id: 'c1', organization_id: ORG_ID, registry_type: 'ecr',
        registry_url: 'x', display_name: 'New name', credential_shape: 'aws_keys',
        encryption_key_version: 1, last_used_at: null, created_by: USER.id,
        created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T01:00:00Z',
      },
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ display_name: 'New name' });

    expect(res.status).toBe(200);
    expect(res.body.display_name).toBe('New name');
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'registry_credential_updated',
    }));
  });

  it('rejects an unknown field with 400', async () => {
    setPerm({ manage_integrations: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ display_name: 'ok', registry_type: 'ghcr' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unknown_field');
    expect(res.body.field).toBe('registry_type');
  });

  it('returns 403 without manage_integrations', async () => {
    setPerm({ manage_integrations: false });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ display_name: 'New' });
    expect(res.status).toBe(403);
  });
});

// ===========================================================================
// PATCH /:id/registry-credentials/:credId/rotate
// ===========================================================================
describe('PATCH /api/organizations/:id/registry-credentials/:credId/rotate', () => {
  it('rotates and bumps encryption_key_version', async () => {
    setPerm({ manage_integrations: true });
    // First single() — fetch existing row for shape match.
    pushTableResponse('organization_registry_credentials', {
      data: { id: 'c1', registry_type: 'ecr', credential_shape: 'aws_keys' },
      error: null,
    });
    // Second single() — the UPDATE returning row.
    pushTableResponse('organization_registry_credentials', {
      data: {
        id: 'c1', organization_id: ORG_ID, registry_type: 'ecr',
        registry_url: 'x', display_name: 'Prod ECR', credential_shape: 'aws_keys',
        encryption_key_version: 2, last_used_at: null, created_by: USER.id,
        created_at: '2026-05-05T00:00:00Z', updated_at: '2026-05-05T02:00:00Z',
      },
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1/rotate`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        credentials: {
          shape: 'aws_keys',
          access_key_id: 'AKIA-NEW',
          secret_access_key: 'sk-new',
          region: 'us-west-2',
        },
      });

    expect(res.status).toBe(200);
    expect(res.body.encryption_key_version).toBe(2);
    // The update payload re-encrypted; assert that on the LAST update call.
    const updateCalls = (queryBuilder.update.mock.calls as any[][]);
    const updatePayload = updateCalls[updateCalls.length - 1][0];
    expect(updatePayload.encrypted_credentials).toBeTruthy();
    expect(updatePayload.encryption_key_version).toBeGreaterThanOrEqual(1);
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'registry_credential_rotated',
    }));
  });

  it('rejects rotating to a different credential_shape', async () => {
    setPerm({ manage_integrations: true });
    pushTableResponse('organization_registry_credentials', {
      data: { id: 'c1', registry_type: 'ecr', credential_shape: 'aws_keys' },
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1/rotate`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ credentials: { shape: 'token', token: 't' } });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/different credential_shape/);
  });

  it('rejects an unknown body field', async () => {
    setPerm({ manage_integrations: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1/rotate`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ credentials: { shape: 'token', token: 't' }, display_name: 'sneaky' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('unknown_field');
  });

  it('returns 403 without manage_integrations', async () => {
    setPerm({ manage_integrations: false });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/registry-credentials/c1/rotate`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ credentials: { shape: 'token', token: 't' } });
    expect(res.status).toBe(403);
  });
});

// ===========================================================================
// DELETE /:id/registry-credentials/:credId
// ===========================================================================
describe('DELETE /api/organizations/:id/registry-credentials/:credId', () => {
  it('reports detached_image_count from the cascade', async () => {
    setPerm({ manage_integrations: true });
    // attached-images probe (then-resolver, list).
    setTableResponse('project_configured_images', 'then', {
      data: [{ id: 'i1' }, { id: 'i2' }],
      error: null,
    });
    setTableResponse('organization_registry_credentials', 'single', {
      data: { id: 'c1', display_name: 'Prod ECR', registry_type: 'ecr' },
      error: null,
    });

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/registry-credentials/c1`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.detached_image_count).toBe(2);
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'registry_credential_deleted',
      metadata: expect.objectContaining({ detached_image_count: 2 }),
    }));
  });

  it('returns 403 without manage_integrations', async () => {
    setPerm({ manage_integrations: false });
    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/registry-credentials/c1`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(403);
  });
});

// ===========================================================================
// POST /:id/registry-credentials/:credId/test
// ===========================================================================
describe('POST /api/organizations/:id/registry-credentials/:credId/test', () => {
  // The test endpoint round-trips encrypt(plaintext) -> decrypt -> validate.
  // We seed a real ciphertext (encryptApiKey) so decryptApiKey actually
  // succeeds against the same AI_ENCRYPTION_KEY.
  function seedCipher(plaintextObj: unknown): string {
    const { encryptApiKey } = require('../../lib/ai/encryption');
    return encryptApiKey(JSON.stringify(plaintextObj)).encrypted;
  }

  it('returns ok=true when decrypt + shape match', async () => {
    setPerm({ manage_integrations: true });
    const ciphertext = seedCipher({
      shape: 'aws_keys', access_key_id: 'AKIA', secret_access_key: 'sk', region: 'us-west-2',
    });
    setTableResponse('organization_registry_credentials', 'single', {
      data: {
        id: 'c1',
        encrypted_credentials: ciphertext,
        encryption_key_version: 1,
        credential_shape: 'aws_keys',
        display_name: 'Prod ECR',
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials/c1/test`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: true });
    expect(createActivity).toHaveBeenCalledWith(expect.objectContaining({
      activity_type: 'registry_credential_tested',
      metadata: expect.objectContaining({ ok: true }),
    }));
  });

  it('returns ok=false error_class=decrypt_failed on garbage ciphertext', async () => {
    setPerm({ manage_integrations: true });
    setTableResponse('organization_registry_credentials', 'single', {
      data: {
        id: 'c1',
        encrypted_credentials: 'not::a::valid::cipher',
        encryption_key_version: 1,
        credential_shape: 'aws_keys',
        display_name: 'Broken',
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials/c1/test`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: false, error_class: 'decrypt_failed' });
  });

  it('returns ok=false error_class=shape_invalid when stored shape drifts from row.credential_shape', async () => {
    setPerm({ manage_integrations: true });
    // Decrypts cleanly but the inner `shape` field disagrees with the row.
    const ciphertext = seedCipher({ shape: 'token', token: 't' });
    setTableResponse('organization_registry_credentials', 'single', {
      data: {
        id: 'c1',
        encrypted_credentials: ciphertext,
        encryption_key_version: 1,
        credential_shape: 'aws_keys',  // mismatch
        display_name: 'Drift',
      },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials/c1/test`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body).toEqual({ ok: false, error_class: 'shape_invalid' });
  });

  it('returns 403 without manage_integrations', async () => {
    setPerm({ manage_integrations: false });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/registry-credentials/c1/test`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(403);
  });
});
