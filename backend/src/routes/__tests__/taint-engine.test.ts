/**
 * Phase 6.5 hardening — taint-engine admin route tests.
 *
 * Covers permission split (view_ai_spending GET vs manage_aegis mutate),
 * the cost-cap clamp at COST_CAP_MAX_USD, vuln_classes_enabled validator,
 * killswitch release, framework-models CRUD permission paths, and the
 * CostCapExceededError → 402 Payment Required response shape.
 */
import request from 'supertest';
import app from '../../index';
import { supabase, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';
import { CostCapExceededError } from '../../lib/taint-engine/cost-cap';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

const mockInferAndStore = jest.fn();
const mockStoreUserEdit = jest.fn();
const mockSoftDelete = jest.fn();
const mockListForOrg = jest.fn();
const mockGetById = jest.fn();
jest.mock('../../lib/taint-engine/spec-cache', () => ({
  inferAndStore: (...a: unknown[]) => mockInferAndStore(...a),
  storeUserEdit: (...a: unknown[]) => mockStoreUserEdit(...a),
  softDelete: (...a: unknown[]) => mockSoftDelete(...a),
  listForOrg: (...a: unknown[]) => mockListForOrg(...a),
  getById: (...a: unknown[]) => mockGetById(...a),
}));

const mockGetCostCapState = jest.fn();
jest.mock('../../lib/taint-engine/cost-cap', () => {
  const actual = jest.requireActual('../../lib/taint-engine/cost-cap');
  return {
    ...actual,
    getCostCapState: (...a: unknown[]) => mockGetCostCapState(...a),
  };
});

const ORG_ID = 'org-1';
const TOKEN = 'valid-token';
const USER = { id: 'user-1', email: 'henry@example.com' };
const MODEL_ID = 'model-1';

function setPerm(perms: Record<string, boolean>) {
  setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: perms }, error: null });
}

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
});

describe('GET /api/organizations/:orgId/settings (taint-engine)', () => {
  it('synthesizes default row when none exists', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: true });
    setTableResponse('taint_engine_settings', 'maybeSingle', { data: null, error: null });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.organization_id).toBe(ORG_ID);
    expect(res.body.monthly_ai_cost_cap_usd).toBe(75); // DEFAULT_MONTHLY_AI_COST_CAP_USD
    expect(res.body.killswitch_active).toBe(false);
    expect(Array.isArray(res.body.vuln_classes_enabled)).toBe(true);
    expect(res.body.vuln_classes_enabled).toContain('sql_injection');
    expect(res.body.can_manage).toBe(true);
  });

  it('returns persisted row + can_manage=false when caller lacks manage_aegis', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: false });
    setTableResponse('taint_engine_settings', 'maybeSingle', {
      data: {
        organization_id: ORG_ID,
        enabled: true,
        ai_layer_enabled: false,
        monthly_ai_cost_cap_usd: 200,
        vuln_classes_enabled: ['sql_injection', 'xss'],
        killswitch_active: false,
      },
      error: null,
    });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.monthly_ai_cost_cap_usd).toBe(200);
    expect(res.body.can_manage).toBe(false);
  });

  it('403 without view_ai_spending', async () => {
    setPerm({ view_ai_spending: false, manage_aegis: false });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(403);
  });

  it('401 without bearer token', async () => {
    const res = await request(app).get(`/api/organizations/${ORG_ID}/settings`);
    expect(res.status).toBe(401);
  });
});

describe('PATCH /api/organizations/:orgId/settings (taint-engine)', () => {
  it('clamps monthly_ai_cost_cap_usd to COST_CAP_MAX_USD (1000) when over', async () => {
    setPerm({ manage_aegis: true });
    setTableResponse('taint_engine_settings', 'single', {
      data: { organization_id: ORG_ID, monthly_ai_cost_cap_usd: 1000 },
      error: null,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ monthly_ai_cost_cap_usd: 999999 });

    expect(res.status).toBe(200);
    expect(res.body.monthly_ai_cost_cap_usd).toBe(1000);
  });

  it('400 on negative monthly_ai_cost_cap_usd', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ monthly_ai_cost_cap_usd: -1 });
    expect(res.status).toBe(400);
  });

  it('400 on unknown vuln_class', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ vuln_classes_enabled: ['sql_injection', 'fictional_class'] });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/vuln_classes_enabled/);
  });

  it('400 when no recognized fields', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ irrelevant: true });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/No valid fields/);
  });

  it('403 without manage_aegis (view_ai_spending alone is not enough)', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: false });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/settings`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ enabled: false });
    expect(res.status).toBe(403);
  });
});

describe('POST /api/organizations/:orgId/killswitch/release', () => {
  it('clears killswitch on manage_aegis', async () => {
    setPerm({ manage_aegis: true });
    setTableResponse('taint_engine_settings', 'single', {
      data: { killswitch_active: false },
      error: null,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/killswitch/release`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.killswitch_active).toBe(false);
  });

  it('403 without manage_aegis', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: false });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/killswitch/release`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(403);
  });
});

describe('POST /api/organizations/:orgId/framework-models', () => {
  const sampleSpec = { sources: [], sinks: [], sanitizers: [] };

  it('400 when framework_name missing', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ code_samples: [{ path: 'a.ts', content: 'export const x = 1' }] });
    expect(res.status).toBe(400);
  });

  it('400 when code_samples is empty', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ framework_name: 'koa', code_samples: [] });
    expect(res.status).toBe(400);
  });

  it('400 when a code_sample is shaped incorrectly', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ framework_name: 'koa', code_samples: [{ path: 'a.ts' }] });
    expect(res.status).toBe(400);
  });

  it('201 inferAndStore happy path', async () => {
    setPerm({ manage_aegis: true });
    mockInferAndStore.mockResolvedValueOnce({
      id: MODEL_ID,
      organization_id: ORG_ID,
      framework_name: 'koa',
      framework_version: '*',
      source_type: 'ai_inferred',
      spec: sampleSpec,
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        framework_name: 'koa',
        code_samples: [{ path: 'app.ts', content: 'export const x = 1' }],
      });

    expect(res.status).toBe(201);
    expect(res.body.id).toBe(MODEL_ID);
    expect(mockInferAndStore).toHaveBeenCalledWith(
      expect.objectContaining({
        organizationId: ORG_ID,
        frameworkName: 'koa',
        frameworkVersion: '*',
      }),
    );
  });

  it('402 with state payload when CostCapExceededError is thrown', async () => {
    setPerm({ manage_aegis: true });
    const state = {
      capUsd: 75,
      spentUsdThisMonth: 80,
      remainingUsd: 0,
      exceeded: true,
    };
    mockInferAndStore.mockRejectedValueOnce(new CostCapExceededError(state, 0.05));

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        framework_name: 'koa',
        code_samples: [{ path: 'app.ts', content: 'export const x = 1' }],
      });

    expect(res.status).toBe(402);
    expect(res.body.error).toMatch(/cap exceeded/i);
    expect(res.body.state).toEqual(state);
  });

  it('502 on generic provider failure', async () => {
    setPerm({ manage_aegis: true });
    mockInferAndStore.mockRejectedValueOnce(new Error('upstream timeout'));

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        framework_name: 'koa',
        code_samples: [{ path: 'app.ts', content: 'export const x = 1' }],
      });

    expect(res.status).toBe(502);
  });

  it('403 without manage_aegis', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: false });
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/framework-models`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({
        framework_name: 'koa',
        code_samples: [{ path: 'app.ts', content: 'export const x = 1' }],
      });
    expect(res.status).toBe(403);
    expect(mockInferAndStore).not.toHaveBeenCalled();
  });
});

describe('PATCH /api/organizations/:orgId/framework-models/:modelId', () => {
  const validSpec = { sources: [], sinks: [], sanitizers: [] };

  it('400 on missing spec body', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('400 on spec missing sources/sinks/sanitizers arrays', async () => {
    setPerm({ manage_aegis: true });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ spec: { sources: [] } });
    expect(res.status).toBe(400);
  });

  it('404 when storeUserEdit returns null (cross-org probe)', async () => {
    setPerm({ manage_aegis: true });
    mockStoreUserEdit.mockResolvedValueOnce(null);

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ spec: validSpec });

    expect(res.status).toBe(404);
  });

  it('200 happy path', async () => {
    setPerm({ manage_aegis: true });
    mockStoreUserEdit.mockResolvedValueOnce({
      id: MODEL_ID,
      organization_id: ORG_ID,
      source_type: 'user_edited',
      spec: validSpec,
    });

    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ spec: validSpec });

    expect(res.status).toBe(200);
    expect(res.body.source_type).toBe('user_edited');
  });

  it('403 without manage_aegis', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: false });
    const res = await request(app)
      .patch(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`)
      .send({ spec: validSpec });
    expect(res.status).toBe(403);
    expect(mockStoreUserEdit).not.toHaveBeenCalled();
  });
});

describe('DELETE /api/organizations/:orgId/framework-models/:modelId', () => {
  it('200 on soft-delete success', async () => {
    setPerm({ manage_aegis: true });
    mockSoftDelete.mockResolvedValueOnce(true);

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  it('404 when softDelete returns false (cross-org probe)', async () => {
    setPerm({ manage_aegis: true });
    mockSoftDelete.mockResolvedValueOnce(false);

    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(404);
  });

  it('403 without manage_aegis', async () => {
    setPerm({ view_ai_spending: true, manage_aegis: false });
    const res = await request(app)
      .delete(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);
    expect(res.status).toBe(403);
    expect(mockSoftDelete).not.toHaveBeenCalled();
  });
});

describe('GET /api/organizations/:orgId/framework-models/:modelId', () => {
  it('200 when model exists', async () => {
    setPerm({ view_ai_spending: true });
    mockGetById.mockResolvedValueOnce({
      id: MODEL_ID,
      organization_id: ORG_ID,
      framework_name: 'koa',
      spec: { sources: [], sinks: [], sanitizers: [] },
    });

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(200);
    expect(res.body.id).toBe(MODEL_ID);
  });

  it('404 when getById returns null', async () => {
    setPerm({ view_ai_spending: true });
    mockGetById.mockResolvedValueOnce(null);

    const res = await request(app)
      .get(`/api/organizations/${ORG_ID}/framework-models/${MODEL_ID}`)
      .set('Authorization', `Bearer ${TOKEN}`);

    expect(res.status).toBe(404);
  });
});
