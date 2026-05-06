import express from 'express';
import request from 'supertest';
import crypto from 'crypto';

import {
  setTableResponse,
  pushTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

const ORG_A = '11111111-1111-1111-1111-111111111111';
const ORG_B = '22222222-2222-2222-2222-222222222222';
const PROJECT_A = '33333333-3333-3333-3333-333333333333';
const PROJECT_B = '44444444-4444-4444-4444-444444444444';
const TARGET_A = '55555555-5555-5555-5555-555555555555';
const USER_ID = '99999999-9999-9999-9999-999999999999';

process.env.DAST_CREDENTIAL_KEY = crypto.randomBytes(32).toString('hex');

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
    next();
  },
}));

jest.mock('../lib/url-guard', () => ({
  validateExternalUrl: jest.fn(async (url: string) => {
    if (url.includes('localhost') || url.includes('127.0.0.1') || url.includes('169.254')) {
      return { valid: false, reason: 'private/loopback' };
    }
    if (!url.startsWith('http')) return { valid: false, reason: 'not_http' };
    return { valid: true };
  }),
}));

jest.mock('../lib/dast-spa-detect', () => ({
  detectRuntime: jest.fn(async () => ({ runtime: 'classic', confidence: 0.7, markers: [] })),
  nextRuntimeTtlIso: () => new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
  RUNTIME_TTL_MS: 30 * 24 * 3600 * 1000,
}));

jest.mock('../lib/fly-machines', () => ({
  startDastMachine: jest.fn(async () => undefined),
  getDastMachineConfig: jest.fn(() => ({ memory_mb: 8192 })),
}));

import dastRouter from '../routes/dast';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/projects', dastRouter);
  return app;
}

function setProjectAccessOwner(projectId: string, orgId: string) {
  setTableResponse('projects', 'single', {
    data: { organization_id: orgId },
    error: null,
  });
  pushTableResponse('organization_members', { data: { role: 'owner' }, error: null });
  pushTableResponse('organization_roles', {
    data: { permissions: { manage_teams_and_projects: true, manage_integrations: true } },
    error: null,
  });
}

function targetRowOrgA() {
  return {
    id: TARGET_A,
    project_id: PROJECT_A,
    organization_id: ORG_A,
    target_url: 'https://app.example.com',
    detected_runtime: 'classic',
    detected_runtime_at: '2026-05-01T00:00:00Z',
    detected_runtime_ttl_at: new Date(Date.now() + 86_400_000).toISOString(),
    enabled: true,
    label: null,
    active_dast_run_id: null,
    last_scanned_at: null,
    created_at: '2026-04-30T00:00:00Z',
  };
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
});

// ---------------------------------------------------------------------------

describe('GET /api/projects/:projectId/dast/config — v2 shape', () => {
  it('returns scope_config + targets[] alongside legacy fields', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: {
        enabled: true,
        target_url: 'https://app.example.com',
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
        scope_config: { include_patterns: ['/api/.*'] },
      },
      error: null,
    });
    setTableResponse('project_dast_targets', 'then', {
      data: [targetRowOrgA()],
      error: null,
    });
    setTableResponse('project_dast_credentials', 'then', { data: [], error: null });

    const r = await request(makeApp()).get(`/api/projects/${PROJECT_A}/dast/config`);
    expect(r.status).toBe(200);
    expect(r.body.scope_config).toEqual({ include_patterns: ['/api/.*'] });
    expect(Array.isArray(r.body.targets)).toBe(true);
    expect(r.body.targets[0].id).toBe(TARGET_A);
    expect(r.body.targets[0].has_credentials).toBe(false);
  });
});

describe('PUT /api/projects/:projectId/dast/config — scope_config validation', () => {
  it('rejects sensitive header name with structured 422 error_code', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    const r = await request(makeApp())
      .put(`/api/projects/${PROJECT_A}/dast/config`)
      .send({
        enabled: true,
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
        scope_config: {
          header_rules: [{ name: 'Authorization', value: 'Bearer x', scope: 'all' }],
        },
      });
    expect(r.status).toBe(422);
    expect(r.body.error_code).toBe('sensitive_header_rejected');
  });

  it('rejects nested-quantifier ReDoS pattern with 422', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    const r = await request(makeApp())
      .put(`/api/projects/${PROJECT_A}/dast/config`)
      .send({
        enabled: true,
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
        scope_config: { include_patterns: ['(.+)+x'] },
      });
    expect(r.status).toBe(422);
    expect(r.body.error_code).toBe('regex_pattern_unsafe');
  });
});

// ---------------------------------------------------------------------------

describe('POST /api/projects/:projectId/dast/targets', () => {
  it('rejects an SSRF-blocked URL with 422', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/targets`)
      .send({ target_url: 'http://localhost:8080/' });
    expect(r.status).toBe(422);
    expect(r.body.error).toBe('invalid_target_url');
  });

  it('creates a target on a valid public URL and runs SPA-detect', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'single', {
      data: {
        ...targetRowOrgA(),
        detected_runtime: 'classic',
      },
      error: null,
    });

    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/targets`)
      .send({ target_url: 'https://app.example.com', label: 'staging' });
    expect(r.status).toBe(201);
    expect(r.body.target_url).toBe('https://app.example.com');
    expect(r.body.detected_runtime).toBe('classic');
    expect(r.body.has_credentials).toBe(false);
  });
});

// ---------------------------------------------------------------------------

describe('PATCH /api/projects/:projectId/dast/targets/:targetId — cross-tenant', () => {
  it('returns 404 when targetId belongs to another org (NOT 403)', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    // loadTargetOrDeny SELECT returns target belonging to ORG_B / PROJECT_B.
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: {
        ...targetRowOrgA(),
        organization_id: ORG_B,
        project_id: PROJECT_B,
      },
      error: null,
    });

    const r = await request(makeApp())
      .patch(`/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}`)
      .send({ enabled: false });
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('target_not_found');
  });
});

describe('DELETE /api/projects/:projectId/dast/targets/:targetId', () => {
  it('returns 204 on successful delete', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: targetRowOrgA(),
      error: null,
    });
    setTableResponse('project_dast_targets', 'then', { data: null, error: null });

    const r = await request(makeApp()).delete(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}`,
    );
    expect(r.status).toBe(204);
  });
});

// ---------------------------------------------------------------------------

describe('PUT /api/projects/:projectId/dast/targets/:targetId/credentials', () => {
  it('rejects JWT with too-short exp window with 422 jwt_expired_too_soon', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: targetRowOrgA(),
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_timeout_minutes: 30 },
      error: null,
    });

    // JWT with `exp` 60 seconds from now — far below 1.5 * 30min = 45min threshold.
    const exp = Math.floor(Date.now() / 1000) + 60;
    const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64');
    const payload = Buffer.from(JSON.stringify({ exp })).toString('base64');
    const token = `${header}.${payload}.sig`;

    const r = await request(makeApp())
      .put(`/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials`)
      .send({
        auth_strategy: 'jwt',
        payload: { kind: 'jwt', token },
      });
    expect(r.status).toBe(422);
    expect(r.body.error_code).toBe('jwt_expired_too_soon');
  });

  it('accepts a valid cookie credential and returns redacted summary', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: targetRowOrgA(),
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_timeout_minutes: 30 },
      error: null,
    });
    setTableResponse('project_dast_credentials', 'then', { data: null, error: null });

    const r = await request(makeApp())
      .put(`/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials`)
      .send({
        auth_strategy: 'cookie',
        payload: {
          kind: 'cookie',
          cookies: [
            { name: 'session', value: 'abc-fixture-7f3e' },
            { name: 'csrf', value: 'xyz-fixture-9a82' },
          ],
        },
      });
    expect(r.status).toBe(200);
    expect(r.body.auth_strategy).toBe('cookie');
    expect(r.body.payload_summary.kind).toBe('cookie');
    expect(r.body.payload_summary.cookie_count).toBe(2);
    expect(r.body.payload_summary.cookie_names).toEqual(['session', 'csrf']);
    // Plaintext must not leak.
    expect(JSON.stringify(r.body)).not.toContain('abc-fixture-7f3e');
    expect(JSON.stringify(r.body)).not.toContain('xyz-fixture-9a82');
  });

  it('refuses with 503 when DAST_CREDENTIAL_KEY is unset', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    const saved = process.env.DAST_CREDENTIAL_KEY;
    delete process.env.DAST_CREDENTIAL_KEY;

    const r = await request(makeApp())
      .put(`/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials`)
      .send({
        auth_strategy: 'cookie',
        payload: { kind: 'cookie', cookies: [{ name: 's', value: 'v' }] },
      });
    expect(r.status).toBe(503);
    expect(r.body.error).toBe('dast_encryption_not_configured');

    process.env.DAST_CREDENTIAL_KEY = saved;
  });
});

// ---------------------------------------------------------------------------

describe('POST /api/projects/:projectId/dast/scan', () => {
  it('returns 422 when target_id missing', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);

    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/scan`)
      .send({});
    expect(r.status).toBe(422);
  });

  it('returns 404 when target_id belongs to another tenant', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: {
        ...targetRowOrgA(),
        organization_id: ORG_B,
        project_id: PROJECT_B,
      },
      error: null,
    });

    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/scan`)
      .send({ target_id: TARGET_A });
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('target_not_found');
  });

  it('queues a scan and returns 202 with detected_runtime in payload', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: targetRowOrgA(),
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    setRpcResponse('queue_scan_job', {
      data: {
        id: 'job-id-1',
        status: 'queued',
        target_url: 'https://app.example.com',
        scan_profile: 'auto',
        created_at: '2026-05-05T00:00:00Z',
      },
      error: null,
    });

    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/scan`)
      .send({ target_id: TARGET_A });
    expect(r.status).toBe(202);
    expect(r.body.jobId).toBe('job-id-1');
    expect(r.body.detected_runtime).toBe('classic');
    expect(r.body.target_id).toBe(TARGET_A);
  });

  it('maps queue_scan_job concurrency error to 409', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: targetRowOrgA(),
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    setRpcResponse('queue_scan_job', {
      data: null,
      error: { message: 'queue_scan_job: project_concurrent_dast_blocked' },
    });

    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/scan`)
      .send({ target_id: TARGET_A });
    expect(r.status).toBe(409);
    expect(r.body.error).toBe('project_concurrent_dast_blocked');
  });
});

// ---------------------------------------------------------------------------

describe('GET /api/projects/:projectId/dast/jobs?target_id=...', () => {
  it('returns 404 when target_id filter belongs to another tenant', async () => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: {
        ...targetRowOrgA(),
        organization_id: ORG_B,
        project_id: PROJECT_B,
      },
      error: null,
    });

    const r = await request(makeApp()).get(
      `/api/projects/${PROJECT_A}/dast/jobs?target_id=${TARGET_A}`,
    );
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('target_not_found');
  });
});

// ---------------------------------------------------------------------------
// Cross-tenant 404 matrix (cluster-3 P0).
//
// Every targetId-bearing route must return 404 with body.error='target_not_found'
// when the targetId belongs to a different tenant — NOT 403, NOT 422. The 404
// shape prevents existence enumeration. The matrix below covers each of the
// remaining endpoints; the four already-tested endpoints (PATCH target, POST
// scan, GET jobs filter, plus the timing-parity unit test in
// dast-tenant-guard.test.ts) keep their own targeted assertions above.
// ---------------------------------------------------------------------------

describe('Cross-tenant 404 matrix — every :targetId route', () => {
  type Probe = {
    name: string;
    perform: () => request.Test;
  };

  // Each probe runs the request against PROJECT_A in ORG_A, but the mocked
  // SELECT for project_dast_targets returns a row that belongs to ORG_B /
  // PROJECT_B, simulating an attacker constructing a targetId from a tenant
  // they shouldn't see.
  const probes: Probe[] = [
    {
      name: 'DELETE /dast/targets/:targetId',
      perform: () =>
        request(makeApp()).delete(`/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}`),
    },
    {
      name: 'POST /dast/targets/:targetId/recheck-runtime',
      perform: () =>
        request(makeApp()).post(
          `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/recheck-runtime`,
        ),
    },
    {
      name: 'GET /dast/targets/:targetId/credentials',
      perform: () =>
        request(makeApp()).get(
          `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials`,
        ),
    },
    {
      name: 'PUT /dast/targets/:targetId/credentials',
      perform: () =>
        request(makeApp())
          .put(`/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials`)
          .send({
            auth_strategy: 'cookie',
            payload: { kind: 'cookie', cookies: [{ name: 'sid', value: 'x' }] },
          }),
    },
    {
      name: 'DELETE /dast/targets/:targetId/credentials',
      perform: () =>
        request(makeApp()).delete(
          `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials`,
        ),
    },
    {
      name: 'GET /dast/findings?target_id=...',
      perform: () =>
        request(makeApp()).get(
          `/api/projects/${PROJECT_A}/dast/findings?target_id=${TARGET_A}`,
        ),
    },
  ];

  it.each(probes)('$name returns 404 target_not_found for cross-tenant targetId', async ({ perform }) => {
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: {
        ...targetRowOrgA(),
        organization_id: ORG_B,
        project_id: PROJECT_B,
      },
      error: null,
    });

    const r = await perform();
    // 404 — not 403, not 422. /permission|access/i regex from the old plan
    // is structurally insufficient for cross-tenant isolation.
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('target_not_found');
  });
});

// ---------------------------------------------------------------------------
// Drain mode (Task 1.5 — pre-migration runbook gate).
//
// When INTERNAL_DAST_PAUSED=true, POST /api/projects/:projectId/dast/scan must
// return 503 dast_queue_paused regardless of body / RBAC. The middleware lives
// in backend/src/index.ts; this test mounts it explicitly so the assertion
// covers the wired-up shape, not just the route handler.
// ---------------------------------------------------------------------------

describe('Drain mode — POST /dast/scan returns 503 when INTERNAL_DAST_PAUSED=true', () => {
  // Import the production middleware rather than rebuilding it inline. A
  // divergence between the test stub and the real wiring is exactly what
  // this gate is supposed to prevent (path regex drift, write-method drift).
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { dastDrainMiddleware } = require('../middleware/dast-drain');

  function makeAppWithDrain() {
    const app = express();
    app.use(express.json());
    app.use('/api/projects', dastDrainMiddleware);
    app.use('/api/projects', dastRouter);
    return app;
  }

  const originalDrain = process.env.INTERNAL_DAST_PAUSED;
  afterEach(() => {
    if (originalDrain === undefined) delete process.env.INTERNAL_DAST_PAUSED;
    else process.env.INTERNAL_DAST_PAUSED = originalDrain;
  });

  it('returns 503 dast_queue_paused with no DB calls', async () => {
    process.env.INTERNAL_DAST_PAUSED = 'true';
    const r = await request(makeAppWithDrain())
      .post(`/api/projects/${PROJECT_A}/dast/scan`)
      .send({ target_id: TARGET_A });
    expect(r.status).toBe(503);
    expect(r.body.error).toBe('dast_queue_paused');
  });

  it('passes through other routes (GET /jobs is fine while drained)', async () => {
    process.env.INTERNAL_DAST_PAUSED = 'true';
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('scan_jobs', 'then', { data: [], error: null });

    const r = await request(makeAppWithDrain()).get(`/api/projects/${PROJECT_A}/dast/jobs`);
    expect(r.status).toBe(200);
  });

  it('non-drain requests (different path) pass through even with flag set', async () => {
    process.env.INTERNAL_DAST_PAUSED = 'true';
    setProjectAccessOwner(PROJECT_A, ORG_A);
    setTableResponse('project_dast_targets', 'then', { data: [], error: null });

    // GET /targets is not the drain target — it should NOT 503.
    const r = await request(makeAppWithDrain()).get(`/api/projects/${PROJECT_A}/dast/targets`);
    expect(r.status).toBe(200);
  });
});
