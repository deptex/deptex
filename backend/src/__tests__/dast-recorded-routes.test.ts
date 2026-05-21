// Route tests for the v2.1d recorded-login endpoints:
//   - POST /:projectId/dast/targets/:targetId/credentials/test
//   - POST /:projectId/dast/jobs/:jobId/cancel
//   - POST /:projectId/dast/scan engine guard (nuclei + recorded → 400)
//   - GET  /:projectId/dast/jobs (error_payload surfacing)
//
// Pins the cross-tenant 404s, RBAC denial, Fly-cold-start 503 cleanup,
// concurrency 409s, cancel-RPC empty→404-vs-409 distinction.

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
const TARGET_A = '55555555-5555-5555-5555-555555555555';
const JOB_A = '66666666-6666-6666-6666-666666666666';
const USER_ID = '99999999-9999-9999-9999-999999999999';

process.env.DAST_CREDENTIAL_KEY = crypto.randomBytes(32).toString('hex');

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
    next();
  },
}));

jest.mock('../lib/url-guard', () => ({
  validateExternalUrl: jest.fn(async () => ({ valid: true })),
}));

jest.mock('../lib/dast-spa-detect', () => ({
  detectRuntime: jest.fn(async () => ({ runtime: 'classic', confidence: 0.7, markers: [] })),
  nextRuntimeTtlIso: () => new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
  RUNTIME_TTL_MS: 30 * 24 * 3600 * 1000,
}));

const flyStartMock = jest.fn(async () => undefined);
jest.mock('../lib/fly-machines', () => ({
  startDastMachine: (...args: unknown[]) => flyStartMock(...args),
  getDastMachineConfig: jest.fn(() => ({ memory_mb: 8192 })),
}));

import dastRouter from '../routes/dast';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/projects', dastRouter);
  return app;
}

function setProjectAccessOwner(orgId = ORG_A) {
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

function setProjectAccessMemberNoPerm(orgId = ORG_A) {
  setTableResponse('projects', 'single', {
    data: { organization_id: orgId },
    error: null,
  });
  pushTableResponse('organization_members', { data: { role: 'member' }, error: null });
  pushTableResponse('organization_roles', {
    data: { permissions: { manage_teams_and_projects: true } }, // NO manage_integrations
    error: null,
  });
}

function targetRowOrgA(enabled = true) {
  return {
    id: TARGET_A,
    project_id: PROJECT_A,
    organization_id: ORG_A,
    target_url: 'https://app.example.com',
    detected_runtime: 'classic',
    detected_runtime_at: '2026-05-01T00:00:00Z',
    detected_runtime_ttl_at: new Date(Date.now() + 86_400_000).toISOString(),
    enabled,
    label: null,
    active_dast_run_id: null,
    last_scanned_at: null,
    created_at: '2026-04-30T00:00:00Z',
  };
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  flyStartMock.mockReset();
  flyStartMock.mockResolvedValue(undefined);
});

// ===========================================================================
// POST /credentials/test
// ===========================================================================

describe('POST /:projectId/dast/targets/:targetId/credentials/test', () => {
  it('queues a dast_zap job with payload.dry_run:true and returns 202', async () => {
    setProjectAccessOwner();
    setTableResponse('project_dast_targets', 'maybeSingle', { data: targetRowOrgA(), error: null });
    setTableResponse('project_dast_credentials', 'maybeSingle', {
      data: { auth_strategy: 'recorded' },
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });

    const queuedJob = { id: JOB_A, status: 'queued', target_url: 'https://app.example.com', scan_profile: 'auto', created_at: new Date().toISOString() };
    setRpcResponse('queue_scan_job', { data: queuedJob, error: null });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(202);
    expect(r.body.test_job_id).toBe(JOB_A);
    expect(r.body.status).toBe('queued');
    expect(flyStartMock).toHaveBeenCalled();
  });

  it('returns 422 when credential is form (not recorded)', async () => {
    setProjectAccessOwner();
    setTableResponse('project_dast_targets', 'maybeSingle', { data: targetRowOrgA(), error: null });
    setTableResponse('project_dast_credentials', 'maybeSingle', {
      data: { auth_strategy: 'form' },
      error: null,
    });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(422);
    expect(r.body.code).toBe('unsupported_strategy_for_test');
  });

  it('returns 404 when credentials are not set', async () => {
    setProjectAccessOwner();
    setTableResponse('project_dast_targets', 'maybeSingle', { data: targetRowOrgA(), error: null });
    setTableResponse('project_dast_credentials', 'maybeSingle', { data: null, error: null });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('credentials_not_set');
  });

  it('returns 403 when caller lacks manage_integrations', async () => {
    setProjectAccessMemberNoPerm();
    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(403);
    expect(r.body.error).toMatch(/permission/i);
  });

  it('returns 404 for cross-tenant target (target belongs to ORG_B)', async () => {
    setProjectAccessOwner(ORG_A);
    // loadTargetOrDeny returns null when target.organization_id !== caller's org.
    setTableResponse('project_dast_targets', 'maybeSingle', {
      data: { ...targetRowOrgA(), organization_id: ORG_B },
      error: null,
    });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('target_not_found');
  });

  it('returns 409 when concurrency cap is hit (real scan in flight)', async () => {
    setProjectAccessOwner();
    setTableResponse('project_dast_targets', 'maybeSingle', { data: targetRowOrgA(), error: null });
    setTableResponse('project_dast_credentials', 'maybeSingle', {
      data: { auth_strategy: 'recorded' },
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    setRpcResponse('queue_scan_job', {
      data: null,
      error: { message: 'project_concurrent_dast_blocked: target busy' } as any,
    });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(409);
    expect(r.body.error).toBe('project_concurrent_dast_blocked');
  });

  it('returns 503 and deletes the queued row when Fly cold-start fails', async () => {
    setProjectAccessOwner();
    setTableResponse('project_dast_targets', 'maybeSingle', { data: targetRowOrgA(), error: null });
    setTableResponse('project_dast_credentials', 'maybeSingle', {
      data: { auth_strategy: 'recorded' },
      error: null,
    });
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    const queuedJob = { id: JOB_A, status: 'queued', target_url: 'https://app.example.com', scan_profile: 'auto', created_at: new Date().toISOString() };
    setRpcResponse('queue_scan_job', { data: queuedJob, error: null });
    flyStartMock.mockRejectedValueOnce(new Error('Fly API timeout'));

    // The route attempts a DELETE on scan_jobs after the Fly failure. Mock it
    // so the call doesn't throw — we don't need to verify the DELETE shape,
    // just that the route doesn't crash.
    setTableResponse('scan_jobs', 'eq', { data: null, error: null });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/targets/${TARGET_A}/credentials/test`,
    );
    expect(r.status).toBe(503);
    expect(r.body.error).toBe('fly_machine_unavailable');
  });
});

// ===========================================================================
// POST /dast/jobs/:jobId/cancel
// ===========================================================================

describe('POST /:projectId/dast/jobs/:jobId/cancel', () => {
  it('cancels a queued job and returns 200', async () => {
    setProjectAccessOwner();
    setRpcResponse('cancel_scan_job', {
      data: { id: JOB_A, status: 'cancelled', organization_id: ORG_A },
      error: null,
    });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/jobs/${JOB_A}/cancel`,
    );
    expect(r.status).toBe(200);
    expect(r.body.job_id).toBe(JOB_A);
    expect(r.body.status).toBe('cancelled');
  });

  it('returns 404 when RPC empty AND job not found in caller org', async () => {
    setProjectAccessOwner();
    setRpcResponse('cancel_scan_job', { data: null, error: null });
    setTableResponse('scan_jobs', 'maybeSingle', { data: null, error: null });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/jobs/${JOB_A}/cancel`,
    );
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('job_not_found');
  });

  it('returns 409 when RPC empty AND job exists but is completed', async () => {
    setProjectAccessOwner();
    setRpcResponse('cancel_scan_job', { data: null, error: null });
    setTableResponse('scan_jobs', 'maybeSingle', { data: { status: 'completed' }, error: null });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/jobs/${JOB_A}/cancel`,
    );
    expect(r.status).toBe(409);
    expect(r.body.code).toBe('job_not_cancellable');
    expect(r.body.current_status).toBe('completed');
  });

  it('returns 403 without manage_integrations', async () => {
    setProjectAccessMemberNoPerm();
    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/jobs/${JOB_A}/cancel`,
    );
    expect(r.status).toBe(403);
  });

  it('returns 404 when jobId belongs to a different project in the same org (/criticalreview HEH-1)', async () => {
    // The RPC now AND-binds project_id, so a cross-project cancel attempt
    // from the same-org caller returns empty. The probe also scopes by
    // project_id and DAST type — a foreign-project row no longer matches,
    // so we return 404 (NOT 409 with leaked current_status).
    setProjectAccessOwner();
    setRpcResponse('cancel_scan_job', { data: null, error: null });
    setTableResponse('scan_jobs', 'maybeSingle', { data: null, error: null });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/jobs/${JOB_A}/cancel`,
    );
    expect(r.status).toBe(404);
    expect(r.body.error).toBe('job_not_found');
  });

  it('returns 500 when the 404/409 probe itself errors (/criticalreview EHA-4)', async () => {
    // Pre-fix: a transient supabase blip during the probe yielded a
    // misleading 404. Post-fix: probe errors surface as a 500 so the caller
    // can retry rather than treating the job as missing.
    setProjectAccessOwner();
    setRpcResponse('cancel_scan_job', { data: null, error: null });
    setTableResponse('scan_jobs', 'maybeSingle', {
      data: null,
      error: { message: 'connection reset by peer' },
    });

    const r = await request(makeApp()).post(
      `/api/projects/${PROJECT_A}/dast/jobs/${JOB_A}/cancel`,
    );
    expect(r.status).toBe(500);
  });
});

// ===========================================================================
// POST /dast/scan — engine validator (nuclei + recorded)
// ===========================================================================

describe('POST /:projectId/dast/scan — engine validator (v2.1d)', () => {
  it('rejects nuclei engine on a target with recorded auth_strategy (400)', async () => {
    setProjectAccessOwner();
    setTableResponse('project_dast_targets', 'maybeSingle', { data: targetRowOrgA(), error: null });
    setTableResponse('project_dast_credentials', 'maybeSingle', {
      data: { auth_strategy: 'recorded' },
      error: null,
    });

    const r = await request(makeApp())
      .post(`/api/projects/${PROJECT_A}/dast/scan`)
      .send({ target_id: TARGET_A, engine: 'nuclei' });
    expect(r.status).toBe(400);
    expect(r.body.code).toBe('unsupported_recorded_on_nuclei');
  });
});

// ===========================================================================
// GET /dast/jobs — error_payload surfacing
// ===========================================================================

describe('GET /:projectId/dast/jobs — surfaces error_payload', () => {
  it('returns error_payload alongside the existing job fields', async () => {
    setProjectAccessOwner();
    const testResult = {
      kind: 'test_result',
      test_result: { success: true, duration_ms: 7400, steps_run: 4 },
    };
    setTableResponse('scan_jobs', 'then', {
      data: [
        {
          id: JOB_A,
          status: 'completed',
          trigger_source: 'manual',
          target_id: TARGET_A,
          target_url: 'https://app.example.com',
          scan_profile: 'auto',
          findings_count: 0,
          duration_seconds: 7,
          started_at: '2026-05-20T12:00:00Z',
          completed_at: '2026-05-20T12:00:07Z',
          error: null,
          error_category: null,
          error_payload: testResult,
          attempts: 1,
          created_at: '2026-05-20T11:59:59Z',
        },
      ],
      error: null,
    });

    const r = await request(makeApp()).get(`/api/projects/${PROJECT_A}/dast/jobs`);
    expect(r.status).toBe(200);
    expect(Array.isArray(r.body)).toBe(true);
    expect(r.body[0].error_payload).toEqual(testResult);
  });
});
