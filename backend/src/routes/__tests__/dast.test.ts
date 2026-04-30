import request from 'supertest';
import express from 'express';
import { supabase, setTableResponse, setRpcResponse, clearTableRegistry, clearRpcRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));

const checkProjectAccessMock = jest.fn();
const checkProjectManagePermissionMock = jest.fn();
jest.mock('../projects', () => ({
  checkProjectAccess: (...args: unknown[]) => checkProjectAccessMock(...args),
  checkProjectManagePermission: (...args: unknown[]) => checkProjectManagePermissionMock(...args),
}));

const startDastMachineMock = jest.fn().mockResolvedValue('fly-machine-id');
jest.mock('../../lib/fly-machines', () => ({
  startDastMachine: () => startDastMachineMock(),
  startExtractionMachine: jest.fn(),
  DAST_CONFIG: { app: 'deptex-depscanner' },
  stopFlyMachine: jest.fn(),
}));

const validateExternalUrlMock = jest.fn();
jest.mock('../../lib/url-guard', () => ({
  validateExternalUrl: (...args: unknown[]) => validateExternalUrlMock(...args),
}));

import dastRouter from '../dast';

const app = express();
app.use(express.json());
app.use('/api/projects', dastRouter);

const PROJECT_ID = '11111111-1111-1111-1111-111111111111';
const ORG_ID = '22222222-2222-2222-2222-222222222222';
const USER_ID = 'mock-user-id';

beforeEach(() => {
  jest.clearAllMocks();
  clearTableRegistry();
  clearRpcRegistry();

  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: { id: USER_ID, email: 'test@example.com' } },
    error: null,
  });

  // Default: project belongs to ORG_ID and user has access.
  setTableResponse('projects', 'single', {
    data: { organization_id: ORG_ID },
    error: null,
  });
  checkProjectAccessMock.mockResolvedValue({ hasAccess: true });
  checkProjectManagePermissionMock.mockResolvedValue(true);
  validateExternalUrlMock.mockResolvedValue({ valid: true, resolved: { host: 'staging.example.com', addresses: ['1.2.3.4'] } });
});

describe('GET /api/projects/:projectId/dast/config', () => {
  it('returns auto defaults when no config row exists', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', { data: null, error: null });

    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body).toEqual({
      enabled: false,
      target_url: null,
      scan_profile: 'auto',
      scan_timeout_minutes: 30,
    });
  });

  it('returns the persisted config when present', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: {
        enabled: true,
        target_url: 'https://staging.example.com',
        scan_profile: 'full',
        scan_timeout_minutes: 45,
      },
      error: null,
    });

    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body.target_url).toBe('https://staging.example.com');
    expect(res.body.scan_profile).toBe('full');
    expect(res.body.scan_timeout_minutes).toBe(45);
    expect(res.body.enabled).toBe(true);
  });

  it('returns 404 when project does not exist', async () => {
    setTableResponse('projects', 'single', { data: null, error: null });
    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(404);
  });

  it('returns 403 when user is not a project member', async () => {
    checkProjectAccessMock.mockResolvedValue({
      hasAccess: false,
      error: { status: 403, message: 'Access denied' },
    });
    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(403);
  });
});

describe('PUT /api/projects/:projectId/dast/config', () => {
  it('rejects an invalid target URL with 422', async () => {
    validateExternalUrlMock.mockResolvedValue({ valid: false, reason: 'loopback rejected' });

    const res = await request(app)
      .put(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token')
      .send({
        enabled: true,
        target_url: 'http://localhost:3000',
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
      });

    expect(res.status).toBe(422);
    expect(res.body.error).toBe('invalid_target_url');
  });

  it('rejects enabled=true without a target URL', async () => {
    const res = await request(app)
      .put(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token')
      .send({
        enabled: true,
        target_url: null,
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
      });

    expect(res.status).toBe(422);
    expect(res.body.error).toBe('invalid_target_url');
  });

  it('saves a valid config and returns the persisted DTO', async () => {
    setTableResponse('project_dast_config', 'then', { data: null, error: null });

    const res = await request(app)
      .put(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token')
      .send({
        enabled: true,
        target_url: 'https://staging.example.com',
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
      });

    expect(res.status).toBe(200);
    expect(res.body.target_url).toBe('https://staging.example.com');
    expect(res.body.enabled).toBe(true);
  });

  it('returns 403 when user lacks manage permission', async () => {
    checkProjectManagePermissionMock.mockResolvedValue(false);

    const res = await request(app)
      .put(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token')
      .send({
        enabled: false,
        target_url: 'https://staging.example.com',
        scan_profile: 'auto',
        scan_timeout_minutes: 30,
      });

    expect(res.status).toBe(403);
  });

  it('clamps scan_timeout_minutes into the [5,60] range', async () => {
    setTableResponse('project_dast_config', 'then', { data: null, error: null });

    const res = await request(app)
      .put(`/api/projects/${PROJECT_ID}/dast/config`)
      .set('Authorization', 'Bearer valid-token')
      .send({
        enabled: false,
        target_url: 'https://staging.example.com',
        scan_profile: 'auto',
        scan_timeout_minutes: 9999,
      });

    expect(res.status).toBe(200);
    expect(res.body.scan_timeout_minutes).toBe(60);
  });
});

describe('POST /api/projects/:projectId/dast/scan', () => {
  it('returns 409 when DAST is not configured', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', { data: null, error: null });

    const res = await request(app)
      .post(`/api/projects/${PROJECT_ID}/dast/scan`)
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('dast_not_configured');
  });

  it('returns 409 when config is disabled', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { enabled: false, target_url: 'https://staging.example.com', scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });

    const res = await request(app)
      .post(`/api/projects/${PROJECT_ID}/dast/scan`)
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('dast_not_configured');
  });

  it('returns 422 when the saved URL fails validation (DNS-rebind defense)', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { enabled: true, target_url: 'https://staging.example.com', scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    validateExternalUrlMock.mockResolvedValue({ valid: false, reason: 'now resolves to private' });

    const res = await request(app)
      .post(`/api/projects/${PROJECT_ID}/dast/scan`)
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(res.status).toBe(422);
    expect(res.body.error).toBe('invalid_target_url');
  });

  it('returns 409 when project_concurrent_dast_blocked fires from queue_scan_job', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { enabled: true, target_url: 'https://staging.example.com', scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    setRpcResponse('queue_scan_job', {
      data: null,
      error: { message: 'project_concurrent_dast_blocked' },
    });

    const res = await request(app)
      .post(`/api/projects/${PROJECT_ID}/dast/scan`)
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(res.status).toBe(409);
    expect(res.body.error).toBe('project_concurrent_dast_blocked');
  });

  it('returns 202 with jobId on success and starts a Fly machine', async () => {
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { enabled: true, target_url: 'https://staging.example.com', scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });
    setRpcResponse('queue_scan_job', {
      data: [
        {
          id: 'job-abc',
          status: 'queued',
          target_url: 'https://staging.example.com',
          scan_profile: 'auto',
          created_at: new Date().toISOString(),
        },
      ],
      error: null,
    });

    const res = await request(app)
      .post(`/api/projects/${PROJECT_ID}/dast/scan`)
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(res.status).toBe(202);
    expect(res.body.jobId).toBe('job-abc');
    expect(startDastMachineMock).toHaveBeenCalled();
  });

  it('returns 403 when user lacks manage permission', async () => {
    checkProjectManagePermissionMock.mockResolvedValue(false);
    setTableResponse('project_dast_config', 'maybeSingle', {
      data: { enabled: true, target_url: 'https://staging.example.com', scan_profile: 'auto', scan_timeout_minutes: 30 },
      error: null,
    });

    const res = await request(app)
      .post(`/api/projects/${PROJECT_ID}/dast/scan`)
      .set('Authorization', 'Bearer valid-token')
      .send({});

    expect(res.status).toBe(403);
  });
});

describe('GET /api/projects/:projectId/dast/jobs', () => {
  it('returns the job list mapped to DastJobDTO shape', async () => {
    setTableResponse('scan_jobs', 'then', {
      data: [
        {
          id: 'job-1',
          status: 'completed',
          trigger_source: 'manual',
          target_url: 'https://staging.example.com',
          scan_profile: 'auto',
          findings_count: 7,
          duration_seconds: 142,
          started_at: null,
          completed_at: null,
          error: null,
          error_category: null,
          attempts: 1,
          created_at: new Date().toISOString(),
        },
      ],
      error: null,
    });

    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/jobs`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
    expect(res.body[0]).toHaveProperty('id', 'job-1');
    expect(res.body[0]).toHaveProperty('findings_count', 7);
  });

  it('returns [] when no jobs exist', async () => {
    setTableResponse('scan_jobs', 'then', { data: [], error: null });

    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/jobs`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });
});

describe('GET /api/projects/:projectId/dast/findings', () => {
  it('returns [] when project has no active_dast_run_id', async () => {
    setTableResponse('projects', 'single', {
      data: { organization_id: ORG_ID, active_dast_run_id: null },
      error: null,
    });

    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/findings`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body).toEqual([]);
  });

  it('maps findings + computes confirmed_exploitable from linked_sca_osv_id', async () => {
    setTableResponse('projects', 'single', {
      data: { organization_id: ORG_ID, active_dast_run_id: 'dast_run_42' },
      error: null,
    });
    setTableResponse('project_dast_findings', 'then', {
      data: [
        {
          id: 'f1',
          endpoint_url: '/api/users/42',
          http_method: 'GET',
          vulnerability_type: 'SQL Injection',
          severity: 'high',
          cwe_id: '89',
          owasp_top10_ref: 'A03:2021',
          rule_id: '40018-1',
          message: 'SQLi',
          payload_redacted: null,
          response_evidence_redacted: null,
          confidence: 'medium',
          handler_file_path: 'src/handlers/users.ts',
          handler_function_name: 'getUser',
          handler_line: 25,
          linked_sca_osv_id: 'CVE-2021-1234',
          linked_sca_project_dependency_id: 'pd-1',
          status: 'open',
          risk_accepted_reason: null,
          created_at: new Date().toISOString(),
        },
        {
          id: 'f2',
          endpoint_url: '/api/items',
          http_method: 'POST',
          vulnerability_type: 'XSS',
          severity: 'medium',
          cwe_id: '79',
          owasp_top10_ref: 'A03:2021',
          rule_id: '40012-1',
          message: 'XSS',
          payload_redacted: null,
          response_evidence_redacted: null,
          confidence: 'high',
          handler_file_path: null,
          handler_function_name: null,
          handler_line: null,
          linked_sca_osv_id: null,
          linked_sca_project_dependency_id: null,
          status: 'open',
          risk_accepted_reason: null,
          created_at: new Date().toISOString(),
        },
      ],
      error: null,
    });

    const res = await request(app)
      .get(`/api/projects/${PROJECT_ID}/dast/findings`)
      .set('Authorization', 'Bearer valid-token');

    expect(res.status).toBe(200);
    expect(res.body).toHaveLength(2);
    const linked = res.body.find((f: any) => f.id === 'f1');
    const standalone = res.body.find((f: any) => f.id === 'f2');
    expect(linked.confirmed_exploitable).toBe(true);
    expect(linked.linked_sca_osv_id).toBe('CVE-2021-1234');
    expect(standalone.confirmed_exploitable).toBe(false);
  });
});
