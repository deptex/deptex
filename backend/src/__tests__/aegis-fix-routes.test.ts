import express from 'express';
import request from 'supertest';

import {
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const PROJECT_ID = '00000000-0000-0000-0000-000000000002';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const FIX_ID = '00000000-0000-0000-0000-0000000000ab';

process.env.INTERNAL_API_KEY = 'test-internal-key';

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
    next();
  },
}));

const mockGenerateFixPlan = jest.fn();
jest.mock('../lib/aegis-v3/fix-planner', () => ({
  __esModule: true,
  generateFixPlan: (input: any) => mockGenerateFixPlan(input),
}));

import aegisFixRouter from '../routes/aegis-fix';
import { signApprovalToken } from '../lib/aegis-v3/approval-token';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/aegis/fix', aegisFixRouter);
  return app;
}

function setOwnerWithTriggerFix() {
  setTableResponse('organization_members', 'single', {
    data: { role: 'owner', user_id: USER_ID },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { trigger_fix: true } },
    error: null,
  });
}

function setMemberWithoutTriggerFix() {
  setTableResponse('organization_members', 'single', {
    data: { role: 'member', user_id: USER_ID },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { trigger_fix: false } },
    error: null,
  });
}

function happyPlan() {
  return {
    summary: 'Bump lodash 4.17.20 to 4.17.21',
    finding: { type: 'vulnerability', id: 'GHSA-abc-def-ghi', severity: 'high' },
    currentState: ['lodash@4.17.20'],
    desiredState: ['lodash@4.17.21'],
    fileChanges: [{ path: 'package.json', action: 'modify', description: 'Bump' }],
    testCommand: 'npm test',
    language: 'js',
    estimatedDiffSize: 'small',
    wallClockBudgetSec: 300,
  };
}

function refusalPlan() {
  return {
    ...happyPlan(),
    refusal: { reason: 'No patched version available.' },
  };
}

function setInsertReturning(fixId: string) {
  // Single is consumed in queue order. The insert call's .select('id').single()
  // is the first single read against project_security_fixes for the request.
  pushTableResponse('project_security_fixes', { data: { id: fixId }, error: null });
}

function setLoadFixRow(row: any) {
  setTableResponse('project_security_fixes', 'maybeSingle', { data: row, error: null });
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  mockGenerateFixPlan.mockReset();
});

describe('POST /api/aegis/fix/request', () => {
  it('rejects requests missing required fields', async () => {
    const res = await request(makeApp())
      .post('/api/aegis/fix/request')
      .send({ organizationId: ORG_ID });
    expect(res.status).toBe(400);
  });

  it('rejects an unsupported findingType', async () => {
    const res = await request(makeApp())
      .post('/api/aegis/fix/request')
      .send({
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        findingType: 'unknown',
        findingId: 'x',
      });
    expect(res.status).toBe(400);
  });

  it('returns 403 when caller lacks trigger_fix', async () => {
    setMemberWithoutTriggerFix();
    const res = await request(makeApp())
      .post('/api/aegis/fix/request')
      .send({
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        findingType: 'vulnerability',
        findingId: 'GHSA-abc-def-ghi',
      });
    expect(res.status).toBe(403);
  });

  it('happy path: persists plan and returns awaiting_approval', async () => {
    setOwnerWithTriggerFix();
    setInsertReturning(FIX_ID);
    setLoadFixRow({
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'awaiting_approval',
      plan: happyPlan(),
      plan_generated_at: new Date().toISOString(),
      plan_base_sha: 'sha123',
      plan_base_branch: 'main',
      approval_token: 'token-placeholder',
      approved_at: null,
      rejected_at: null,
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: null,
      created_at: new Date().toISOString(),
      triggered_by: USER_ID,
      osv_id: 'GHSA-abc-def-ghi',
      semgrep_finding_id: null,
      secret_finding_id: null,
    });
    mockGenerateFixPlan.mockResolvedValue({
      plan: happyPlan(),
      baseSha: 'sha123',
      baseBranch: 'main',
      repoFullName: 'acme/payments',
    });

    const res = await request(makeApp())
      .post('/api/aegis/fix/request')
      .send({
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        findingType: 'vulnerability',
        findingId: 'GHSA-abc-def-ghi',
      });

    expect(res.status).toBe(201);
    expect(res.body.fixId).toBe(FIX_ID);
    expect(res.body.status).toBe('awaiting_approval');
    expect(res.body.plan).toMatchObject({ summary: expect.any(String), language: 'js' });
    expect(mockGenerateFixPlan).toHaveBeenCalledWith({
      organizationId: ORG_ID,
      projectId: PROJECT_ID,
      findingType: 'vulnerability',
      findingId: 'GHSA-abc-def-ghi',
      triggeredByUserId: USER_ID,
    });
  });

  it('refusal path: returns failed status when planner sets refusal', async () => {
    setOwnerWithTriggerFix();
    setInsertReturning(FIX_ID);
    setLoadFixRow({
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'failed',
      plan: refusalPlan(),
      plan_generated_at: new Date().toISOString(),
      plan_base_sha: 'sha456',
      plan_base_branch: 'main',
      approval_token: null,
      approved_at: null,
      rejected_at: null,
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: 'Refusal: No patched version available.',
      created_at: new Date().toISOString(),
      triggered_by: USER_ID,
      osv_id: 'GHSA-no-patch',
      semgrep_finding_id: null,
      secret_finding_id: null,
    });
    mockGenerateFixPlan.mockResolvedValue({
      plan: refusalPlan(),
      baseSha: 'sha456',
      baseBranch: 'main',
      repoFullName: 'acme/payments',
    });

    const res = await request(makeApp())
      .post('/api/aegis/fix/request')
      .send({
        organizationId: ORG_ID,
        projectId: PROJECT_ID,
        findingType: 'vulnerability',
        findingId: 'GHSA-no-patch',
      });

    expect(res.status).toBe(201);
    expect(res.body.status).toBe('failed');
    expect(res.body.plan.refusal.reason).toMatch(/No patched version/);
  });
});

describe('PATCH /api/aegis/fix/:fixId/approve', () => {
  it('rejects with 401 when token does not match', async () => {
    const generatedAt = new Date().toISOString();
    setLoadFixRow({
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'awaiting_approval',
      plan: happyPlan(),
      plan_generated_at: generatedAt,
      plan_base_sha: 'sha123',
      plan_base_branch: 'main',
      approval_token: signApprovalToken(FIX_ID, ORG_ID, generatedAt),
      approved_at: null,
      rejected_at: null,
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: null,
      created_at: generatedAt,
      triggered_by: USER_ID,
      osv_id: 'GHSA-abc',
      semgrep_finding_id: null,
      secret_finding_id: null,
    });
    setOwnerWithTriggerFix();

    const res = await request(makeApp())
      .patch(`/api/aegis/fix/${FIX_ID}/approve`)
      .send({ token: 'forged' });
    expect(res.status).toBe(401);
  });

  it('approves when valid token + status awaiting_approval', async () => {
    const generatedAt = new Date().toISOString();
    const validToken = signApprovalToken(FIX_ID, ORG_ID, generatedAt);
    const baseRow = {
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'awaiting_approval',
      plan: happyPlan(),
      plan_generated_at: generatedAt,
      plan_base_sha: 'sha123',
      plan_base_branch: 'main',
      approval_token: validToken,
      approved_at: null,
      rejected_at: null,
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: null,
      created_at: generatedAt,
      triggered_by: USER_ID,
      osv_id: 'GHSA-abc',
      semgrep_finding_id: null,
      secret_finding_id: null,
    };
    setLoadFixRow(baseRow);
    setOwnerWithTriggerFix();

    const res = await request(makeApp())
      .patch(`/api/aegis/fix/${FIX_ID}/approve`)
      .send({ token: validToken });
    expect(res.status).toBe(200);
    expect(res.body.fix).toBeTruthy();
  });

  it('returns 409 when fix is not awaiting_approval', async () => {
    setLoadFixRow({
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'rejected',
      plan: happyPlan(),
      plan_generated_at: new Date().toISOString(),
      plan_base_sha: 'sha123',
      plan_base_branch: 'main',
      approval_token: 'whatever',
      approved_at: null,
      rejected_at: new Date().toISOString(),
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: null,
      created_at: new Date().toISOString(),
      triggered_by: USER_ID,
      osv_id: 'GHSA-abc',
      semgrep_finding_id: null,
      secret_finding_id: null,
    });
    setOwnerWithTriggerFix();

    const res = await request(makeApp())
      .patch(`/api/aegis/fix/${FIX_ID}/approve`)
      .send({ token: 'whatever' });
    expect(res.status).toBe(409);
  });
});

describe('PATCH /api/aegis/fix/:fixId/reject', () => {
  it('rejects when status is awaiting_approval', async () => {
    setLoadFixRow({
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'awaiting_approval',
      plan: happyPlan(),
      plan_generated_at: new Date().toISOString(),
      plan_base_sha: 'sha123',
      plan_base_branch: 'main',
      approval_token: 'tok',
      approved_at: null,
      rejected_at: null,
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: null,
      created_at: new Date().toISOString(),
      triggered_by: USER_ID,
      osv_id: 'GHSA-abc',
      semgrep_finding_id: null,
      secret_finding_id: null,
    });
    setOwnerWithTriggerFix();

    const res = await request(makeApp())
      .patch(`/api/aegis/fix/${FIX_ID}/reject`)
      .send({ reason: 'not safe' });
    expect(res.status).toBe(200);
    expect(res.body.fix).toBeTruthy();
  });

  it('403 when user lacks trigger_fix', async () => {
    setLoadFixRow({
      id: FIX_ID,
      organization_id: ORG_ID,
      project_id: PROJECT_ID,
      fix_type: 'vulnerability',
      status: 'awaiting_approval',
      plan: happyPlan(),
      plan_generated_at: new Date().toISOString(),
      plan_base_sha: 'sha123',
      plan_base_branch: 'main',
      approval_token: 'tok',
      approved_at: null,
      rejected_at: null,
      pr_url: null,
      pr_number: null,
      diff_summary: null,
      error_message: null,
      created_at: new Date().toISOString(),
      triggered_by: USER_ID,
      osv_id: 'GHSA-abc',
      semgrep_finding_id: null,
      secret_finding_id: null,
    });
    setMemberWithoutTriggerFix();

    const res = await request(makeApp())
      .patch(`/api/aegis/fix/${FIX_ID}/reject`)
      .send({});
    expect(res.status).toBe(403);
  });
});
