// Security gates on the two billed task routes — accepting or cancelling a task
// boots/stops a Fly machine, so a permission gap or a cross-tenant taskId is a
// spend-on-another-tenant vector. These assert 403 on missing permission and
// 404 on a cross-org taskId, with NO machine boot on either path.

import express from 'express';
import request from 'supertest';

import { setTableResponse, clearTableRegistry, clearRpcRegistry } from '../../test/mocks/supabaseSingleton';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const OTHER_ORG_ID = '00000000-0000-0000-0000-0000000000ff';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const TASK_ID = '00000000-0000-0000-0000-0000000000cc';

jest.mock('../../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
    next();
  },
}));

const mockStartFixMachine = jest.fn(async () => {});
jest.mock('../../lib/fly-machines', () => ({ startFixMachine: (...a: any[]) => mockStartFixMachine(...a) }));

import aegisTasksRouter from '../aegis-tasks';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/aegis/tasks', aegisTasksRouter);
  return app;
}

function setOwnerWithTriggerFix() {
  setTableResponse('organization_members', 'single', { data: { role: 'owner', user_id: USER_ID }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: { trigger_fix: true } }, error: null });
}
function setMemberWithoutTriggerFix() {
  setTableResponse('organization_members', 'single', { data: { role: 'member', user_id: USER_ID }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: { trigger_fix: false } }, error: null });
}
/** A task that belongs to ANOTHER org — the cross-tenant vector. */
function setCrossTenantTask() {
  setTableResponse('aegis_agent_tasks', 'maybeSingle', {
    data: { id: TASK_ID, organization_id: OTHER_ORG_ID, status: 'proposed', targets: [], title: 't' },
    error: null,
  });
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  mockStartFixMachine.mockClear();
});

describe('POST/PATCH aegis task routes — security gates', () => {
  test('accept without trigger_fix → 403, no machine boot', async () => {
    setMemberWithoutTriggerFix();
    const res = await request(makeApp())
      .patch(`/api/aegis/tasks/${TASK_ID}/accept`)
      .send({ organizationId: ORG_ID });
    expect(res.status).toBe(403);
    expect(mockStartFixMachine).not.toHaveBeenCalled();
  });

  test('accept a cross-tenant taskId → 404, no machine boot', async () => {
    setOwnerWithTriggerFix();
    setCrossTenantTask();
    const res = await request(makeApp())
      .patch(`/api/aegis/tasks/${TASK_ID}/accept`)
      .send({ organizationId: ORG_ID });
    expect(res.status).toBe(404);
    expect(mockStartFixMachine).not.toHaveBeenCalled();
  });

  test('accept without organizationId → 400', async () => {
    const res = await request(makeApp()).patch(`/api/aegis/tasks/${TASK_ID}/accept`).send({});
    expect(res.status).toBe(400);
    expect(mockStartFixMachine).not.toHaveBeenCalled();
  });

  test('cancel without trigger_fix → 403', async () => {
    setMemberWithoutTriggerFix();
    const res = await request(makeApp())
      .post(`/api/aegis/tasks/${TASK_ID}/cancel`)
      .send({ organizationId: ORG_ID });
    expect(res.status).toBe(403);
  });

  test('cancel a cross-tenant taskId → 404', async () => {
    setOwnerWithTriggerFix();
    setCrossTenantTask();
    const res = await request(makeApp())
      .post(`/api/aegis/tasks/${TASK_ID}/cancel`)
      .send({ organizationId: ORG_ID });
    expect(res.status).toBe(404);
  });
});
