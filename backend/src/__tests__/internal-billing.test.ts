import express from 'express';
import request from 'supertest';
import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

// Valid v4 UUIDs — meterEventSchema validates organization_id / resource_id with z.string().uuid(),
// which (in this zod version) enforces the version/variant bits.
const ORG_ID = '11111111-1111-4111-8111-111111111111';
const OTHER_ORG = '22222222-2222-4222-8222-222222222222';
const RESOURCE_ID = '33333333-3333-4333-8333-333333333333';
const KEY = 'test-internal-key';

jest.mock('../lib/billing/ledger', () => ({
  recordMeterEvent: jest.fn().mockResolvedValue({ deducted: true, newBalanceCents: 5000, reason: null }),
  canCharge: jest.fn(),
}));
jest.mock('../lib/billing/pricing', () => ({
  chargedCentsForWorker: () => ({ cogCents: 1, chargedCents: 2 }),
}));
jest.mock('../lib/ai/pricing', () => ({
  chargedCentsForAi: () => ({ cogCents: 1, chargedCents: 2 }),
}));

import internalBillingRouter from '../routes/internal-billing';
import { recordMeterEvent } from '../lib/billing/ledger';

const app = express();
app.use(express.json());
app.use('/api/internal/billing', internalBillingRouter);

function workerEvent(attribution?: Record<string, string>) {
  const body: Record<string, unknown> = {
    organization_id: ORG_ID,
    event_type: 'worker_minutes',
    provider: 'fly',
    feature: 'fix-worker.task',
    quantity: 12,
    unit: 'seconds',
    machine_size: 'performance-2x',
    idempotency_key: 'k-1',
  };
  if (attribution) body.attribution = attribution;
  return body;
}

// P0-A regression guard: the meter-event route binds every charge to a real job row and
// fails closed. A leaked INTERNAL_API_KEY must not be able to charge an arbitrary org by
// omitting attribution or naming an unbindable / cross-tenant resource.
describe('internal-billing meter-event attribution (job-binding, fail-closed)', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.INTERNAL_API_KEY = KEY;
    (recordMeterEvent as jest.Mock).mockClear();
  });

  function post(body: unknown) {
    return request(app)
      .post('/api/internal/billing/meter-event')
      .set('x-internal-api-key', KEY)
      .send(body);
  }

  it('401s without the internal key', async () => {
    const res = await request(app).post('/api/internal/billing/meter-event').send(workerEvent());
    expect(res.status).toBe(401);
  });

  it('rejects (403) when attribution is missing — no unbound charge', async () => {
    const res = await post(workerEvent());
    expect(res.status).toBe(403);
    expect(res.body.error).toBe('attribution_mismatch');
    expect(recordMeterEvent).not.toHaveBeenCalled();
  });

  it('rejects (403) for an unbindable resource_type (rule_generation)', async () => {
    const res = await post(workerEvent({ resource_type: 'rule_generation', resource_id: RESOURCE_ID }));
    expect(res.status).toBe(403);
    expect(recordMeterEvent).not.toHaveBeenCalled();
  });

  it('rejects (403) when the fix_task belongs to another org (drain attempt)', async () => {
    setTableResponse('project_security_fixes', 'maybeSingle', { data: { organization_id: OTHER_ORG }, error: null });
    const res = await post(workerEvent({ resource_type: 'fix_task', resource_id: RESOURCE_ID }));
    expect(res.status).toBe(403);
    expect(recordMeterEvent).not.toHaveBeenCalled();
  });

  it('rejects (403) when the fix_task does not exist', async () => {
    setTableResponse('project_security_fixes', 'maybeSingle', { data: null, error: null });
    const res = await post(workerEvent({ resource_type: 'fix_task', resource_id: RESOURCE_ID }));
    expect(res.status).toBe(403);
    expect(recordMeterEvent).not.toHaveBeenCalled();
  });

  it('charges (200) when the fix_task is bound to the body org', async () => {
    setTableResponse('project_security_fixes', 'maybeSingle', { data: { organization_id: ORG_ID }, error: null });
    const res = await post(workerEvent({ resource_type: 'fix_task', resource_id: RESOURCE_ID }));
    expect(res.status).toBe(200);
    expect(recordMeterEvent).toHaveBeenCalledTimes(1);
  });
});
