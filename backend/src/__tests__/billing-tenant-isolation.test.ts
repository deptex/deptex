import express from 'express';
import request from 'supertest';
import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

const ORG_A = '00000000-0000-0000-0000-00000000000a';
const ORG_B = '00000000-0000-0000-0000-00000000000b';
const USER = '00000000-0000-0000-0000-000000000099';

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER };
    next();
  },
}));

jest.mock('../lib/billing/stripe-billing', () => ({
  createPaymentIntent: jest.fn(),
  detachPaymentMethod: jest.fn(),
  setDefaultPaymentMethod: jest.fn(),
}));

jest.mock('../lib/billing/auto-recharge', () => ({
  maybeAutoRecharge: jest.fn().mockResolvedValue({ attempted: false, reason: 'disabled' }),
}));

import billingRouter from '../routes/billing';

const app = express();
app.use(express.json());
app.use('/api/organizations', billingRouter);

// User is a member of ORG_A only.
function memberOfA_attemptsB() {
  setTableResponse('organization_members', 'single', {
    data: null,
    error: { message: 'not found', code: 'PGRST116' },
  });
}

describe('billing routes — tenant isolation', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
  });

  const cases: Array<[string, () => request.Test]> = [
    ['GET /billing', () => request(app).get(`/api/organizations/${ORG_B}/billing`)],
    [
      'POST /topup',
      () =>
        request(app)
          .post(`/api/organizations/${ORG_B}/billing/topup`)
          .send({ amount_cents: 2500 }),
    ],
    [
      'PUT /auto-recharge',
      () =>
        request(app)
          .put(`/api/organizations/${ORG_B}/billing/auto-recharge`)
          .send({ enabled: false }),
    ],
    [
      'PUT /low-balance-threshold',
      () =>
        request(app)
          .put(`/api/organizations/${ORG_B}/billing/low-balance-threshold`)
          .send({ threshold_cents: 100 }),
    ],
    [
      'PUT /billing-email',
      () =>
        request(app)
          .put(`/api/organizations/${ORG_B}/billing/billing-email`)
          .send({ email: 'attacker@example.com' }),
    ],
    [
      'DELETE /payment-method',
      () => request(app).delete(`/api/organizations/${ORG_B}/billing/payment-method`),
    ],
    [
      'POST /payment-method',
      () =>
        request(app)
          .post(`/api/organizations/${ORG_B}/billing/payment-method`)
          .send({ payment_method_id: 'pm_x' }),
    ],
    [
      'GET /transactions',
      () => request(app).get(`/api/organizations/${ORG_B}/billing/transactions`),
    ],
    ['GET /usage', () => request(app).get(`/api/organizations/${ORG_B}/billing/usage`)],
  ];

  test.each(cases)('cross-org request to %s returns 403', async (_label, runRequest) => {
    memberOfA_attemptsB();
    const res = await runRequest();
    expect(res.status).toBe(403);
  });

  test('GET /transactions cursor derives org from URL param, not query', async () => {
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { manage_billing: true } },
      error: null,
    });
    setTableResponse('billing_transactions', 'then', { data: [], error: null });

    const res = await request(app)
      .get(`/api/organizations/${ORG_A}/billing/transactions`)
      .query({ cursor: 'malformed-or-stolen', limit: 10 });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ transactions: [] });
    void ORG_B;
  });
});
