import express from 'express';
import request from 'supertest';
import {
  setTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
  queryBuilder,
} from '../test/mocks/supabaseSingleton';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = '00000000-0000-0000-0000-000000000099';

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER_ID };
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
import { createPaymentIntent } from '../lib/billing/stripe-billing';

const app = express();
app.use(express.json());
app.use('/api/organizations', billingRouter);

function setOwner() {
  setTableResponse('organization_members', 'single', {
    data: { role: 'owner' },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { manage_billing: true } },
    error: null,
  });
}

function setViewerWithoutManageBilling() {
  setTableResponse('organization_members', 'single', {
    data: { role: 'viewer' },
    error: null,
  });
  setTableResponse('organization_roles', 'single', {
    data: { permissions: { view_settings: true } },
    error: null,
  });
}

function setNonMember() {
  setTableResponse('organization_members', 'single', {
    data: null,
    error: { message: 'not found' },
  });
}

function setBillingState() {
  setTableResponse('organization_billing', 'single', {
    data: {
      balance_cents: 1234,
      auto_recharge_enabled: false,
      auto_recharge_threshold_cents: null,
      auto_recharge_amount_cents: null,
      auto_recharge_monthly_cap_cents: null,
      low_balance_alert_threshold_cents: 500,
      stripe_customer_id: null,
      stripe_default_payment_method_id: null,
    },
    error: null,
  });
}

describe('billing routes — GET /:id/billing', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    (createPaymentIntent as jest.Mock).mockReset();
  });

  it('403s non-members', async () => {
    setNonMember();
    const res = await request(app).get(`/api/organizations/${ORG_ID}/billing`);
    expect(res.status).toBe(403);
  });

  it('returns billing state for viewer with view_settings', async () => {
    setViewerWithoutManageBilling();
    setBillingState();
    const res = await request(app).get(`/api/organizations/${ORG_ID}/billing`);
    expect(res.status).toBe(200);
    expect(res.body.balanceCents).toBe(1234);
  });

  it('returns 404 when no billing row exists', async () => {
    setOwner();
    setTableResponse('organization_billing', 'single', {
      data: null,
      error: { message: 'not found' },
    });
    const res = await request(app).get(`/api/organizations/${ORG_ID}/billing`);
    expect(res.status).toBe(404);
  });
});

describe('billing routes — POST /:id/billing/topup', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'on';
    (createPaymentIntent as jest.Mock).mockReset();
  });

  it('403s users without manage_billing', async () => {
    setViewerWithoutManageBilling();
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/billing/topup`)
      .send({ amount_cents: 2500 });
    expect(res.status).toBe(403);
  });

  it('400s amounts below $5 minimum', async () => {
    setOwner();
    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/billing/topup`)
      .send({ amount_cents: 400 });
    expect(res.status).toBe(400);
  });

  it('returns client_secret on success', async () => {
    setOwner();
    (createPaymentIntent as jest.Mock).mockResolvedValueOnce({
      paymentIntent: { id: 'pi_x', client_secret: 'cs_x' },
      customerId: 'cus_x',
    });

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/billing/topup`)
      .send({ amount_cents: 2500 });
    expect(res.status).toBe(200);
    expect(res.body.clientSecret).toBe('cs_x');
    expect(res.body.amountCents).toBe(2500);
  });

  it('returns generic 500 on Stripe failure (no raw error surfaced)', async () => {
    setOwner();
    (createPaymentIntent as jest.Mock).mockRejectedValueOnce(
      new Error('stripe internal: card_error_xyz'),
    );
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const res = await request(app)
      .post(`/api/organizations/${ORG_ID}/billing/topup`)
      .send({ amount_cents: 2500 });
    expect(res.status).toBe(500);
    expect(res.body.error).toBe('Top-up failed. Please try again.');
    expect(JSON.stringify(res.body)).not.toContain('card_error_xyz');
    errSpy.mockRestore();
  });

});

describe('billing routes — PUT /:id/billing/auto-recharge', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
  });

  it('rejects enable without threshold + amount', async () => {
    setOwner();
    const res = await request(app)
      .put(`/api/organizations/${ORG_ID}/billing/auto-recharge`)
      .send({ enabled: true });
    expect(res.status).toBe(400);
  });

  it('rejects enable without payment method', async () => {
    setOwner();
    setTableResponse('organization_billing', 'single', {
      data: { stripe_default_payment_method_id: null },
      error: null,
    });

    const res = await request(app)
      .put(`/api/organizations/${ORG_ID}/billing/auto-recharge`)
      .send({ enabled: true, threshold_cents: 500, amount_cents: 2000 });
    expect(res.status).toBe(400);
  });

  it('rejects amount below minimum', async () => {
    setOwner();
    const res = await request(app)
      .put(`/api/organizations/${ORG_ID}/billing/auto-recharge`)
      .send({ enabled: true, threshold_cents: 500, amount_cents: 100 });
    expect(res.status).toBe(400);
  });

  it('returns ok on disable (no PM required)', async () => {
    setOwner();
    (queryBuilder.update as jest.Mock).mockReturnValue({
      eq: jest.fn().mockResolvedValue({ error: null }),
    });

    const res = await request(app)
      .put(`/api/organizations/${ORG_ID}/billing/auto-recharge`)
      .send({ enabled: false });
    expect(res.status).toBe(200);
  });
});
