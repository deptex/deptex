import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../../test/mocks/supabaseSingleton';

jest.mock('../stripe-billing', () => ({
  createPaymentIntent: jest.fn(),
}));

import { maybeAutoRecharge } from '../auto-recharge';
import { createPaymentIntent } from '../stripe-billing';

const ORG_ID = '00000000-0000-0000-0000-000000000001';

function billingRow(overrides: Partial<Record<string, any>> = {}) {
  return {
    organization_id: ORG_ID,
    balance_cents: 100,
    auto_recharge_enabled: true,
    auto_recharge_threshold_cents: 500,
    auto_recharge_amount_cents: 2000,
    auto_recharge_monthly_cap_cents: null,
    auto_recharge_in_progress: false,
    auto_recharge_in_progress_started_at: null,
    auto_recharge_last_attempt_at: null,
    stripe_default_payment_method_id: 'pm_test',
    ...overrides,
  };
}

describe('maybeAutoRecharge', () => {
  const origEnv = process.env.DEPTEX_BILLING_ENFORCEMENT;

  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'on';
    (createPaymentIntent as jest.Mock).mockReset();
  });

  afterEach(() => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = origEnv;
  });

  it('returns enforcement_off when DEPTEX_BILLING_ENFORCEMENT != on', async () => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'off';
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result).toEqual({ attempted: false, reason: 'enforcement_off' });
    expect(createPaymentIntent).not.toHaveBeenCalled();
  });

  it('returns disabled when auto_recharge_enabled = false', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({ auto_recharge_enabled: false }),
      error: null,
    });
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('disabled');
    expect(createPaymentIntent).not.toHaveBeenCalled();
  });

  it('returns disabled when threshold or amount missing', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({ auto_recharge_threshold_cents: null }),
      error: null,
    });
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('disabled');
  });

  it('returns no_payment_method when missing PM', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({ stripe_default_payment_method_id: null }),
      error: null,
    });
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('no_payment_method');
  });

  it('returns above_threshold when balance >= threshold', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({ balance_cents: 1000 }),
      error: null,
    });
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('above_threshold');
    expect(createPaymentIntent).not.toHaveBeenCalled();
  });

  it('clears stuck flag when in_progress > 30 minutes old', async () => {
    const oldTs = new Date(Date.now() - 31 * 60 * 1000).toISOString();
    setTableResponse('organization_billing', 'single', {
      data: billingRow({
        auto_recharge_in_progress: true,
        auto_recharge_in_progress_started_at: oldTs,
      }),
      error: null,
    });

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('stuck_flag_cleared');
  });

  it('returns in_progress when fresh in_progress flag set', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({
        auto_recharge_in_progress: true,
        auto_recharge_in_progress_started_at: new Date().toISOString(),
      }),
      error: null,
    });

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('in_progress');
    expect(createPaymentIntent).not.toHaveBeenCalled();
  });

  it('returns monthly_cap_reached when adding amount would exceed cap', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({ auto_recharge_monthly_cap_cents: 1000 }),
      error: null,
    });
    setTableResponse('billing_transactions', 'then', {
      data: [{ amount_cents: 800 }],
      error: null,
    });

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('monthly_cap_reached');
    expect(createPaymentIntent).not.toHaveBeenCalled();
  });

  it('creates PaymentIntent on happy path', async () => {
    setTableResponse('organization_billing', 'single', { data: billingRow(), error: null });
    (createPaymentIntent as jest.Mock).mockResolvedValueOnce({
      paymentIntent: { id: 'pi_x' },
      customerId: 'cus_x',
    });

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result).toEqual({
      attempted: true,
      reason: 'pi_created',
      paymentIntentId: 'pi_x',
    });
    expect(createPaymentIntent).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: ORG_ID,
        amountCents: 2000,
        purpose: 'auto_recharge_topup',
        offSession: true,
        paymentMethodId: 'pm_test',
      }),
    );
  });

  it('returns pi_failed and disables auto-recharge when PI creation throws', async () => {
    setTableResponse('organization_billing', 'single', { data: billingRow(), error: null });
    (createPaymentIntent as jest.Mock).mockRejectedValueOnce(new Error('card_declined'));
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('pi_failed');
    expect(result.attempted).toBe(true);

    errSpy.mockRestore();
  });
});
