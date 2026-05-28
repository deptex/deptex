import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../../test/mocks/supabaseSingleton';

jest.mock('../stripe-billing', () => ({
  createTopUpInvoice: jest.fn(),
}));

jest.mock('../alerts', () => ({
  resolveBillingRecipients: jest.fn().mockResolvedValue(['owner@example.com']),
  sendAutoRechargeFailed: jest.fn().mockResolvedValue({ sent: true }),
}));

import { maybeAutoRecharge } from '../auto-recharge';
import { createTopUpInvoice } from '../stripe-billing';
import { sendAutoRechargeFailed } from '../alerts';

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
    (createTopUpInvoice as jest.Mock).mockReset();
    (sendAutoRechargeFailed as jest.Mock).mockClear();
  });

  afterEach(() => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = origEnv;
  });

  it('returns enforcement_off when DEPTEX_BILLING_ENFORCEMENT != on', async () => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'off';
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result).toEqual({ attempted: false, reason: 'enforcement_off' });
    expect(createTopUpInvoice).not.toHaveBeenCalled();
  });

  it('returns disabled when auto_recharge_enabled = false', async () => {
    setTableResponse('organization_billing', 'single', {
      data: billingRow({ auto_recharge_enabled: false }),
      error: null,
    });
    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('disabled');
    expect(createTopUpInvoice).not.toHaveBeenCalled();
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
    expect(createTopUpInvoice).not.toHaveBeenCalled();
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
    expect(createTopUpInvoice).not.toHaveBeenCalled();
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
    expect(createTopUpInvoice).not.toHaveBeenCalled();
  });

  it('creates invoice top-up on happy path', async () => {
    setTableResponse('organization_billing', 'single', { data: billingRow(), error: null });
    (createTopUpInvoice as jest.Mock).mockResolvedValueOnce({
      status: 'succeeded',
      clientSecret: null,
      paymentIntentId: 'pi_x',
      invoiceId: 'in_x',
      subtotalCents: 2000,
      taxCents: 0,
      totalCents: 2000,
    });

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result).toEqual({
      attempted: true,
      reason: 'pi_created',
      paymentIntentId: 'pi_x',
    });
    expect(createTopUpInvoice).toHaveBeenCalledWith(
      expect.objectContaining({
        orgId: ORG_ID,
        amountCents: 2000,
        purpose: 'auto_recharge_topup',
        fallbackEmail: 'owner@example.com',
      }),
    );
  });

  it('returns pi_failed when invoice top-up throws', async () => {
    setTableResponse('organization_billing', 'single', { data: billingRow(), error: null });
    (createTopUpInvoice as jest.Mock).mockRejectedValueOnce(new Error('card_declined'));
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('pi_failed');
    expect(result.attempted).toBe(true);
    expect(sendAutoRechargeFailed).toHaveBeenCalledWith(ORG_ID, 'card_declined');

    errSpy.mockRestore();
  });

  it('returns pi_failed and disables auto-recharge when needs_setup', async () => {
    setTableResponse('organization_billing', 'single', { data: billingRow(), error: null });
    (createTopUpInvoice as jest.Mock).mockResolvedValueOnce({
      status: 'needs_setup',
      clientSecret: null,
      paymentIntentId: null,
      invoiceId: '',
      subtotalCents: 2000,
      taxCents: 0,
      totalCents: 2000,
    });
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});

    const result = await maybeAutoRecharge(ORG_ID);
    expect(result.reason).toBe('pi_failed');
    expect(sendAutoRechargeFailed).toHaveBeenCalledWith(
      ORG_ID,
      expect.stringContaining('Billing address'),
    );

    warnSpy.mockRestore();
  });
});
