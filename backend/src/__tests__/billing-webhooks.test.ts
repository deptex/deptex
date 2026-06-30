// Unit tests for the Stripe webhook handlers.
//
// These exercise the handler control flow (enforcement gate, cross-tenant guard,
// metadata fallback, dedup, error handling) via the shared mocked-supabase
// singleton. Idempotency at the SQL level (uq_billing_transactions_pi_credit,
// the credit_balance / deduct_balance RPCs themselves) is covered by
// billing-real-db.test.ts against a real Postgres.
//
// The handlers are exported from billing-stripe-webhooks.ts specifically so
// these tests can call them directly without going through HTTP + signature
// verification (which is covered by webhook-security.test.ts).

import {
  setTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
  queryBuilder,
} from '../test/mocks/supabaseSingleton';

jest.mock('../lib/billing/stripe-billing', () => ({
  voidOpenInvoice: jest.fn().mockResolvedValue(undefined),
  getInvoiceMetadata: jest.fn().mockResolvedValue(null),
  constructWebhookEvent: jest.fn(),
  isEventProcessed: jest.fn(),
  markEventProcessed: jest.fn(),
  claimWebhookEvent: jest.fn(),
}));
jest.mock('../lib/billing/alerts', () => ({
  sendAutoRechargeFailed: jest.fn().mockResolvedValue({ sent: true }),
  checkAndDispatchBalanceAlerts: jest.fn().mockResolvedValue(undefined),
}));

import {
  handlePaymentIntentSucceeded,
  handlePaymentIntentFailed,
  handleInvoicePaymentFailed,
  handlePaymentMethodDetached,
  handleCustomerDeleted,
} from '../routes/billing-stripe-webhooks';
import { sendAutoRechargeFailed, checkAndDispatchBalanceAlerts } from '../lib/billing/alerts';
import { voidOpenInvoice, getInvoiceMetadata } from '../lib/billing/stripe-billing';

const ORG_A = '00000000-0000-0000-0000-00000000000a';
const ORG_B = '00000000-0000-0000-0000-00000000000b';
const CUSTOMER_A = 'cus_test_a';

const ORIGINAL_ENFORCEMENT = process.env.DEPTEX_BILLING_ENFORCEMENT;

function resetMocks() {
  clearTableRegistry();
  clearRpcRegistry();
  (queryBuilder.update as jest.Mock).mockClear();
  (queryBuilder.update as jest.Mock).mockReturnThis();
  (sendAutoRechargeFailed as jest.Mock).mockClear();
  (checkAndDispatchBalanceAlerts as jest.Mock).mockClear();
  (voidOpenInvoice as jest.Mock).mockClear();
  (getInvoiceMetadata as jest.Mock).mockReset();
  (getInvoiceMetadata as jest.Mock).mockResolvedValue(null);
}

describe('handlePaymentIntentSucceeded', () => {
  beforeEach(() => {
    resetMocks();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'on';
  });
  afterAll(() => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = ORIGINAL_ENFORCEMENT;
  });

  it('returns early without crediting when metadata is missing and fallback fails', async () => {
    (getInvoiceMetadata as jest.Mock).mockResolvedValueOnce(null);
    await handlePaymentIntentSucceeded({
      id: 'pi_x',
      amount: 1000,
      customer: CUSTOMER_A,
      invoice: 'in_x',
      metadata: {},
    });
    // No update should have been called at all.
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });

  it('uses invoice metadata fallback when PI metadata is wiped', async () => {
    (getInvoiceMetadata as jest.Mock).mockResolvedValueOnce({
      organization_id: ORG_A,
      purpose: 'topup',
    });
    setTableResponse('organization_billing', 'single', {
      data: { organization_id: ORG_A, balance_cents: 1500 },
      error: null,
    });
    setRpcResponse('credit_balance', { data: 1500, error: null });

    await handlePaymentIntentSucceeded({
      id: 'pi_x',
      amount: 1500,
      customer: null, // no cross-tenant check when no customer
      invoice: 'in_x',
      metadata: {},
    });

    expect(getInvoiceMetadata).toHaveBeenCalledWith('in_x');
  });

  it('rejects cross-tenant mismatch when pi.customer belongs to a different org', async () => {
    // The customer lookup returns ORG_A, but metadata says ORG_B → reject.
    setTableResponse('organization_billing', 'single', {
      data: { organization_id: ORG_A },
      error: null,
    });
    setRpcResponse('credit_balance', { data: 1500, error: null });

    await handlePaymentIntentSucceeded({
      id: 'pi_x',
      amount: 1000,
      customer: CUSTOMER_A,
      metadata: { organization_id: ORG_B, purpose: 'topup' },
    });

    // No update on auto_recharge_in_progress should follow (we returned early).
    expect(queryBuilder.update).not.toHaveBeenCalledWith(
      expect.objectContaining({ auto_recharge_in_progress: false }),
    );
  });

  it('clears auto_recharge_in_progress on auto_recharge_topup success', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { organization_id: ORG_A, balance_cents: 3000 },
      error: null,
    });
    setRpcResponse('credit_balance', { data: 3000, error: null });

    await handlePaymentIntentSucceeded({
      id: 'pi_y',
      amount: 2000,
      customer: null,
      metadata: { organization_id: ORG_A, purpose: 'auto_recharge_topup' },
    });

    expect(queryBuilder.update).toHaveBeenCalledWith(
      expect.objectContaining({
        auto_recharge_in_progress: false,
        auto_recharge_in_progress_started_at: null,
      }),
    );
    expect(checkAndDispatchBalanceAlerts).toHaveBeenCalledWith(ORG_A, expect.any(Number));
  });

  it('does NOT throw + does NOT re-credit when credit_balance returns 23505', async () => {
    setRpcResponse('credit_balance', { data: null, error: { code: '23505', message: 'duplicate' } });

    await expect(
      handlePaymentIntentSucceeded({
        id: 'pi_dup',
        amount: 1000,
        customer: null,
        metadata: { organization_id: ORG_A, purpose: 'topup' },
      }),
    ).resolves.not.toThrow();
  });
});

describe('handlePaymentIntentFailed', () => {
  beforeEach(() => {
    resetMocks();
  });

  it('disables auto_recharge + sends email on auto_recharge_topup PI failure', async () => {
    await handlePaymentIntentFailed({
      id: 'pi_f',
      metadata: { organization_id: ORG_A, purpose: 'auto_recharge_topup' },
      last_payment_error: { message: 'Card was declined.', code: 'card_declined' },
    });

    expect(queryBuilder.update).toHaveBeenCalledWith(
      expect.objectContaining({
        auto_recharge_enabled: false,
        auto_recharge_in_progress: false,
      }),
    );
    expect(sendAutoRechargeFailed).toHaveBeenCalledWith(ORG_A, expect.stringContaining('declined'));
  });

  it('no-op when purpose is not auto_recharge_topup', async () => {
    await handlePaymentIntentFailed({
      id: 'pi_f',
      metadata: { organization_id: ORG_A, purpose: 'topup' },
    });
    expect(queryBuilder.update).not.toHaveBeenCalled();
    expect(sendAutoRechargeFailed).not.toHaveBeenCalled();
  });

  it('no-op when orgId missing', async () => {
    await handlePaymentIntentFailed({ id: 'pi_f', metadata: {} });
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});

describe('handleInvoicePaymentFailed', () => {
  beforeEach(() => {
    resetMocks();
  });

  it('disables auto_recharge + voids invoice + sends email on auto_recharge_topup failure', async () => {
    await handleInvoicePaymentFailed({
      id: 'in_f',
      customer: null,
      metadata: { organization_id: ORG_A, purpose: 'auto_recharge_topup' },
      last_payment_error: { message: 'Authentication required', code: 'authentication_required' },
    });

    expect(queryBuilder.update).toHaveBeenCalledWith(
      expect.objectContaining({
        auto_recharge_enabled: false,
        auto_recharge_in_progress: false,
      }),
    );
    expect(voidOpenInvoice).toHaveBeenCalledWith('in_f');
    expect(sendAutoRechargeFailed).toHaveBeenCalledWith(ORG_A, expect.stringContaining('Authentication'));
  });

  it('no-op when purpose is not auto_recharge_topup', async () => {
    await handleInvoicePaymentFailed({
      id: 'in_f',
      metadata: { organization_id: ORG_A, purpose: 'topup' },
    });
    expect(queryBuilder.update).not.toHaveBeenCalled();
    expect(voidOpenInvoice).not.toHaveBeenCalled();
  });

  it('rejects cross-tenant mismatch when invoice.customer belongs to a different org', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { organization_id: ORG_A },
      error: null,
    });

    await handleInvoicePaymentFailed({
      id: 'in_f',
      customer: CUSTOMER_A,
      metadata: { organization_id: ORG_B, purpose: 'auto_recharge_topup' },
    });

    expect(queryBuilder.update).not.toHaveBeenCalledWith(
      expect.objectContaining({ auto_recharge_enabled: false }),
    );
    expect(voidOpenInvoice).not.toHaveBeenCalled();
    expect(sendAutoRechargeFailed).not.toHaveBeenCalled();
  });
});

describe('handlePaymentMethodDetached', () => {
  beforeEach(() => {
    resetMocks();
  });

  it('nulls default PM + disables auto_recharge when an org has this PM as default', async () => {
    setTableResponse('organization_billing', 'maybeSingle', {
      data: { organization_id: ORG_A },
      error: null,
    });

    await handlePaymentMethodDetached({ id: 'pm_x' });

    expect(queryBuilder.update).toHaveBeenCalledWith(
      expect.objectContaining({
        stripe_default_payment_method_id: null,
        auto_recharge_enabled: false,
      }),
    );
  });

  it('no-op when no org has this PM as default', async () => {
    setTableResponse('organization_billing', 'maybeSingle', { data: null, error: null });

    await handlePaymentMethodDetached({ id: 'pm_x' });

    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});

describe('handleCustomerDeleted', () => {
  beforeEach(() => {
    resetMocks();
  });

  it('nulls customer_id + PM + disables auto_recharge', async () => {
    await handleCustomerDeleted({ id: CUSTOMER_A });

    expect(queryBuilder.update).toHaveBeenCalledWith(
      expect.objectContaining({
        stripe_customer_id: null,
        stripe_default_payment_method_id: null,
        auto_recharge_enabled: false,
        auto_recharge_in_progress: false,
      }),
    );
  });

  it('no-op when customer has no id', async () => {
    await handleCustomerDeleted({});
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});
