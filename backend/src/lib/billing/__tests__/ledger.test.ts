import {
  setTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../../test/mocks/supabaseSingleton';
import { recordMeterEvent, canCharge, setStripePaymentMethodFetcher, getBalance } from '../ledger';

const ORG_ID = '00000000-0000-0000-0000-000000000001';

function baseInput() {
  return {
    organizationId: ORG_ID,
    eventType: 'ai_tokens' as const,
    provider: 'anthropic' as const,
    feature: 'aegis.chat',
    quantity: 1000,
    outputQuantity: 500,
    unit: 'mixed_tokens' as const,
    cogCents: 5,
    chargedCents: 10,
    modelId: 'claude-haiku-4-5-20251001',
    idempotencyKey: 'aegis:turn-abc:tokens',
  };
}

describe('billing ledger — enforcement off', () => {
  const origEnv = process.env.DEPTEX_BILLING_ENFORCEMENT;
  let infoSpy: jest.SpyInstance;

  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'off';
    infoSpy = jest.spyOn(console, 'info').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = origEnv;
    infoSpy.mockRestore();
  });

  it('recordMeterEvent skips deduct and writes NO DB row', async () => {
    const rpcSpy = jest.fn();
    setRpcResponse('deduct_balance', { data: null, error: { message: 'should not be called' } });

    const result = await recordMeterEvent(baseInput());

    expect(result).toEqual({
      deducted: false,
      newBalanceCents: null,
      reason: 'enforcement_off',
    });
    expect(infoSpy).toHaveBeenCalledWith(
      '[billing.enforcement_off]',
      expect.objectContaining({ orgId: ORG_ID, feature: 'aegis.chat' }),
    );
    expect(rpcSpy).not.toHaveBeenCalled();
  });

  it('canCharge returns allowed:true with enforcement_off even when balance is $0', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 0 },
      error: null,
    });
    const result = await canCharge(ORG_ID, 999_999);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe('enforcement_off');
  });
});

describe('billing ledger — enforcement on', () => {
  const origEnv = process.env.DEPTEX_BILLING_ENFORCEMENT;

  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'on';
  });

  afterEach(() => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = origEnv;
  });

  it('recordMeterEvent happy path returns new balance', async () => {
    setTableResponse('billing_transactions', 'maybeSingle', { data: null, error: null });
    setRpcResponse('deduct_balance', { data: 490, error: null });

    const result = await recordMeterEvent(baseInput());
    expect(result.deducted).toBe(true);
    expect(result.newBalanceCents).toBe(490);
  });

  it('recordMeterEvent returns insufficient_credit when RPC returns null', async () => {
    setTableResponse('billing_transactions', 'maybeSingle', { data: null, error: null });
    setRpcResponse('deduct_balance', { data: null, error: null });
    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 5 },
      error: null,
    });

    const result = await recordMeterEvent(baseInput());
    expect(result.deducted).toBe(false);
    expect(result.reason).toBe('insufficient_credit');
    expect(result.newBalanceCents).toBe(5);
  });

  it('recordMeterEvent returns duplicate_idempotency_key when prior event exists', async () => {
    setTableResponse('billing_transactions', 'maybeSingle', {
      data: { id: 'existing-uuid', amount_cents: -10 },
      error: null,
    });
    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 500 },
      error: null,
    });
    const rpcSpy = jest.fn();
    setRpcResponse('deduct_balance', { data: null, error: { message: 'should not be called' } });

    const result = await recordMeterEvent(baseInput());
    expect(result.deducted).toBe(false);
    expect(result.reason).toBe('duplicate_idempotency_key');
    expect(result.newBalanceCents).toBe(500);
    expect(rpcSpy).not.toHaveBeenCalled();
  });

  it('recordMeterEvent throws on non-duplicate RPC error', async () => {
    setTableResponse('billing_transactions', 'maybeSingle', { data: null, error: null });
    setRpcResponse('deduct_balance', {
      data: null,
      error: { code: '42601', message: 'syntax error' },
    });
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    await expect(recordMeterEvent(baseInput())).rejects.toThrow(/deduct_balance failed/);
    errSpy.mockRestore();
  });

  it('canCharge returns allowed:true when balance covers estimate', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 1000 },
      error: null,
    });
    const result = await canCharge(ORG_ID, 500);
    expect(result.allowed).toBe(true);
    expect(result.balanceCents).toBe(1000);
  });

  it('canCharge returns allowed:false with insufficient_credit when balance short', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 100 },
      error: null,
    });
    const result = await canCharge(ORG_ID, 500);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe('insufficient_credit');
  });

  it('canCharge rounds up estimate (Math.ceil)', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 100 },
      error: null,
    });
    const onTheNose = await canCharge(ORG_ID, 100);
    expect(onTheNose.allowed).toBe(true);

    setTableResponse('organization_billing', 'single', {
      data: { balance_cents: 100 },
      error: null,
    });
    const justOver = await canCharge(ORG_ID, 100.001);
    expect(justOver.allowed).toBe(false);
  });
});

describe('billing ledger — getBalance', () => {
  const origEnv = process.env.DEPTEX_BILLING_ENFORCEMENT;

  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'on';
    setStripePaymentMethodFetcher(null);
  });

  afterEach(() => {
    process.env.DEPTEX_BILLING_ENFORCEMENT = origEnv;
    setStripePaymentMethodFetcher(null);
  });

  it('returns BillingState shape with null payment method when no fetcher set', async () => {
    setTableResponse('organization_billing', 'single', {
      data: {
        balance_cents: 1234,
        auto_recharge_enabled: false,
        auto_recharge_threshold_cents: null,
        auto_recharge_amount_cents: null,
        auto_recharge_monthly_cap_cents: null,
        low_balance_alert_threshold_cents: 500,
        stripe_customer_id: 'cus_x',
        stripe_default_payment_method_id: 'pm_x',
      },
      error: null,
    });

    const state = await getBalance(ORG_ID);
    expect(state).not.toBeNull();
    expect(state!.balanceCents).toBe(1234);
    expect(state!.paymentMethod).toBeNull();
  });

  it('invokes fetcher when present and returns its result', async () => {
    setTableResponse('organization_billing', 'single', {
      data: {
        balance_cents: 1000,
        auto_recharge_enabled: false,
        auto_recharge_threshold_cents: null,
        auto_recharge_amount_cents: null,
        auto_recharge_monthly_cap_cents: null,
        low_balance_alert_threshold_cents: 500,
        stripe_customer_id: 'cus_x',
        stripe_default_payment_method_id: 'pm_x',
      },
      error: null,
    });
    const fetcher = jest.fn().mockResolvedValue({
      brand: 'visa',
      last4: '4242',
      expiresMonth: 12,
      expiresYear: 2030,
    });
    setStripePaymentMethodFetcher(fetcher);

    const state = await getBalance(ORG_ID);
    expect(fetcher).toHaveBeenCalledWith('cus_x', 'pm_x');
    expect(state!.paymentMethod?.last4).toBe('4242');
  });

  it('returns null when org not in organization_billing', async () => {
    setTableResponse('organization_billing', 'single', {
      data: null,
      error: { message: 'not found', code: 'PGRST116' },
    });
    const state = await getBalance(ORG_ID);
    expect(state).toBeNull();
  });
});
