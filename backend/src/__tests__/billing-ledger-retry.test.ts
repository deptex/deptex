import {
  setRpcResponse,
  pushRpcResponse,
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
  supabase,
} from '../test/mocks/supabaseSingleton';

// The post-deduction side-effects (auto-recharge + balance alerts) fire in a
// setImmediate inside recordMeterEvent and are covered elsewhere — stub them so the
// retry assertions aren't tangled up with their I/O.
jest.mock('../lib/billing/auto-recharge', () => ({
  maybeAutoRecharge: jest.fn().mockResolvedValue(undefined),
}));
jest.mock('../lib/billing/alerts', () => ({
  checkAndDispatchBalanceAlerts: jest.fn().mockResolvedValue(undefined),
}));

import { recordMeterEvent } from '../lib/billing/ledger';
import type { RecordMeterEventInput } from '../lib/billing/types';

const ORG_ID = '11111111-1111-4111-8111-111111111111';

function meterInput(): RecordMeterEventInput {
  return {
    organizationId: ORG_ID,
    eventType: 'worker_minutes',
    provider: 'fly',
    feature: 'fix-worker.task',
    quantity: 12,
    unit: 'seconds',
    cogCents: 1,
    chargedCents: 2,
    machineSize: 'performance-2x',
    idempotencyKey: 'k-retry-1',
  };
}

// Statement-timeout (57014) and a network-layer fetch failure (no SQLSTATE) are the
// canonical transient cases; P0001 (a RAISE inside the function) is the canonical
// deterministic/terminal case; 23505 is the idempotency dup.
const TRANSIENT = { data: null, error: { code: '57014', message: 'canceling statement due to statement timeout' } };
const NETWORK = { data: null, error: { code: '', message: 'TypeError: fetch failed' } };
const SUCCESS = { data: 4200, error: null };
const TERMINAL = { data: null, error: { code: 'P0001', message: 'business_rule_violation' } };
const DUP = { data: null, error: { code: '23505', message: 'duplicate key value violates unique constraint' } };

describe('recordMeterEvent — deduct_balance bounded retry (P1-13)', () => {
  const ORIGINAL_ENF = process.env.DEPTEX_BILLING_ENFORCEMENT;
  let warnSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;
  let infoSpy: jest.SpyInstance;

  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
    process.env.DEPTEX_BILLING_ENFORCEMENT = 'on';
    (supabase.rpc as jest.Mock).mockClear();
    warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    infoSpy = jest.spyOn(console, 'info').mockImplementation(() => {});
  });

  afterEach(async () => {
    // Drain the post-deduction setImmediate (success paths) before the test ends so its
    // async work runs against the stubbed side-effects, not after the suite tears down.
    await new Promise((resolve) => setImmediate(resolve));
    warnSpy.mockRestore();
    errorSpy.mockRestore();
    infoSpy.mockRestore();
  });

  afterAll(() => {
    if (ORIGINAL_ENF === undefined) delete process.env.DEPTEX_BILLING_ENFORCEMENT;
    else process.env.DEPTEX_BILLING_ENFORCEMENT = ORIGINAL_ENF;
  });

  it('retries a transient (statement-timeout) RPC error, then succeeds', async () => {
    pushRpcResponse('deduct_balance', TRANSIENT);
    pushRpcResponse('deduct_balance', SUCCESS);

    const result = await recordMeterEvent(meterInput());

    expect(result).toEqual({ deducted: true, newBalanceCents: 4200 });
    expect(supabase.rpc).toHaveBeenCalledTimes(2);
    expect(warnSpy).toHaveBeenCalledWith(
      '[billing.deduct] transient RPC error — retrying',
      expect.objectContaining({ code: '57014', attempt: 1 }),
    );
  });

  it('retries a network-layer failure that carries no SQLSTATE code', async () => {
    pushRpcResponse('deduct_balance', NETWORK);
    pushRpcResponse('deduct_balance', SUCCESS);

    const result = await recordMeterEvent(meterInput());

    expect(result).toEqual({ deducted: true, newBalanceCents: 4200 });
    expect(supabase.rpc).toHaveBeenCalledTimes(2);
  });

  it('gives up after MAX_DEDUCT_ATTEMPTS when the error stays transient, and throws', async () => {
    setRpcResponse('deduct_balance', TRANSIENT); // static → every attempt is transient

    await expect(recordMeterEvent(meterInput())).rejects.toThrow(/deduct_balance failed/);
    expect(supabase.rpc).toHaveBeenCalledTimes(3);
  });

  it('does NOT retry a deterministic/terminal error (P0001) — fails fast', async () => {
    setRpcResponse('deduct_balance', TERMINAL);

    await expect(recordMeterEvent(meterInput())).rejects.toThrow(/deduct_balance failed/);
    expect(supabase.rpc).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry a 23505 idempotency dup and reports duplicate (never double-charges)', async () => {
    // Pre-check finds no prior event (proceeds to RPC); the RPC then races a concurrent
    // commit and returns 23505; the post-23505 refetch finds the committed row.
    pushTableResponse('billing_transactions', { data: null, error: null });
    pushTableResponse('billing_transactions', { data: { id: 'evt-1', amount_cents: -2 }, error: null });
    setTableResponse('organization_billing', 'single', { data: { balance_cents: 4200 }, error: null });
    setRpcResponse('deduct_balance', DUP);

    const result = await recordMeterEvent(meterInput());

    expect(result).toEqual({
      deducted: false,
      newBalanceCents: 4200,
      reason: 'duplicate_idempotency_key',
    });
    expect(supabase.rpc).toHaveBeenCalledTimes(1);
  });

  it('does NOT retry an insufficient_credit result (data === null, no error)', async () => {
    setRpcResponse('deduct_balance', { data: null, error: null });
    setTableResponse('organization_billing', 'single', { data: { balance_cents: 1 }, error: null });

    const result = await recordMeterEvent(meterInput());

    expect(result).toEqual({ deducted: false, newBalanceCents: 1, reason: 'insufficient_credit' });
    expect(supabase.rpc).toHaveBeenCalledTimes(1);
  });
});
