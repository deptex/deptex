import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../../test/mocks/supabaseSingleton';

// A stale stripe_customer_id (created under a different Stripe key/mode) 404s on every
// billing call. ensureStripeCustomer must detect that and re-provision — but only for a
// genuine resource_missing, never for an auth/network blip (which would orphan a real
// customer). These pin both halves + the discriminator.

const mockRetrieve = jest.fn();
const mockCreate = jest.fn();

jest.mock('stripe', () =>
  jest.fn().mockImplementation(() => ({
    customers: { retrieve: mockRetrieve, create: mockCreate },
  })),
);

process.env.STRIPE_SECRET_KEY = 'sk_test_dummy';

import { ensureStripeCustomer, isStripeResourceMissing } from '../stripe-billing';

const ORG_ID = '00000000-0000-0000-0000-000000000001';

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  mockRetrieve.mockReset();
  mockCreate.mockReset();
  // Updates (clear stale id + persist new id) resolve through the `then` terminal.
  setTableResponse('organization_billing', 'then', { data: null, error: null });
  setTableResponse('organizations', 'single', { data: { id: ORG_ID, name: 'Acme' }, error: null });
});

describe('isStripeResourceMissing', () => {
  it('is true for a resource_missing / 404 invalid-request error', () => {
    expect(isStripeResourceMissing({ code: 'resource_missing' })).toBe(true);
    expect(isStripeResourceMissing({ type: 'StripeInvalidRequestError', statusCode: 404 })).toBe(true);
  });

  it('is false for auth / rate-limit / network errors and non-errors', () => {
    expect(isStripeResourceMissing({ type: 'StripeAuthenticationError', statusCode: 401 })).toBe(false);
    expect(isStripeResourceMissing({ type: 'StripeRateLimitError', statusCode: 429 })).toBe(false);
    expect(isStripeResourceMissing(new Error('socket hang up'))).toBe(false);
    expect(isStripeResourceMissing(null)).toBe(false);
  });
});

describe('ensureStripeCustomer', () => {
  it('returns the stored customer unchanged when it still exists', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { stripe_customer_id: 'cus_valid' },
      error: null,
    });
    mockRetrieve.mockResolvedValueOnce({ id: 'cus_valid' });

    const result = await ensureStripeCustomer(ORG_ID);

    expect(result).toBe('cus_valid');
    expect(mockCreate).not.toHaveBeenCalled();
  });

  it('re-provisions when the stored customer is missing under the active key', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { stripe_customer_id: 'cus_stale' },
      error: null,
    });
    mockRetrieve.mockRejectedValueOnce({
      code: 'resource_missing',
      type: 'StripeInvalidRequestError',
      statusCode: 404,
    });
    mockCreate.mockResolvedValueOnce({ id: 'cus_fresh' });

    const result = await ensureStripeCustomer(ORG_ID);

    expect(result).toBe('cus_fresh');
    expect(mockCreate).toHaveBeenCalledTimes(1);
  });

  it('re-throws (and does NOT re-provision) on a non-resource_missing Stripe error', async () => {
    setTableResponse('organization_billing', 'single', {
      data: { stripe_customer_id: 'cus_real' },
      error: null,
    });
    mockRetrieve.mockRejectedValueOnce({ type: 'StripeAuthenticationError', statusCode: 401 });

    await expect(ensureStripeCustomer(ORG_ID)).rejects.toBeDefined();
    expect(mockCreate).not.toHaveBeenCalled();
  });
});
