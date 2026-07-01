import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '../../../test/utils';
import { PaymentMethodsCard } from '../PaymentMethodsCard';

// Regression: a failing /payment-methods fetch used to leave the card on its loading
// skeleton forever (the "never loads" bug). It must now surface an error + Retry.

vi.mock('../../../contexts/AuthContext', () => ({
  useAuth: () => ({ user: { email: 'henry@example.com' } }),
}));
vi.mock('../../../lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: 'tok' } } }),
    },
  },
}));

function stubFetch(impl: () => Promise<any>) {
  vi.stubGlobal('fetch', vi.fn(impl) as any);
}

describe('PaymentMethodsCard', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('shows an error + Retry (not an endless skeleton) when the fetch fails', async () => {
    stubFetch(async () => ({ ok: false, status: 500, json: async () => ({ error: 'Failed' }) }));
    render(<PaymentMethodsCard organizationId="org1" />);
    expect(await screen.findByText(/Couldn't load payment methods/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Try again/i })).toBeInTheDocument();
  });

  it('renders the saved cards on success', async () => {
    stubFetch(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        payment_methods: [
          { id: 'pm_1', brand: 'visa', last4: '4242', expiresMonth: 12, expiresYear: 2030, isDefault: true },
        ],
      }),
    }));
    render(<PaymentMethodsCard organizationId="org1" />);
    expect(await screen.findByText(/4242/)).toBeInTheDocument();
    expect(screen.getByText(/Valid until 12\/2030/i)).toBeInTheDocument();
  });

  it('shows the empty state when there are no saved cards', async () => {
    stubFetch(async () => ({ ok: true, status: 200, json: async () => ({ payment_methods: [] }) }));
    render(<PaymentMethodsCard organizationId="org1" />);
    expect(await screen.findByText(/No payment methods/i)).toBeInTheDocument();
  });
});
