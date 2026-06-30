import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '../../../test/utils';
import { TopUpModal } from '../TopUpModal';

// supabase.auth.getSession is called by the modal (and by TopUpForm) to attach
// the bearer; return a fixed token so the GET /billing fetch proceeds.
vi.mock('../../../lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: 'tok' } } }),
    },
  },
}));

function stubBilling(body: { balanceCents: number; paymentMethod: unknown }) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => ({ ok: true, status: 200, json: async () => body })) as any,
  );
}

describe('TopUpModal', () => {
  beforeEach(() => {
    // Default: a funded org with a saved card.
    stubBilling({ balanceCents: 250, paymentMethod: { brand: 'visa', last4: '4242' } });
  });
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('shows a permission message and no form when the viewer cannot manage billing', () => {
    render(
      <TopUpModal
        open
        onOpenChange={() => {}}
        organizationId="org1"
        reason="insufficient_credit"
        canManageBilling={false}
      />,
    );
    expect(screen.getByText(/Only members with billing access can add credit/i)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Add credit/i })).toBeNull();
    expect(screen.queryByRole('button', { name: /Add a card/i })).toBeNull();
  });

  it('shows the balance and the top-up form when a payment method exists', async () => {
    render(
      <TopUpModal open onOpenChange={() => {}} organizationId="org1" reason="manual" canManageBilling />,
    );
    // Balance from GET /billing (250¢ → $2.50) renders after the async load.
    expect(await screen.findByText('$2.50')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Add credit/i })).toBeInTheDocument();
    // No add-card prompt when a card is on file.
    expect(screen.queryByRole('button', { name: /Add a card/i })).toBeNull();
  });

  it('prompts to add a card (not the top-up form) when there is no payment method', async () => {
    stubBilling({ balanceCents: 0, paymentMethod: null });
    render(
      <TopUpModal
        open
        onOpenChange={() => {}}
        organizationId="org1"
        reason="insufficient_credit"
        canManageBilling
      />,
    );
    expect(await screen.findByRole('button', { name: /Add a card/i })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Add credit/i })).toBeNull();
  });

  it('uses reason-keyed copy for the insufficient_credit header', async () => {
    render(
      <TopUpModal
        open
        onOpenChange={() => {}}
        organizationId="org1"
        reason="insufficient_credit"
        canManageBilling
      />,
    );
    expect(await screen.findByText(/out of AI credit/i)).toBeInTheDocument();
  });
});
