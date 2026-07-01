import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '../../../test/utils';
import { UsageSectionContent } from '../UsageSectionContent';

// Regression: the usage breakdown used to be fetched twice on load — once on mount,
// then again when the projects list resolved and pre-selected every project (even
// though "all projects" was still on, so the request was identical). That produced
// the load → "no products" → load → "no products" flicker. It must fetch exactly once.

vi.mock('../../../lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({ data: { session: { access_token: 'tok' } } }),
    },
  },
}));

const emptyBreakdown = {
  buckets: [],
  products: [],
  totalCents: 0,
  granularity: 'day',
  cumulative: false,
  start: new Date('2026-06-01').toISOString(),
  end: new Date('2026-06-30').toISOString(),
};

describe('UsageSectionContent', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('fetches the breakdown once on mount, not a second time after projects load', async () => {
    let breakdownCalls = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: unknown) => {
        const u = String(url);
        if (u.includes('/billing/usage/breakdown')) {
          breakdownCalls++;
          return { ok: true, status: 200, json: async () => emptyBreakdown };
        }
        if (u.includes('/projects')) {
          return { ok: true, status: 200, json: async () => ({ projects: [{ id: 'p1', name: 'Project One' }] }) };
        }
        return { ok: true, status: 200, json: async () => ({}) };
      }) as any,
    );

    render(<UsageSectionContent organizationId="org1" />);

    // Once projects settle the trigger shows "All projects selected" — in the buggy
    // version the redundant second breakdown fetch fired right around here.
    expect(await screen.findByText('All projects selected')).toBeInTheDocument();
    // Let any queued follow-on effect fire.
    await new Promise((r) => setTimeout(r, 40));

    expect(breakdownCalls).toBe(1);
  });
});
