import {
  computeAdminBillingFinancials,
  AdminBillingMathInput,
} from '../lib/billing/admin-financials';

// The admin /billing route pages five kind-filtered queries off ONE table, so the
// table-keyed singleton mock can't feed them distinct rows — the whole money math
// collapses to zero under the route test (audit P0-9). These assert the extracted
// pure function against known inputs so a sign flip / proration / off-by-one is caught.

const NOW = Date.UTC(2026, 5, 2, 12, 0, 0); // 2026-06-02T12:00:00Z
const DAY = 24 * 60 * 60 * 1000;
const iso = (ms: number) => new Date(ms).toISOString();
const dayStr = (ms: number) => new Date(ms).toISOString().slice(0, 10);

function run(partial: Partial<AdminBillingMathInput>) {
  return computeAdminBillingFinancials({
    now: NOW,
    balanceRows: [],
    grantRows: [],
    depositRows: [],
    refundRows: [],
    usageRows: [],
    ...partial,
  });
}

describe('computeAdminBillingFinancials — deposits (net cash in)', () => {
  it('sums topups/auto-recharges and subtracts refunds', () => {
    const { financials } = run({
      depositRows: [
        { amount_cents: 5000, created_at: iso(NOW) },
        { amount_cents: 3000, created_at: iso(NOW) },
      ],
      refundRows: [{ amount_cents: 1000 }],
    });
    expect(financials.depositsCents).toBe(7000);
  });

  it('subtracts refunds by magnitude regardless of stored sign', () => {
    // The audit disputed a "double-count" P0; Math.abs makes the net correct whether
    // refunds are stored positive or negative. Pin both directions.
    const positive = run({
      depositRows: [{ amount_cents: 8000, created_at: iso(NOW) }],
      refundRows: [{ amount_cents: 1000 }],
    });
    const negative = run({
      depositRows: [{ amount_cents: 8000, created_at: iso(NOW) }],
      refundRows: [{ amount_cents: -1000 }],
    });
    expect(positive.financials.depositsCents).toBe(7000);
    expect(negative.financials.depositsCents).toBe(7000);
  });
});

describe('computeAdminBillingFinancials — gross margin', () => {
  it('charges = -amount_cents (usage is negative); margin = charged - cogs', () => {
    const { financials } = run({
      usageRows: [
        { organization_id: 'a', amount_cents: -100, cost_cents_cog: 40 },
        { organization_id: 'a', amount_cents: -50, cost_cents_cog: 20 },
      ],
    });
    // charged 150, cogs 60
    expect(financials.grossMarginCents).toBe(90);
  });
});

describe('computeAdminBillingFinancials — free-credit split (spent-first estimate)', () => {
  it('prorates burned free credit by the share of charges covered by the grant', () => {
    const { financials } = run({
      grantRows: [{ organization_id: 'a', amount_cents: 500 }],
      usageRows: [{ organization_id: 'a', amount_cents: -800, cost_cents_cog: 320 }],
      balanceRows: [{ organization_id: 'a', balance_cents: 0 }],
    });
    // freeUsed = min(500, 800) = 500 → burned = 320 * 500/800 = 200
    expect(financials.freeCreditBurnedCents).toBe(200);
    expect(financials.freeCreditOutstandingCents).toBe(0); // grant fully consumed
    expect(financials.realBalanceHeldCents).toBe(0);
    expect(financials.grossMarginCents).toBe(480); // 800 - 320
  });

  it('counts unspent grant as outstanding and paid cash beyond it as real balance', () => {
    const { financials } = run({
      grantRows: [{ organization_id: 'b', amount_cents: 500 }],
      balanceRows: [{ organization_id: 'b', balance_cents: 1500 }], // 500 grant + 1000 paid
    });
    expect(financials.freeCreditBurnedCents).toBe(0);
    expect(financials.freeCreditOutstandingCents).toBe(500);
    expect(financials.realBalanceHeldCents).toBe(1000);
  });

  it('guards divide-by-zero when an org has zero charges (no NaN)', () => {
    const { financials } = run({
      grantRows: [{ organization_id: 'c', amount_cents: 500 }],
      usageRows: [{ organization_id: 'c', amount_cents: 0, cost_cents_cog: 0 }],
      balanceRows: [{ organization_id: 'c', balance_cents: 500 }],
    });
    expect(financials.freeCreditBurnedCents).toBe(0);
    expect(Number.isNaN(financials.freeCreditBurnedCents)).toBe(false);
  });

  it('rounds a fractional proration to the nearest cent', () => {
    const { financials } = run({
      grantRows: [{ organization_id: 'a', amount_cents: 100 }],
      usageRows: [{ organization_id: 'a', amount_cents: -300, cost_cents_cog: 100 }],
      balanceRows: [{ organization_id: 'a', balance_cents: 0 }],
    });
    // freeUsed = 100 → burned = 100 * 100/300 = 33.33… → 33
    expect(financials.freeCreditBurnedCents).toBe(33);
  });

  it('aggregates the split across multiple orgs', () => {
    const { financials } = run({
      grantRows: [
        { organization_id: 'a', amount_cents: 500 },
        { organization_id: 'b', amount_cents: 500 },
      ],
      usageRows: [{ organization_id: 'a', amount_cents: -800, cost_cents_cog: 320 }],
      balanceRows: [
        { organization_id: 'a', balance_cents: 0 },
        { organization_id: 'b', balance_cents: 1500 },
      ],
    });
    // a: burned 200, outstanding 0, real 0  |  b: burned 0, outstanding 500, real 1000
    expect(financials.freeCreditBurnedCents).toBe(200);
    expect(financials.freeCreditOutstandingCents).toBe(500);
    expect(financials.realBalanceHeldCents).toBe(1000);
    expect(financials.grossMarginCents).toBe(480);
  });
});

describe('computeAdminBillingFinancials — deposit windows + revenue series', () => {
  it('windows the 30-day total and the 365-day series independently of lifetime deposits', () => {
    const { financials, revenueSeries } = run({
      depositRows: [
        { amount_cents: 1000, created_at: iso(NOW - 10 * DAY) }, // inside 30d + 365d
        { amount_cents: 2000, created_at: iso(NOW - 40 * DAY) }, // outside 30d, inside 365d
        { amount_cents: 500, created_at: iso(NOW - 400 * DAY) }, // outside the 365d series
      ],
    });
    expect(financials.depositsCents).toBe(3500); // lifetime gross, unwindowed
    expect(financials.deposits30dCents).toBe(1000); // only the 10-day-ago deposit

    expect(revenueSeries).toHaveLength(365);
    expect(revenueSeries.find((p) => p.date === dayStr(NOW - 10 * DAY))?.cents).toBe(1000);
    expect(revenueSeries.find((p) => p.date === dayStr(NOW - 40 * DAY))?.cents).toBe(2000);
    // 400-day-ago deposit has no bucket in the 365-day series.
    const seriesTotal = revenueSeries.reduce((s, p) => s + p.cents, 0);
    expect(seriesTotal).toBe(3000);
  });
});

describe('computeAdminBillingFinancials — empty input', () => {
  it('returns all-zero financials and a full 365-day series', () => {
    const { financials, revenueSeries } = run({});
    expect(financials).toEqual({
      depositsCents: 0,
      deposits30dCents: 0,
      grossMarginCents: 0,
      freeCreditBurnedCents: 0,
      realBalanceHeldCents: 0,
      freeCreditOutstandingCents: 0,
    });
    expect(revenueSeries).toHaveLength(365);
    expect(revenueSeries.every((p) => p.cents === 0)).toBe(true);
  });
});
