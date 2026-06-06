// Pure aggregation behind the admin /billing financial snapshot. Extracted from the
// route handler so the money math is unit-testable with known inputs: deposit
// net-of-refunds, the 30-day + 365-day deposit windows, gross-margin sign, and the
// free-credit-spent-first proration / per-org rollup. Under the route's table-keyed
// paginated mock these all collapse to zero (and the four kind-filtered
// billing_transactions queries can't be given distinct rows), so a sign flip or
// off-by-one would otherwise ship uncaught — billing audit P0-9.
//
// Sign convention (phase37): usage_deduction rows store amount_cents NEGATIVE; every
// other kind (signup_grant / topup / auto_recharge_topup / refund / adjustment) is
// positive. cost_cents_cog is our cost of goods (positive).

const DAY_MS = 24 * 60 * 60 * 1000;

const n = (v: unknown): number => Number(v ?? 0);

export interface AdminBillingMathInput {
  /** Wall-clock anchor (ms) for the 30-day and 365-day windows. */
  now: number;
  balanceRows: Array<{ organization_id: string; balance_cents: number | null }>;
  grantRows: Array<{ organization_id: string; amount_cents: number | null }>;
  depositRows: Array<{ amount_cents: number | null; created_at: string | null }>;
  refundRows: Array<{ amount_cents: number | null }>;
  usageRows: Array<{
    organization_id: string;
    amount_cents: number | null;
    cost_cents_cog: number | null;
  }>;
}

export interface AdminBillingFinancials {
  depositsCents: number;
  deposits30dCents: number;
  grossMarginCents: number;
  freeCreditBurnedCents: number;
  realBalanceHeldCents: number;
  freeCreditOutstandingCents: number;
}

export interface AdminBillingMath {
  financials: AdminBillingFinancials;
  revenueSeries: Array<{ date: string; cents: number }>;
}

export function computeAdminBillingFinancials(input: AdminBillingMathInput): AdminBillingMath {
  const { now, balanceRows, grantRows, depositRows, refundRows, usageRows } = input;

  // Per-org rollups for the free-credit split.
  const balanceByOrg = new Map<string, number>();
  for (const r of balanceRows) {
    balanceByOrg.set(r.organization_id, (balanceByOrg.get(r.organization_id) ?? 0) + n(r.balance_cents));
  }
  const grantByOrg = new Map<string, number>();
  for (const r of grantRows) {
    grantByOrg.set(r.organization_id, (grantByOrg.get(r.organization_id) ?? 0) + n(r.amount_cents));
  }
  const chargedByOrg = new Map<string, number>();
  const cogsByOrg = new Map<string, number>();
  let chargedTotal = 0;
  let cogsTotal = 0;
  for (const r of usageRows) {
    const charged = -n(r.amount_cents); // usage amounts are negative
    const cogs = n(r.cost_cents_cog);
    chargedByOrg.set(r.organization_id, (chargedByOrg.get(r.organization_id) ?? 0) + charged);
    cogsByOrg.set(r.organization_id, (cogsByOrg.get(r.organization_id) ?? 0) + cogs);
    chargedTotal += charged;
    cogsTotal += cogs;
  }

  // Deposits (net cash in) + 30-day total + 12-month daily series.
  const depositsGross = depositRows.reduce((s, r) => s + n(r.amount_cents), 0);
  const refundsAbs = refundRows.reduce((s, r) => s + Math.abs(n(r.amount_cents)), 0);
  const depositsCents = Math.round(depositsGross - refundsAbs);

  const utcDay = (ms: number) => new Date(ms).toISOString().slice(0, 10);
  const seriesMap = new Map<string, number>();
  // 12-month daily window — the frontend slices it to 7d / 30d / 90d / 12m.
  for (let i = 364; i >= 0; i--) seriesMap.set(utcDay(now - i * DAY_MS), 0);
  const ms30 = now - 30 * DAY_MS;
  let deposits30d = 0;
  for (const r of depositRows) {
    if (!r.created_at) continue;
    const ts = new Date(r.created_at);
    const key = ts.toISOString().slice(0, 10);
    if (seriesMap.has(key)) seriesMap.set(key, (seriesMap.get(key) ?? 0) + n(r.amount_cents));
    if (ts.getTime() >= ms30) deposits30d += n(r.amount_cents);
  }
  const revenueSeries = Array.from(seriesMap, ([date, cents]) => ({ date, cents }));

  // Gross margin across all usage: what we charged minus what it cost us.
  const grossMarginCents = Math.round(chargedTotal - cogsTotal);

  // Free-credit split (free-credit-spent-first estimate).
  let freeCreditBurnedCents = 0;
  let freeCreditOutstandingCents = 0;
  let realBalanceHeldCents = 0;
  const allOrgs = new Set<string>([
    ...balanceByOrg.keys(),
    ...grantByOrg.keys(),
    ...chargedByOrg.keys(),
  ]);
  for (const org of allOrgs) {
    const granted = grantByOrg.get(org) ?? 0;
    const charged = chargedByOrg.get(org) ?? 0;
    const cogs = cogsByOrg.get(org) ?? 0;
    const bal = balanceByOrg.get(org) ?? 0;
    const freeUsed = Math.min(granted, charged);
    freeCreditBurnedCents += charged > 0 ? cogs * (freeUsed / charged) : 0;
    const freeRemaining = Math.max(0, Math.min(bal, granted - charged));
    freeCreditOutstandingCents += freeRemaining;
    realBalanceHeldCents += bal - freeRemaining;
  }

  return {
    financials: {
      depositsCents,
      deposits30dCents: deposits30d,
      grossMarginCents,
      freeCreditBurnedCents: Math.round(freeCreditBurnedCents),
      realBalanceHeldCents: Math.round(realBalanceHeldCents),
      freeCreditOutstandingCents: Math.round(freeCreditOutstandingCents),
    },
    revenueSeries,
  };
}
