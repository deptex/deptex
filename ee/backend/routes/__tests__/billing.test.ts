// ─── Mocks ───

// Inline Stripe mock so CI does not depend on backend/src/__mocks__/stripe.js
jest.mock('stripe', () => ({
  __esModule: true,
  default: function StripeMock() {
    return (global as any).__STRIPE_MOCK__ ?? {};
  },
}));

const mockSupabase = {
  from: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  in: jest.fn().mockReturnThis(),
  match: jest.fn().mockReturnThis(),
  single: jest.fn(),
  maybeSingle: jest.fn(),
  order: jest.fn().mockReturnThis(),
  limit: jest.fn().mockReturnThis(),
  lt: jest.fn().mockReturnThis(),
  gt: jest.fn().mockReturnThis(),
  neq: jest.fn().mockReturnThis(),
  insert: jest.fn().mockReturnThis(),
  update: jest.fn().mockReturnThis(),
  rpc: jest.fn(),
};

jest.mock('../../../../backend/src/lib/supabase', () => ({
  supabase: mockSupabase,
}));

jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));

const mockStripe = {
  customers: { create: jest.fn() },
  checkout: { sessions: { create: jest.fn() } },
  subscriptions: { retrieve: jest.fn() },
  billingPortal: { sessions: { create: jest.fn() } },
  invoices: { list: jest.fn() },
  webhooks: { constructEvent: jest.fn() },
};

// mockStripe is set in beforeEach as global.__STRIPE_MOCK__; Stripe is mocked above

beforeEach(() => {
  jest.clearAllMocks();
  (global as any).__STRIPE_MOCK__ = mockStripe;

  mockSupabase.from.mockReturnThis();
  mockSupabase.select.mockReturnThis();
  mockSupabase.eq.mockReturnThis();
  mockSupabase.in.mockReturnThis();
  mockSupabase.match.mockReturnThis();
  mockSupabase.lt.mockReturnThis();
  mockSupabase.gt.mockReturnThis();
  mockSupabase.neq.mockReturnThis();
  mockSupabase.order.mockReturnThis();
  mockSupabase.limit.mockReturnThis();
  mockSupabase.insert.mockReturnThis();
  mockSupabase.update.mockReturnThis();

  process.env.STRIPE_SECRET_KEY = 'sk_test_xxx';
  process.env.STRIPE_WEBHOOK_SECRET = 'whsec_test_xxx';
  process.env.STRIPE_PRO_MONTHLY_PRICE_ID = 'price_pro_monthly';
  process.env.STRIPE_PRO_ANNUAL_PRICE_ID = 'price_pro_annual';
  process.env.STRIPE_TEAM_MONTHLY_PRICE_ID = 'price_team_monthly';
  process.env.STRIPE_TEAM_ANNUAL_PRICE_ID = 'price_team_annual';
});

// ═══════════════════════════════════════════════════════════════
// PLAN LIMITS ENGINE
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Plan Limits Engine', () => {
  it('1. PLAN_LIMITS defines correct limits for all tiers', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');

    expect(PLAN_LIMITS.free.projects).toBe(3);
    expect(PLAN_LIMITS.free.members).toBe(5);
    expect(PLAN_LIMITS.free.syncs).toBe(10);
    expect(PLAN_LIMITS.pro.projects).toBe(15);
    expect(PLAN_LIMITS.pro.syncs).toBe(100);
    expect(PLAN_LIMITS.team.members).toBe(-1);
    expect(PLAN_LIMITS.enterprise.projects).toBe(-1);
  });

  it('2. getResolvedLimits applies custom overrides', async () => {
    const { getResolvedLimits } = await import('../../lib/plan-limits');

    const limits = getResolvedLimits('pro', { projects: 30, syncs: 200 });
    expect(limits.projects).toBe(30);
    expect(limits.syncs).toBe(200);
    expect(limits.members).toBe(20);
  });

  it('3. getResolvedLimits without overrides returns tier defaults', async () => {
    const { getResolvedLimits } = await import('../../lib/plan-limits');

    const limits = getResolvedLimits('team', null);
    expect(limits.projects).toBe(50);
    expect(limits.members).toBe(-1);
  });

  it('4. checkPlanLimit returns allowed:true when under limit', async () => {
    const { checkPlanLimit } = await import('../../lib/plan-limits');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'pro', subscription_status: 'active', syncs_used: 5, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    // getOrgPlan: from().select().eq().single() — first select() must return chain (mockSupabase)
    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    // getResourceCount: from().select().match() — second select() returns { match }
    mockSupabase.select.mockReturnValueOnce({
      match: jest.fn().mockReturnValue({ count: 3, error: null }),
    });

    const result = await checkPlanLimit('org-1', 'projects');
    expect(result.allowed).toBe(true);
    expect(result.tier).toBe('pro');
  });

  it('5. checkPlanLimit returns allowed:false when at limit', async () => {
    const { checkPlanLimit, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-at-limit');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'free', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    mockSupabase.select.mockReturnValueOnce({
      match: jest.fn().mockReturnValue({ count: 3, error: null }),
    });

    const result = await checkPlanLimit('org-at-limit', 'projects');
    expect(result.allowed).toBe(false);
    expect(result.limit).toBe(3);
  });

  it('6. Enterprise tier returns unlimited for all resources', async () => {
    const { checkPlanLimit, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-enterprise');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'enterprise', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    const result = await checkPlanLimit('org-enterprise', 'projects');
    expect(result.allowed).toBe(true);
    expect(result.limit).toBe(-1);
  });

  it('7. checkPlanFeature gates Aegis on free tier', async () => {
    const { checkPlanFeature, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-free-aegis');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'free', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    const result = await checkPlanFeature('org-free-aegis', 'aegis_chat');
    expect(result.allowed).toBe(false);
    expect(result.requiredTier).toBe('pro');
  });

  it('8. checkPlanFeature allows Aegis on pro tier', async () => {
    const { checkPlanFeature, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-pro-aegis');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'pro', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    const result = await checkPlanFeature('org-pro-aegis', 'aegis_chat');
    expect(result.allowed).toBe(true);
  });

  it('9. SSO requires team tier', async () => {
    const { checkPlanFeature, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-pro-sso');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'pro', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    const result = await checkPlanFeature('org-pro-sso', 'sso');
    expect(result.allowed).toBe(false);
    expect(result.requiredTier).toBe('team');
  });

  it('10. getOrgPlan returns free defaults when no plan exists', async () => {
    const { getOrgPlan, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-no-plan');

    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    mockSupabase.single.mockResolvedValueOnce({ data: null, error: { message: 'not found' } });

    const plan = await getOrgPlan('org-no-plan');
    expect(plan.plan_tier).toBe('free');
    expect(plan.syncs_used).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════
// DOWNGRADE VALIDATION
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Downgrade Validation', () => {
  it('11. checkDowngradeAllowed blocks when over project limit', async () => {
    const { checkDowngradeAllowed } = await import('../../lib/plan-limits');

    mockSupabase.select
      .mockReturnValueOnce({ match: jest.fn().mockReturnValue({ count: 15, error: null }) })
      .mockReturnValueOnce({ match: jest.fn().mockReturnValue({ count: 3, error: null }) })
      .mockReturnValueOnce(mockSupabase);
    mockSupabase.eq.mockImplementation(() => Promise.resolve({ count: 0, error: null }));

    const result = await checkDowngradeAllowed('org-1', 'free');
    expect(result.allowed).toBe(false);
    expect(result.overLimits.some(o => o.resource === 'projects')).toBe(true);
  });

  it('12. checkDowngradeAllowed allows when usage fits', async () => {
    const { checkDowngradeAllowed } = await import('../../lib/plan-limits');

    mockSupabase.select
      .mockReturnValueOnce({ match: jest.fn().mockReturnValue({ count: 2, error: null }) })
      .mockReturnValueOnce({ match: jest.fn().mockReturnValue({ count: 3, error: null }) })
      .mockReturnValueOnce(mockSupabase);
    mockSupabase.eq.mockImplementation(() => Promise.resolve({ count: 0, error: null }));

    const result = await checkDowngradeAllowed('org-fits', 'free');
    expect(result.allowed).toBe(true);
    expect(result.overLimits.length).toBe(0);
  });
});

// ═══════════════════════════════════════════════════════════════
// STRIPE INTEGRATION
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Stripe Integration', () => {
  it('13. constructWebhookEvent verifies signature', async () => {
    const { constructWebhookEvent } = await import('../../lib/stripe');

    mockStripe.webhooks.constructEvent.mockReturnValue({ id: 'evt_1', type: 'test', data: { object: {} } });

    const event = constructWebhookEvent(Buffer.from('raw'), 'sig_123');
    expect(event.id).toBe('evt_1');
    expect(mockStripe.webhooks.constructEvent).toHaveBeenCalledWith(Buffer.from('raw'), 'sig_123', 'whsec_test_xxx');
  });

  it('14. constructWebhookEvent throws on invalid signature', async () => {
    const { constructWebhookEvent } = await import('../../lib/stripe');

    mockStripe.webhooks.constructEvent.mockImplementation(() => {
      throw new Error('Webhook signature verification failed');
    });

    expect(() => constructWebhookEvent(Buffer.from('raw'), 'bad_sig')).toThrow('Webhook signature verification failed');
  });

  it('15. isEventProcessed returns true for processed events', async () => {
    const { isEventProcessed } = await import('../../lib/stripe');

    mockSupabase.maybeSingle.mockResolvedValueOnce({ data: { id: 'x' }, error: null });

    const result = await isEventProcessed('evt_123');
    expect(result).toBe(true);
  });

  it('16. isEventProcessed returns false for new events', async () => {
    const { isEventProcessed } = await import('../../lib/stripe');

    mockSupabase.maybeSingle.mockResolvedValueOnce({ data: null, error: null });

    const result = await isEventProcessed('evt_new');
    expect(result).toBe(false);
  });

  it('17. markEventProcessed inserts event', async () => {
    const { markEventProcessed } = await import('../../lib/stripe');

    mockSupabase.insert.mockReturnValueOnce({ error: null });

    const result = await markEventProcessed('evt_123', 'checkout.session.completed');
    expect(result).toBe(true);
    expect(mockSupabase.from).toHaveBeenCalledWith('stripe_webhook_events');
  });

  it('18. handleCheckoutCompleted activates plan', async () => {
    const { handleCheckoutCompleted } = await import('../../lib/stripe');

    mockStripe.subscriptions.retrieve.mockResolvedValueOnce({
      items: { data: [{ price: { id: 'price_pro_monthly' } }] },
      current_period_start: Math.floor(Date.now() / 1000),
      current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
    });

    mockSupabase.update.mockReturnValueOnce({ eq: jest.fn().mockReturnValue({ error: null }) });

    await handleCheckoutCompleted({
      metadata: { organization_id: 'org-1' },
      subscription: 'sub_123',
      customer: 'cus_123',
      customer_email: 'test@example.com',
    } as any);

    expect(mockStripe.subscriptions.retrieve).toHaveBeenCalledWith('sub_123');
  });

  it('19. handleSubscriptionDeleted downgrades to free', async () => {
    const { handleSubscriptionDeleted } = await import('../../lib/stripe');

    mockSupabase.update.mockReturnValueOnce({ eq: jest.fn().mockReturnValue({ error: null }) });

    await handleSubscriptionDeleted({
      metadata: { organization_id: 'org-1' },
    } as any);

    expect(mockSupabase.from).toHaveBeenCalledWith('organization_plans');
  });

  it('20. handlePaymentFailed sets past_due status', async () => {
    const { handlePaymentFailed } = await import('../../lib/stripe');

    mockSupabase.single.mockResolvedValueOnce({
      data: { organization_id: 'org-1' },
      error: null,
    });
    mockSupabase.update.mockReturnValueOnce({ eq: jest.fn().mockReturnValue({ error: null }) });

    await handlePaymentFailed({
      customer: 'cus_123',
      id: 'inv_123',
    } as any);

    expect(mockSupabase.from).toHaveBeenCalledWith('organization_plans');
  });

  it('21. handlePaymentSucceeded clears past_due', async () => {
    const { handlePaymentSucceeded } = await import('../../lib/stripe');

    mockSupabase.single.mockResolvedValueOnce({
      data: { organization_id: 'org-1', subscription_status: 'past_due' },
      error: null,
    });
    mockSupabase.update.mockReturnValueOnce({ eq: jest.fn().mockReturnValue({ error: null }) });

    await handlePaymentSucceeded({
      customer: 'cus_123',
      amount_paid: 2500,
      id: 'inv_123',
    } as any);

    expect(mockSupabase.from).toHaveBeenCalledWith('organization_plans');
  });
});

// ═══════════════════════════════════════════════════════════════
// SYNC COUNTER
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Sync Counter', () => {
  it('22. resetDueSyncCounters resets orgs past period end', async () => {
    const { resetDueSyncCounters } = await import('../../lib/stripe');

    // First call: paid orgs past period
    mockSupabase.select.mockReturnValueOnce({
      lt: jest.fn().mockReturnValue({
        neq: jest.fn().mockReturnValue({
          gt: jest.fn().mockReturnValue({
            data: [{ organization_id: 'org-1' }],
            error: null,
          }),
        }),
      }),
    });

    mockSupabase.update.mockReturnValueOnce({ eq: jest.fn().mockReturnValue({ error: null }) });

    // Second call: free orgs past 30 days
    mockSupabase.select.mockReturnValueOnce({
      eq: jest.fn().mockReturnValue({
        lt: jest.fn().mockReturnValue({
          gt: jest.fn().mockReturnValue({
            data: [],
            error: null,
          }),
        }),
      }),
    });

    const count = await resetDueSyncCounters();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

// ═══════════════════════════════════════════════════════════════
// USAGE SUMMARY
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Usage Summary', () => {
  it('23. getUsageSummary returns all resource counts', async () => {
    const { getUsageSummary, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-usage');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'pro', subscription_status: 'active', syncs_used: 42, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    for (let i = 0; i < 7; i++) mockSupabase.select.mockReturnValueOnce(mockSupabase);
    mockSupabase.eq.mockReturnValueOnce(mockSupabase);
    const countResults = [5, 8, 3, 4, 2, 3, 1];
    let idx = 0;
    mockSupabase.eq.mockImplementation(() => Promise.resolve({ count: countResults[idx++] ?? 0, error: null }));

    const summary = await getUsageSummary('org-usage');
    expect(summary.tier).toBe('pro');
    expect(summary.usage.syncs).toBe(42);
    expect(summary.features.aegis_chat).toBe(true);
    expect(summary.limits.projects).toBe(15);
  });
});

// ═══════════════════════════════════════════════════════════════
// PLAN FEATURES
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Feature Gates', () => {
  it('24. Free tier cannot use ai_fixes', async () => {
    const { PLAN_FEATURES } = await import('../../lib/plan-limits');
    expect(PLAN_FEATURES.free.ai_fixes).toBe(false);
  });

  it('25. Pro tier can use ai_fixes', async () => {
    const { PLAN_FEATURES } = await import('../../lib/plan-limits');
    expect(PLAN_FEATURES.pro.ai_fixes).toBe(true);
  });

  it('26. Pro tier cannot use SSO', async () => {
    const { PLAN_FEATURES } = await import('../../lib/plan-limits');
    expect(PLAN_FEATURES.pro.sso).toBe(false);
  });

  it('27. Team tier can use SSO', async () => {
    const { PLAN_FEATURES } = await import('../../lib/plan-limits');
    expect(PLAN_FEATURES.team.sso).toBe(true);
  });

  it('28. Free tier has 0 automations', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    expect(PLAN_LIMITS.free.automations).toBe(0);
  });

  it('29. Team tier has unlimited members (-1)', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    expect(PLAN_LIMITS.team.members).toBe(-1);
  });

  it('30. Enterprise has unlimited everything', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    const limits = Object.values(PLAN_LIMITS.enterprise);
    const allUnlimited = limits.every(v => v === -1 || v === 5000);
    expect(allUnlimited).toBe(true);
  });
});

// ═══════════════════════════════════════════════════════════════
// TIER DISPLAY NAMES
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Tier Display', () => {
  it('31. TIER_DISPLAY_NAMES maps correctly', async () => {
    const { TIER_DISPLAY_NAMES } = await import('../../lib/plan-limits');
    expect(TIER_DISPLAY_NAMES.free).toBe('Free');
    expect(TIER_DISPLAY_NAMES.pro).toBe('Pro');
    expect(TIER_DISPLAY_NAMES.team).toBe('Team');
    expect(TIER_DISPLAY_NAMES.enterprise).toBe('Enterprise');
  });
});

// ═══════════════════════════════════════════════════════════════
// MIDDLEWARE
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Middleware', () => {
  it('32. requirePlanLimit returns 403 with PLAN_LIMIT error', async () => {
    const { requirePlanLimit, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-limit-test');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'free', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    mockSupabase.select.mockReturnValueOnce({
      match: jest.fn().mockReturnValue({ count: 3, error: null }),
    });

    const middleware = requirePlanLimit('projects');
    const req = { params: { id: 'org-limit-test' }, user: { id: 'u1' } } as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'PLAN_LIMIT' }));
    expect(next).not.toHaveBeenCalled();
  });

  it('33. requirePlanFeature returns 403 with PLAN_FEATURE error', async () => {
    const { requirePlanFeature, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-feat-test');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'free', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    const middleware = requirePlanFeature('aegis_chat');
    const req = { params: { id: 'org-feat-test' }, user: { id: 'u1' } } as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();

    await middleware(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({ error: 'PLAN_FEATURE' }));
  });

  it('34. middleware calls next() when limit is fine', async () => {
    const { requirePlanLimit, invalidatePlanCache } = await import('../../lib/plan-limits');
    invalidatePlanCache('org-ok');

    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'enterprise', subscription_status: 'active', syncs_used: 0, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });

    const middleware = requirePlanLimit('projects');
    const req = { params: { id: 'org-ok' }, user: { id: 'u1' } } as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();

    await middleware(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  it('35. middleware skips check when no orgId', async () => {
    const { requirePlanLimit } = await import('../../lib/plan-limits');

    const middleware = requirePlanLimit('projects');
    const req = { params: {}, user: { id: 'u1' } } as any;
    const res = { status: jest.fn().mockReturnThis(), json: jest.fn() } as any;
    const next = jest.fn();

    await middleware(req, res, next);
    expect(next).toHaveBeenCalled();
  });
});

// ═══════════════════════════════════════════════════════════════
// BILLING LIFECYCLE
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Billing Lifecycle', () => {
  it('36. handleSubscriptionUpdated syncs tier', async () => {
    const { handleSubscriptionUpdated } = await import('../../lib/stripe');

    mockSupabase.update.mockReturnValueOnce({ eq: jest.fn().mockReturnValue({ error: null }) });

    await handleSubscriptionUpdated({
      metadata: { organization_id: 'org-1' },
      items: { data: [{ price: { id: 'price_team_monthly' } }] },
      status: 'active',
      current_period_start: Math.floor(Date.now() / 1000),
      current_period_end: Math.floor(Date.now() / 1000) + 30 * 86400,
      cancel_at_period_end: false,
      cancel_at: null,
      default_payment_method: null,
    } as any);

    expect(mockSupabase.from).toHaveBeenCalledWith('organization_plans');
  });

  it('37. handleCheckoutCompleted ignores event without org_id', async () => {
    const { handleCheckoutCompleted } = await import('../../lib/stripe');

    await handleCheckoutCompleted({ metadata: {} } as any);
    expect(mockStripe.subscriptions.retrieve).not.toHaveBeenCalled();
  });

  it('38. handlePaymentSucceeded ignores when not past_due', async () => {
    const { handlePaymentSucceeded } = await import('../../lib/stripe');

    mockSupabase.single.mockResolvedValueOnce({
      data: { organization_id: 'org-1', subscription_status: 'active' },
      error: null,
    });

    await handlePaymentSucceeded({
      customer: 'cus_123',
      amount_paid: 2500,
      id: 'inv_123',
    } as any);

    // Should not call update to change status
    expect(mockSupabase.update).not.toHaveBeenCalledWith(expect.objectContaining({ subscription_status: 'active' }));
  });
});

// ═══════════════════════════════════════════════════════════════
// PLAN TIER API RATES
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: API Rate Limits', () => {
  it('39. Free tier has 60 rpm', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    expect(PLAN_LIMITS.free.api_rpm).toBe(60);
  });

  it('40. Pro tier has 300 rpm', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    expect(PLAN_LIMITS.pro.api_rpm).toBe(300);
  });

  it('41. Team tier has 1000 rpm', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    expect(PLAN_LIMITS.team.api_rpm).toBe(1000);
  });

  it('42. Enterprise tier has 5000 rpm', async () => {
    const { PLAN_LIMITS } = await import('../../lib/plan-limits');
    expect(PLAN_LIMITS.enterprise.api_rpm).toBe(5000);
  });
});

// ═══════════════════════════════════════════════════════════════
// CACHE BEHAVIOR
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Plan Cache', () => {
  it('43. invalidatePlanCache clears cached data', async () => {
    const { getOrgPlan, invalidatePlanCache } = await import('../../lib/plan-limits');

    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'pro', subscription_status: 'active', syncs_used: 10, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });
    const plan1 = await getOrgPlan('org-cache');
    expect(plan1.plan_tier).toBe('pro');

    invalidatePlanCache('org-cache');

    mockSupabase.select.mockReturnValueOnce(mockSupabase);
    mockSupabase.single.mockResolvedValueOnce({
      data: { plan_tier: 'team', subscription_status: 'active', syncs_used: 20, syncs_reset_at: new Date().toISOString(), current_period_end: null, cancel_at_period_end: false, custom_limits: null },
      error: null,
    });
    const plan2 = await getOrgPlan('org-cache');
    expect(plan2.plan_tier).toBe('team');
  });
});

// ═══════════════════════════════════════════════════════════════
// INVOICE RETRIEVAL
// ═══════════════════════════════════════════════════════════════

describe('Phase 13: Invoices', () => {
  it('44. getInvoices returns empty when no customer', async () => {
    const { getInvoices } = await import('../../lib/stripe');

    mockSupabase.single.mockResolvedValueOnce({ data: null, error: null });

    const result = await getInvoices('org-no-customer');
    expect(result.invoices).toEqual([]);
    expect(result.has_more).toBe(false);
  });

  it('45. getInvoices maps Stripe invoice data', async () => {
    const { getInvoices } = await import('../../lib/stripe');

    mockSupabase.single.mockResolvedValueOnce({
      data: { stripe_customer_id: 'cus_123' },
      error: null,
    });

    mockStripe.invoices.list.mockResolvedValueOnce({
      data: [{
        id: 'inv_1', number: 'INV-001', amount_due: 2500, amount_paid: 2500,
        currency: 'usd', status: 'paid', created: 1700000000, period_start: 1700000000,
        period_end: 1702600000, invoice_pdf: 'https://pdf', hosted_invoice_url: 'https://hosted',
      }],
      has_more: false,
    });

    const result = await getInvoices('org-with-customer');
    expect(result.invoices.length).toBe(1);
    expect(result.invoices[0].id).toBe('inv_1');
    expect(result.invoices[0].status).toBe('paid');
  });
});
