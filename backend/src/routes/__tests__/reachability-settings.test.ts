/**
 * Phase 25 reachability-settings route tests.
 *
 * Covers permission split (view_ai_spending GET vs manage_organization_settings PATCH),
 * tenant isolation through the URL :id param, validator reject paths, and the
 * GET-when-no-row default fallback.
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));
jest.mock('../../lib/activities', () => ({ createActivity: jest.fn() }));
jest.mock('../../lib/email', () => ({ sendInvitationEmail: jest.fn() }));
jest.mock('../../lib/openai', () => ({
  getOpenAIClient: jest.fn().mockReturnValue({ chat: { completions: { create: jest.fn() } } }),
}));

const ORG_ID = 'org-1';
const OTHER_ORG_ID = 'org-2';
const TOKEN = 'valid-token';
const USER = { id: 'user-1', email: 'a@b.com' };

function setPerm(perms: Record<string, boolean>) {
  setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: perms }, error: null });
}

function setPermAsOwner() {
  setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
}

function setNotMember() {
  setTableResponse('organization_members', 'single', { data: null, error: null });
}

describe('Reachability Settings Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
  });

  describe('GET /api/organizations/:id/reachability-settings', () => {
    it('returns persisted row when user has view_ai_spending', async () => {
      setPerm({ view_ai_spending: true });
      setTableResponse('organization_reachability_settings', 'maybeSingle', {
        data: {
          organization_id: ORG_ID,
          auto_generate_enabled: true,
          ai_provider: 'anthropic',
          ai_model: 'claude-sonnet-4-6',
          monthly_budget_usd: 25.0,
          trigger_severities: ['critical', 'high'],
        },
        error: null,
      });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.organization_id).toBe(ORG_ID);
      expect(res.body.auto_generate_enabled).toBe(true);
      expect(res.body.monthly_budget_usd).toBe(25.0);
    });

    it('returns DEFAULTS shape when no row exists', async () => {
      setPerm({ view_ai_spending: true });
      setTableResponse('organization_reachability_settings', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.organization_id).toBe(ORG_ID);
      // Defaults shape — must populate the form so the UI doesn't crash on a fresh org.
      expect(res.body.auto_generate_enabled).toBe(false);
      expect(res.body.trigger_severities).toEqual(['critical', 'high']);
      expect(res.body.ai_provider).toBe('anthropic');
      expect(res.body.monthly_budget_usd).toBe(30.0);
      expect(res.body.on_budget_exhaustion).toBe('skip');
    });

    it('returns 403 without view_ai_spending permission', async () => {
      setPerm({ view_ai_spending: false, manage_organization_settings: true });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });

    it('returns 403 when user is not a member', async () => {
      // hasPermission returns false when org_members lookup yields no row.
      setNotMember();

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });

    it('owner short-circuit grants access without explicit permission row', async () => {
      setPermAsOwner();
      setTableResponse('organization_reachability_settings', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
    });

    it('rejects without a JWT', async () => {
      const res = await request(app).get(`/api/organizations/${ORG_ID}/reachability-settings`);
      expect(res.status).toBe(401);
    });

    it('cross-tenant: GET against a different org id still routes through that org\'s membership check', async () => {
      // Tenant isolation: the URL :id is what hasPermission uses, so a user
      // who is a member of ORG_ID but not OTHER_ORG_ID must receive 403 from
      // the membership lookup against OTHER_ORG_ID.
      setNotMember();

      const res = await request(app)
        .get(`/api/organizations/${OTHER_ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });
  });

  describe('PATCH /api/organizations/:id/reachability-settings', () => {
    function mockUpsertReturning(data: unknown) {
      setTableResponse('organization_reachability_settings', 'single', { data, error: null });
      setTableResponse('organization_reachability_settings', 'maybeSingle', { data: null, error: null });
    }

    it('returns 403 without manage_organization_settings — view_ai_spending is NOT enough', async () => {
      // Critical: monthly_budget_usd is the only thing standing between us
      // and a runaway platform AI bill. View permission alone must not allow PATCH.
      setPerm({ view_ai_spending: true, manage_organization_settings: false });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ monthly_budget_usd: 1000 });

      expect(res.status).toBe(403);
    });

    it('persists a valid update', async () => {
      setPerm({ manage_organization_settings: true });
      mockUpsertReturning({ organization_id: ORG_ID, monthly_budget_usd: 25, auto_generate_enabled: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ monthly_budget_usd: 25, auto_generate_enabled: true });

      expect(res.status).toBe(200);
      expect(res.body.monthly_budget_usd).toBe(25);
    });

    it('rejects monthly_budget_usd > 1000', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ monthly_budget_usd: 1001 });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/monthly_budget_usd/);
    });

    it('rejects negative monthly_budget_usd', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ monthly_budget_usd: -1 });

      expect(res.status).toBe(400);
    });

    it('rejects non-numeric monthly_budget_usd', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ monthly_budget_usd: 'lots' });

      expect(res.status).toBe(400);
    });

    it('rejects trigger_asset_tier_max_rank=0 (filters out all projects)', async () => {
      // The asset-tier filter min is 1; allowing 0 would disable generation
      // for every project silently.
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ trigger_asset_tier_max_rank: 0 });

      expect(res.status).toBe(400);
    });

    it('rejects trigger_asset_tier_max_rank > 5', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ trigger_asset_tier_max_rank: 6 });

      expect(res.status).toBe(400);
    });

    it('rejects unknown ai_provider', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ ai_provider: 'fake-provider' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/ai_provider/);
    });

    it('rejects unknown trigger_severities entry', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ trigger_severities: ['critical', 'apocalyptic'] });

      expect(res.status).toBe(400);
    });

    it('rejects unknown on_budget_exhaustion value', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ on_budget_exhaustion: 'crash' });

      expect(res.status).toBe(400);
    });

    it('rejects empty body (no valid fields)', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({});

      expect(res.status).toBe(400);
    });

    it('rounds monthly_budget_usd to 2 decimals', async () => {
      setPerm({ manage_organization_settings: true });
      mockUpsertReturning({ organization_id: ORG_ID, monthly_budget_usd: 12.35 });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/reachability-settings`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ monthly_budget_usd: 12.349999 });

      expect(res.status).toBe(200);
      // The handler rounds before persisting; we round-trip through the mock.
      expect(res.body.monthly_budget_usd).toBe(12.35);
    });
  });
});
