/**
 * Phase 25 generated-rules route tests.
 *
 * Covers tenant isolation, permission gating (manage_organization_settings
 * for mutation, view_ai_spending for cost-field visibility), validator reject
 * paths, previous_versions LIFO cap, and the regenerate stage-only semantics.
 */
import request from 'supertest';
import app from '../../index';
import {
  supabase,
  queryBuilder,
  setTableResponse,
  pushTableResponse,
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
const RULE_ID = 'rule-1';
const TOKEN = 'valid-token';
const USER = { id: 'user-1', email: 'a@b.com' };

function setMember(role = 'member') {
  setTableResponse('organization_members', 'single', { data: { role }, error: null });
}

function setNotMember() {
  setTableResponse('organization_members', 'single', { data: null, error: null });
}

function setPerm(perms: Record<string, boolean>, role = 'admin') {
  setTableResponse('organization_members', 'single', { data: { role }, error: null });
  setTableResponse('organization_roles', 'single', { data: { permissions: perms }, error: null });
}

describe('Generated Rules Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: USER }, error: null });
  });

  describe('GET /api/organizations/:id/generated-rules (list)', () => {
    it('returns the list when user is a member; nulls out cost without view_ai_spending', async () => {
      // requireMembership query (single) — second call (hasPermission for view_ai_spending) gets a different table.
      // Mock chain: members→OK, roles→view_ai_spending=false.
      pushTableResponse('organization_members', { data: { id: 'mem-1' }, error: null }); // requireMembership
      pushTableResponse('organization_members', { data: { role: 'member' }, error: null }); // hasPermission member
      setTableResponse('organization_roles', 'single', { data: { permissions: { view_ai_spending: false } }, error: null });
      // Terminal await on the rules query
      setTableResponse('organization_generated_rules', 'then', {
        data: [
          { id: 'r1', cve_id: 'CVE-2024-1', generation_cost_usd: 0.0234, validation_status: 'validated' },
          { id: 'r2', cve_id: 'CVE-2024-2', generation_cost_usd: 0.0102, validation_status: 'validated' },
        ],
        error: null,
        count: 2,
      });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.rules).toHaveLength(2);
      // Members without view_ai_spending must NOT see per-rule cost.
      expect(res.body.rules[0].generation_cost_usd).toBeNull();
      expect(res.body.rules[1].generation_cost_usd).toBeNull();
      // Other fields still visible (CVE id is operational, not financial).
      expect(res.body.rules[0].cve_id).toBe('CVE-2024-1');
    });

    it('preserves generation_cost_usd when user has view_ai_spending', async () => {
      pushTableResponse('organization_members', { data: { id: 'mem-1' }, error: null });
      pushTableResponse('organization_members', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { view_ai_spending: true } }, error: null });
      setTableResponse('organization_generated_rules', 'then', {
        data: [{ id: 'r1', cve_id: 'CVE-2024-1', generation_cost_usd: 0.0234 }],
        error: null,
        count: 1,
      });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.rules[0].generation_cost_usd).toBe(0.0234);
    });

    it('owners see cost without an explicit permission row', async () => {
      pushTableResponse('organization_members', { data: { id: 'mem-1' }, error: null });
      pushTableResponse('organization_members', { data: { role: 'owner' }, error: null });
      setTableResponse('organization_generated_rules', 'then', {
        data: [{ id: 'r1', cve_id: 'CVE-2024-1', generation_cost_usd: 0.05 }],
        error: null,
        count: 1,
      });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.rules[0].generation_cost_usd).toBe(0.05);
    });

    it('returns 403 to non-members', async () => {
      setNotMember();

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });

    it('cross-tenant: non-member of OTHER_ORG_ID is rejected even with valid JWT', async () => {
      setNotMember();

      const res = await request(app)
        .get(`/api/organizations/${OTHER_ORG_ID}/generated-rules`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });

    it('rejects without a JWT', async () => {
      const res = await request(app).get(`/api/organizations/${ORG_ID}/generated-rules`);
      expect(res.status).toBe(401);
    });

    it('returns pagination metadata', async () => {
      pushTableResponse('organization_members', { data: { id: 'mem-1' }, error: null });
      pushTableResponse('organization_members', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { view_ai_spending: true } }, error: null });
      setTableResponse('organization_generated_rules', 'then', {
        data: [],
        error: null,
        count: 137,
      });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules?page=2&per_page=25`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.pagination).toEqual({ page: 2, per_page: 25, total: 137, total_pages: 6 });
    });
  });

  describe('GET /api/organizations/:id/generated-rules/:ruleId (detail)', () => {
    it('masks generation_cost_usd in detail and previous_versions when user lacks view_ai_spending', async () => {
      pushTableResponse('organization_members', { data: { id: 'mem-1' }, error: null });
      pushTableResponse('organization_members', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { view_ai_spending: false } }, error: null });
      setTableResponse('organization_generated_rules', 'maybeSingle', {
        data: {
          id: RULE_ID,
          cve_id: 'CVE-2024-1',
          rule_yaml: 'rules: []',
          generation_cost_usd: 0.0234,
          previous_versions: [
            { generation_cost_usd: 0.012, replaced_at: '2026-04-29T00:00:00Z' },
            { generation_cost_usd: 0.018, replaced_at: '2026-04-28T00:00:00Z' },
          ],
        },
        error: null,
      });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(200);
      expect(res.body.generation_cost_usd).toBeNull();
      expect(res.body.previous_versions).toHaveLength(2);
      expect(res.body.previous_versions[0].generation_cost_usd).toBeNull();
      expect(res.body.previous_versions[1].generation_cost_usd).toBeNull();
      // Non-cost fields preserved.
      expect(res.body.rule_yaml).toBe('rules: []');
      expect(res.body.previous_versions[0].replaced_at).toBe('2026-04-29T00:00:00Z');
    });

    it('returns 404 for a ruleId not in this org (cross-tenant guess)', async () => {
      pushTableResponse('organization_members', { data: { id: 'mem-1' }, error: null });
      pushTableResponse('organization_members', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: { view_ai_spending: true } }, error: null });
      // The composite filter `.eq(organization_id).eq(id)` returns nothing
      // when the rule belongs to a different org — proving the route rejects
      // cross-tenant ruleId guessing without leaking existence.
      setTableResponse('organization_generated_rules', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules/some-other-orgs-rule-id`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(404);
    });

    it('returns 403 to non-members', async () => {
      setNotMember();

      const res = await request(app)
        .get(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });
  });

  describe('PATCH /api/organizations/:id/generated-rules/:ruleId', () => {
    it('returns 403 without manage_organization_settings — view_ai_spending alone is NOT enough', async () => {
      setPerm({ view_ai_spending: true, manage_organization_settings: false });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ enabled: false });

      expect(res.status).toBe(403);
    });

    it('toggles enabled', async () => {
      setPerm({ manage_organization_settings: true });
      setTableResponse('organization_generated_rules', 'maybeSingle', {
        data: { id: RULE_ID, cve_id: 'CVE-2024-1', package_purl: 'pkg:npm/x@1', enabled: true, validation_status: 'validated' },
        error: null,
      });
      setTableResponse('organization_generated_rules', 'single', {
        data: { id: RULE_ID, enabled: false, validation_status: 'validated' },
        error: null,
      });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ enabled: false });

      expect(res.status).toBe(200);
      expect(res.body.enabled).toBe(false);
    });

    it('rejects non-boolean enabled', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ enabled: 'yes-please' });

      expect(res.status).toBe(400);
    });

    it('rejects validation_status set to anything other than manual_override', async () => {
      // Critical: the validation_status enum has 4 values; PATCH must only
      // permit manual_override (the operator-controlled one). Allowing an
      // operator to set 'validated' would let them bypass the actual gate.
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ validation_status: 'validated' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/manual_override/);
    });

    it('returns 404 when rule does not exist for this org', async () => {
      setPerm({ manage_organization_settings: true });
      setTableResponse('organization_generated_rules', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ enabled: false });

      expect(res.status).toBe(404);
    });

    it('rejects empty body', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .patch(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({});

      expect(res.status).toBe(400);
    });
  });

  describe('DELETE /api/organizations/:id/generated-rules/:ruleId', () => {
    it('returns 403 without manage_organization_settings', async () => {
      setPerm({ manage_organization_settings: false });

      const res = await request(app)
        .delete(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(403);
    });

    it('returns 204 on success', async () => {
      setPerm({ manage_organization_settings: true });
      setTableResponse('organization_generated_rules', 'maybeSingle', {
        data: { id: RULE_ID, cve_id: 'CVE-2024-1', package_purl: 'pkg:npm/x@1', generated_with_model: 'm', validation_status: 'validated' },
        error: null,
      });
      setTableResponse('organization_generated_rules', 'then', { data: null, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(204);
    });

    it('returns 404 when rule does not exist for this org', async () => {
      setPerm({ manage_organization_settings: true });
      setTableResponse('organization_generated_rules', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .delete(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}`)
        .set('Authorization', `Bearer ${TOKEN}`);

      expect(res.status).toBe(404);
    });
  });

  describe('POST /api/organizations/:id/generated-rules/:ruleId/regenerate', () => {
    it('returns 403 without manage_organization_settings', async () => {
      setPerm({ manage_organization_settings: false });

      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}/regenerate`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ provider: 'anthropic', model: 'claude-sonnet-4-6' });

      expect(res.status).toBe(403);
    });

    it('rejects unknown provider', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}/regenerate`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ provider: 'fake', model: 'whatever' });

      expect(res.status).toBe(400);
    });

    it('rejects empty model string', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}/regenerate`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ provider: 'anthropic', model: '' });

      expect(res.status).toBe(400);
    });

    it('rejects model > 100 chars', async () => {
      setPerm({ manage_organization_settings: true });

      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}/regenerate`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ provider: 'anthropic', model: 'x'.repeat(101) });

      expect(res.status).toBe(400);
    });

    it('caps previous_versions at 10 (LIFO)', async () => {
      // Existing rule has 10 prior versions; regenerate must push the current
      // state to the head and drop the oldest.
      setPerm({ manage_organization_settings: true });
      const existingPriors = Array.from({ length: 10 }, (_, i) => ({
        rule_yaml: `old-${i}`,
        replaced_at: `2026-04-${20 + i}T00:00:00Z`,
      }));
      setTableResponse('organization_generated_rules', 'maybeSingle', {
        data: {
          id: RULE_ID,
          cve_id: 'CVE-2024-1',
          package_purl: 'pkg:npm/x@1',
          rule_yaml: 'current',
          vulnerable_fixture: 'v',
          safe_fixture: 's',
          generated_with_provider: 'anthropic',
          generated_with_model: 'claude-haiku-4-5-20251001',
          generation_cost_usd: 0.01,
          validation_status: 'validated',
          validation_log: {},
          generated_at: '2026-04-30T00:00:00Z',
          previous_versions: existingPriors,
        },
        error: null,
      });
      // Capture the update payload for assertion.
      let capturedUpdate: any = null;
      const origUpdate = queryBuilder.update;
      queryBuilder.update.mockImplementation(function (this: any, payload: any) {
        capturedUpdate = payload;
        return queryBuilder;
      });
      setTableResponse('organization_generated_rules', 'single', {
        data: { id: RULE_ID, validation_status: 'pending' },
        error: null,
      });

      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}/regenerate`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ provider: 'anthropic', model: 'claude-sonnet-4-6' });

      expect(res.status).toBe(202);
      expect(capturedUpdate).not.toBeNull();
      expect(Array.isArray(capturedUpdate.previous_versions)).toBe(true);
      // 10 prior + 1 new pushed to head, sliced to 10 = 10 total. Newest at index 0.
      expect(capturedUpdate.previous_versions).toHaveLength(10);
      expect(capturedUpdate.previous_versions[0].rule_yaml).toBe('current');
      expect(capturedUpdate.previous_versions[0].replaced_by_user_id).toBe(USER.id);
      // Oldest (`old-9` was at end of existingPriors, so the slice should drop it).
      expect(capturedUpdate.previous_versions[10]).toBeUndefined();
      expect(capturedUpdate.validation_status).toBe('pending');

      queryBuilder.update.mockImplementation(origUpdate);
    });

    it('returns 404 when rule does not exist for this org', async () => {
      setPerm({ manage_organization_settings: true });
      setTableResponse('organization_generated_rules', 'maybeSingle', { data: null, error: null });

      const res = await request(app)
        .post(`/api/organizations/${ORG_ID}/generated-rules/${RULE_ID}/regenerate`)
        .set('Authorization', `Bearer ${TOKEN}`)
        .send({ provider: 'anthropic', model: 'claude-sonnet-4-6' });

      expect(res.status).toBe(404);
    });
  });
});
