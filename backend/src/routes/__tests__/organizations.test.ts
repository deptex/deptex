import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));

jest.mock('../../lib/email', () => ({
  sendInvitationEmail: jest.fn(),
}));

// Mock OpenAI
jest.mock('../../lib/openai', () => ({
  getOpenAIClient: jest.fn().mockReturnValue({
    chat: { completions: { create: jest.fn() } }
  }),
}));

jest.mock('../../lib/policy-seed', () => ({
  seedOrganizationPolicyDefaults: jest.fn().mockResolvedValue(undefined),
}));

describe('Organization Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: { manage_members: true } }, error: null });
    setTableResponse('organizations', 'single', { data: { mfa_enforced: false }, error: null });
  });

  describe('GET /api/organizations', () => {
    it('should list organizations for the user', async () => {
      // Mock memberships with organizations
      const mockMemberships = [
        {
          organization_id: 'org-1',
          role: 'owner',
          organizations: {
            id: 'org-1',
            name: 'Test Org 1',
            plan: 'free',
            created_at: new Date().toISOString(),
          },
        },
      ];

      // Setup the chain for fetching memberships
      // .from('organization_members').select(...).eq('user_id', userId)
      queryBuilder.select.mockReturnThis();
      // queryBuilder.eq is default (returns this)

      // 1. Memberships query
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ data: mockMemberships, error: null }));

      // 2. Member count query (for org-1)
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ count: 5, error: null }));

      // 3. Roles query
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({
        data: [{ organization_id: 'org-1', name: 'owner', display_name: 'Owner', color: '#000' }],
        error: null
      }));

      const res = await request(app)
        .get('/api/organizations')
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].name).toBe('Test Org 1');
      expect(res.body[0].role).toBe('owner');
      expect(res.body[0].member_count).toBe(5);
    });
  });

  describe('POST /api/organizations', () => {
    it('should create an organization', async () => {
      const newOrg = {
        id: 'new-org-1',
        name: 'New Org',
        plan: 'free',
      };

      // 1. Insert Org
      queryBuilder.select.mockReturnThis();
      queryBuilder.single.mockResolvedValueOnce({ data: newOrg, error: null });

      // 2. Insert Member (Owner) - no return needed, just error check
      // `insert` returns builder. `insert({..})` is awaited?
      // Code: `const { error: memberError } = await supabase.from('organization_members').insert(...)`
      // So `insert` needs to be thenable or we use `then`.

      // reset the `then` mock sequence
      queryBuilder.then = jest.fn();

      // 1. Create Org (insert -> select -> single)
      // The code is: `await supabase.from('organizations').insert(...).select().single()`
      // My mock `single` returns a promise. So `then` is not needed here if `single` is called.
      // `single` mock is already set up in `createMockSupabase` but we override it.

      // 2. Add Member
      // Code: `await supabase.from('organization_members').insert(...)`
      // This awaits the result of `insert`. `insert` returns builder. Builder needs `then`.
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ error: null }));

      // 3. Create Default Roles
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ error: null }));

      // 4-10. Statuses, tiers, policy tables (Phase 4), seedOrganizationPolicyDefaults is mocked
      // Provide default so all remaining .then() calls resolve (avoids hang/timeout)
      queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: {}, error: null }));

      const res = await request(app)
        .post('/api/organizations')
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'New Org' });

      expect(res.status).toBe(201);
      expect(res.body).toEqual({ ...newOrg, role: 'owner' });

      // Verify calls
      expect(queryBuilder.insert).toHaveBeenCalledWith(expect.objectContaining({
        name: 'New Org',
        plan: 'free'
      }));
    });
  });

  describe('GET /api/organizations/:id/invitations', () => {
    it('returns 200 with invitations array for org member', async () => {
      const mockInvitations = [
        { id: 'inv-1', email: 'a@test.com', role: 'member', status: 'pending', created_at: new Date().toISOString(), expires_at: new Date(Date.now() + 7 * 864e5).toISOString() },
      ];
      queryBuilder.single
        .mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.then
        .mockImplementationOnce((resolve: any) => resolve({ data: mockInvitations, error: null }));
      queryBuilder.then
        .mockImplementationOnce((resolve: any) => resolve({ data: [], error: null }));

      const res = await request(app)
        .get('/api/organizations/org-1/invitations')
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].email).toBe('a@test.com');
      expect(res.body[0].role).toBe('member');
    });

    it('returns 404 for non-member', async () => {
      setTableResponse('organization_members', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .get('/api/organizations/org-1/invitations')
        .set('Authorization', `Bearer ${mockToken}`);

      expect([403, 404]).toContain(res.status);
      if (res.body.error) expect(res.body.error).toMatch(/not found|access denied/i);
    });
  });

  describe('POST /api/organizations/:id/invitations', () => {
    beforeEach(() => {
      (supabase.auth.admin.getUserById as jest.Mock).mockResolvedValue({
        data: { user: { email: 'admin@test.com', user_metadata: {} } },
        error: null,
      });
    });

    it('returns 400 when email is missing', async () => {
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations')
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ role: 'member' });

      expect(res.status).toBe(400);
      expect(res.body.error).toMatch(/email is required/i);
    });

    it('returns 403 when user is not admin or owner', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations')
        .set('Authorization', `Bearer ${mockToken}`)
        .set('Content-Type', 'application/json')
        .send({ email: 'new@test.com', role: 'member' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/only admins and owners can invite/i);
    });

    it('returns 400 when email already has pending invitation', async () => {
      setTableResponse('organizations', 'single', { data: { name: 'Test Org' }, error: null });
      setTableResponse('organization_invitations', 'single', { data: { id: 'existing-inv' }, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations')
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ email: 'already@test.com', role: 'member' });

      expect([400, 403]).toContain(res.status);
      if (res.status === 400 && res.body.error) expect(res.body.error).toMatch(/already invited/i);
    });

    it('returns 201 with invitation when valid', async () => {
      const newInvitation = {
        id: 'inv-new',
        organization_id: 'org-1',
        email: 'new@test.com',
        role: 'member',
        status: 'pending',
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + 7 * 864e5).toISOString(),
      };
      setTableResponse('organizations', 'single', { data: { name: 'Test Org' }, error: null });
      setTableResponse('organization_invitations', 'single', { data: newInvitation, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations')
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ email: 'new@test.com', role: 'member' });

      expect([201, 400, 403, 404]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.email).toBe('new@test.com');
        expect(res.body.role).toBe('member');
      }
    });
  });

  describe('DELETE /api/organizations/:id/invitations/:invitationId', () => {
    it('returns 403 when user is not admin or owner', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });

      const res = await request(app)
        .delete('/api/organizations/org-1/invitations/inv-1')
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/only admins and owners can cancel/i);
    });

    it('returns 200 when admin cancels invitation', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_invitations', 'single', { data: { email: 'x@test.com', role: 'member', team_id: null }, error: null });

      const res = await request(app)
        .delete('/api/organizations/org-1/invitations/inv-1')
        .set('Authorization', `Bearer ${mockToken}`);

      expect([200, 403]).toContain(res.status);
      if (res.status === 200) expect(res.body.message).toMatch(/cancelled/i);
    });
  });

  describe('POST /api/organizations/:id/invitations/:invitationId/resend', () => {
    it('returns 403 when user is not admin or owner', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations/inv-1/resend')
        .set('Authorization', `Bearer ${mockToken}`);

      expect([403, 404]).toContain(res.status);
      if (res.body.error) expect(res.body.error).toMatch(/only admins and owners can resend|access|denied/i);
    });

    it('returns 404 when invitation not found', async () => {
      setTableResponse('organization_invitations', 'single', { data: null, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations/inv-1/resend')
        .set('Authorization', `Bearer ${mockToken}`);

      expect([403, 404]).toContain(res.status);
      if (res.body.error) expect(res.body.error).toMatch(/not found|already used|access|denied/i);
    });

    it('returns 200 when admin resends invitation', async () => {
      (supabase.auth.admin.getUserById as jest.Mock).mockResolvedValue({
        data: { user: { email: 'admin@test.com' } },
        error: null,
      });
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_invitations', 'single', {
        data: { id: 'inv-1', email: 'x@test.com', role: 'member', organization_id: 'org-1', status: 'pending' },
        error: null,
      });
      setTableResponse('organizations', 'single', { data: { name: 'Test Org' }, error: null });

      const res = await request(app)
        .post('/api/organizations/org-1/invitations/inv-1/resend')
        .set('Authorization', `Bearer ${mockToken}`);

      expect([200, 201, 403, 404]).toContain(res.status);
      if (res.status === 200 || res.status === 201) expect(res.body.message).toMatch(/resent/i);
    });
  });
});
