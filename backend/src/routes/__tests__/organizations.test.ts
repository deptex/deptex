import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder } from '../../test/mocks/supabaseSingleton';

// Mock dependencies
jest.mock('../../lib/supabase');

jest.mock('../../../../ee/backend/lib/activities', () => ({
  createActivity: jest.fn(),
}));

jest.mock('../../../../ee/backend/lib/email', () => ({
  sendInvitationEmail: jest.fn(),
}));

// Mock OpenAI
jest.mock('../../../../ee/backend/lib/openai', () => ({
  getOpenAIClient: jest.fn().mockReturnValue({
    chat: { completions: { create: jest.fn() } }
  }),
}));

describe('Organization Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';

  beforeEach(() => {
    jest.clearAllMocks();
    // Setup default auth mock
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    // Restore default implementations
    queryBuilder.single.mockResolvedValue({ data: {}, error: null });
    queryBuilder.maybeSingle.mockResolvedValue({ data: {}, error: null });
    queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: [], error: null }));
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
      // Code: `await supabase.from('organization_roles').insert(...)`
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ error: null }));

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
});
