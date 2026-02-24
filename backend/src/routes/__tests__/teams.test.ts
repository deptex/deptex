import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder } from '../../test/mocks/supabaseSingleton';

// Mock dependencies
jest.mock('../../lib/supabase');

jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));

describe('Team Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';

  beforeEach(() => {
    jest.clearAllMocks();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    // Restore default implementations
    queryBuilder.single.mockResolvedValue({ data: {}, error: null });
    queryBuilder.maybeSingle.mockResolvedValue({ data: {}, error: null });
    queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: [], error: null }));
  });

  describe('GET /api/organizations/:id/teams', () => {
    it('should list all teams for org owner', async () => {
      // 1. Check membership
      // .from('organization_members').select('role').eq('organization_id', id).eq('user_id', userId).single()
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null
      });

      // 2. Get org role permissions
      // .from('organization_roles').select('permissions').eq(...).single()
      queryBuilder.single.mockResolvedValueOnce({
        data: { permissions: { manage_teams_and_projects: true } },
        error: null
      });

      // 3. Get teams (owner sees all)
      // .from('teams').select('*').eq(...).order(...)
      const mockTeams = [{ id: 'team-1', name: 'Team A' }];
      // Use 'then' for the list query
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ data: mockTeams, error: null }));

      // 4. For each team:
      // a. Member count
      // b. Project count
      // c. User team membership
      // Loop for team-1:
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ count: 2, error: null })); // members
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ count: 1, error: null })); // projects
      queryBuilder.single.mockResolvedValueOnce({ data: null, error: null }); // team membership (user not in team)

      const res = await request(app)
        .get(`/api/organizations/${orgId}/teams`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].name).toBe('Team A');
      expect(res.body[0].member_count).toBe(2);
      // Owner gets full permissions even if not in team
      expect(res.body[0].permissions.manage_members).toBe(true);
    });
  });

  describe('POST /api/organizations/:id/teams', () => {
    it('should create a team if user is owner', async () => {
      // 1. Check membership
      queryBuilder.single.mockResolvedValueOnce({
        data: { role: 'owner' },
        error: null
      });

      // 2. Insert team
      const newTeam = { id: 'team-new', name: 'New Team' };
      queryBuilder.single.mockResolvedValueOnce({ data: newTeam, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/teams`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'New Team' });

      expect(res.status).toBe(201);
      expect(res.body.name).toBe('New Team');
      expect(queryBuilder.insert).toHaveBeenCalledWith(expect.objectContaining({
        organization_id: orgId,
        name: 'New Team'
      }));
    });
  });
});
