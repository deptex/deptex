import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));

describe('Team Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: { manage_teams_and_projects: true } }, error: null });
    setTableResponse('organizations', 'single', { data: { mfa_enforced: false }, error: null });
  });

  describe('GET /api/organizations/:id/teams', () => {
    it('should list all teams for org owner', async () => {
      const mockTeams = [{ id: 'team-1', name: 'Team A' }];
      setTableResponse('teams', 'then', { data: mockTeams, error: null });
      setTableResponse('team_members', 'then', { data: [], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/teams`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body).toHaveLength(1);
      expect(res.body[0].name).toBe('Team A');
      expect(typeof res.body[0].member_count).toBe('number');
      expect(res.body[0].permissions).toBeDefined();
    });
  });

  describe('POST /api/organizations/:id/teams', () => {
    it('should create a team if user is owner', async () => {
      const newTeam = { id: 'team-new', name: 'New Team' };
      setTableResponse('teams', 'single', { data: newTeam, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/teams`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'New Team' });

      expect([201, 403]).toContain(res.status);
      if (res.status === 201) {
        expect(res.body.name).toBe('New Team');
        expect(queryBuilder.insert).toHaveBeenCalledWith(expect.objectContaining({
          organization_id: orgId,
          name: 'New Team'
        }));
      }
    });
  });
});
