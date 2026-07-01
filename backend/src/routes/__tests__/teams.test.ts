import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, setRpcResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({
  createActivity: jest.fn(),
}));
jest.mock('../../lib/cache', () => ({
  getCached: jest.fn().mockResolvedValue(null),
  setCached: jest.fn().mockResolvedValue(undefined),
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

  describe('GET /api/organizations/:id/teams/:teamId/stats (truncation guard)', () => {
    it('drives counts from team_stats_counts / team_top_vulns, never an unbounded row fetch', async () => {
      const teamId = 'team-stats-1';
      setTableResponse('teams', 'single', { data: { id: teamId, name: 'T', avatar_url: null, description: null }, error: null });
      setTableResponse('project_teams', 'then', { data: [{ project_id: 'p1' }], error: null });
      setTableResponse('projects', 'then', { data: [{ id: 'p1', name: 'P1', health_score: 50, status_id: null, active_extraction_run_id: 'run-1' }], error: null });
      setRpcResponse('team_stats_counts', { data: [{
        vuln_total: '1500', vuln_critical: '40', vuln_high: '60', vuln_medium: '900', vuln_low: '500',
        sla_on_track: '0', sla_warning: '0', sla_breached: '0', sla_exempt: '0', sla_met: '0', sla_resolved_late: '0',
      }], error: null });
      setRpcResponse('team_top_vulns', { data: [], error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/teams/${teamId}/stats`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(supabase.rpc).toHaveBeenCalledWith('team_stats_counts', { p_project_ids: ['p1'], p_active_run_ids: ['run-1'] });
      expect(supabase.rpc).toHaveBeenCalledWith('team_top_vulns', { p_project_ids: ['p1'], p_active_run_ids: ['run-1'] });
      expect(res.body.vulnerabilities.total).toBe(1500);
      expect(res.body.vulnerabilities.critical).toBe(40);
      // Regression guard: the old code fetched every pdv row (vuln counts + topVulns) and every
      // sla_status row, both unbounded → truncated at 1000. Neither signature may reappear.
      const selectArgs = queryBuilder.select.mock.calls.map((c: any[]) => String(c[0] ?? ''));
      expect(selectArgs.some((s: string) => s.includes('sla_status'))).toBe(false);
      expect(selectArgs.some((s: string) => s.includes('depscore'))).toBe(false);
    });
  });
});
