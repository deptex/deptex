import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  pushTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
jest.mock('../../lib/activities', () => ({ createActivity: jest.fn() }));
jest.mock('../../lib/email', () => ({ sendInvitationEmail: jest.fn() }));
jest.mock('../../lib/rate-limit', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true, remaining: 120 }),
}));

describe('Organization Canvas Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';
  const teamId = 'team-abc';
  const projectId = 'proj-abc';

  const teamRow = {
    id: teamId,
    canvas_position_x: 10,
    canvas_position_y: 20,
    canvas_position_updated_at: '2026-04-21T00:00:00.000Z',
  };
  const projectRow = {
    id: projectId,
    canvas_position_x: 50,
    canvas_position_y: -30,
    canvas_position_updated_at: '2026-04-21T00:00:00.000Z',
  };

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    clearRpcRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    // Default: org owner (passes requireManagePermission immediately via short-circuit).
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
  });

  // ── PATCH /canvas/teams/:teamId/position ────────────────────────────────────

  describe('PATCH /api/organizations/:id/canvas/teams/:teamId/position', () => {
    const url = `/api/organizations/${orgId}/canvas/teams/${teamId}/position`;

    it('returns 401 when no auth token', async () => {
      const res = await request(app)
        .patch(url)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(401);
    });

    it('returns 400 when body is missing coords', async () => {
      setTableResponse('teams', 'single', { data: teamRow, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({});
      expect(res.status).toBe(400);
    });

    it('returns 400 when coords are not numbers', async () => {
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 'left', canvas_position_y: 20 });
      expect(res.status).toBe(400);
    });

    it('returns 400 when coords exceed MAX_POSITION', async () => {
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 2_000_000, canvas_position_y: 0 });
      expect(res.status).toBe(400);
    });

    it('returns 404 when user has no membership', async () => {
      setTableResponse('organization_members', 'single', { data: null, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(404);
    });

    it('returns 403 when member lacks manage_teams_and_projects', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'viewer' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(403);
    });

    it('returns 200 when admin role carries manage_teams_and_projects', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'admin' }, error: null });
      setTableResponse('organization_roles', 'single', {
        data: { permissions: { manage_teams_and_projects: true } },
        error: null,
      });
      setTableResponse('teams', 'single', { data: teamRow, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(200);
      expect(res.body.canvas_position_x).toBe(10);
      expect(res.body.canvas_position_y).toBe(20);
    });

    it('returns 200 when member with manage_teams_and_projects updates position', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'contributor' }, error: null });
      setTableResponse('organization_roles', 'single', {
        data: { permissions: { manage_teams_and_projects: true } },
        error: null,
      });
      setTableResponse('teams', 'single', { data: teamRow, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(200);
    });

    it('returns 404 when team not found in org', async () => {
      setTableResponse('teams', 'single', { data: null, error: { message: 'Row not found' } });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(404);
    });

    it('accepts negative and fractional coords', async () => {
      setTableResponse('teams', 'single', {
        data: { ...teamRow, canvas_position_x: -123.45, canvas_position_y: -0.1 },
        error: null,
      });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: -123.45, canvas_position_y: -0.1 });
      expect(res.status).toBe(200);
    });

    it('team drag does NOT fall back to team-level permission', async () => {
      // Team Lead with team-level manage_projects but no org-level permission
      // should still be 403 on team moves — team position is org-level.
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(403);
    });
  });

  // ── PATCH /canvas/projects/:projectId/position ──────────────────────────────

  describe('PATCH /api/organizations/:id/canvas/projects/:projectId/position', () => {
    const url = `/api/organizations/${orgId}/canvas/projects/${projectId}/position`;

    it('returns 400 when body is empty', async () => {
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({});
      expect(res.status).toBe(400);
    });

    it('returns 200 and updated row for owner', async () => {
      setTableResponse('projects', 'single', { data: projectRow, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 50, canvas_position_y: -30 });
      expect(res.status).toBe(200);
      expect(res.body.canvas_position_x).toBe(50);
      expect(res.body.canvas_position_y).toBe(-30);
    });

    it('returns 404 when project not found in org', async () => {
      setTableResponse('projects', 'single', { data: null, error: { message: 'Row not found' } });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 50, canvas_position_y: -30 });
      expect(res.status).toBe(404);
    });

    it('returns 403 when member lacks any permission', async () => {
      // No org-level perm, no team-level fallback possible.
      setTableResponse('organization_members', 'single', { data: { role: 'viewer' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
      setTableResponse('project_teams', 'then', { data: [], error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 50, canvas_position_y: -30 });
      expect(res.status).toBe(403);
    });

    it('returns 200 when team lead has manage_projects on the owning team', async () => {
      // Non-admin org member, but team lead of the project's owner team.
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
      setTableResponse('project_teams', 'then', {
        data: [{ is_owner: true, team_id: 'team-owner' }],
        error: null,
      });
      pushTableResponse('team_members', { data: { role: 'lead' }, error: null });
      pushTableResponse('team_roles', {
        data: { permissions: { manage_projects: true } },
        error: null,
      });
      setTableResponse('projects', 'single', { data: projectRow, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 50, canvas_position_y: -30 });
      expect(res.status).toBe(200);
    });

    it('returns 403 when team member lacks manage_projects team-role permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
      setTableResponse('project_teams', 'then', {
        data: [{ is_owner: true, team_id: 'team-owner' }],
        error: null,
      });
      pushTableResponse('team_members', { data: { role: 'contributor' }, error: null });
      pushTableResponse('team_roles', { data: { permissions: {} }, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 50, canvas_position_y: -30 });
      expect(res.status).toBe(403);
    });
  });

  // ── PATCH /canvas/batch ─────────────────────────────────────────────────────

  describe('PATCH /api/organizations/:id/canvas/batch', () => {
    const url = `/api/organizations/${orgId}/canvas/batch`;

    it('returns 400 when both arrays are empty', async () => {
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ teams: [], projects: [] });
      expect(res.status).toBe(400);
    });

    it('returns 400 when an item is missing id', async () => {
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [{ canvas_position_x: 10, canvas_position_y: 20 }],
          projects: [],
        });
      expect(res.status).toBe(400);
    });

    it('returns 400 when a coord exceeds MAX_POSITION', async () => {
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [{ id: teamId, canvas_position_x: 5_000_000, canvas_position_y: 0 }],
          projects: [],
        });
      expect(res.status).toBe(400);
    });

    it('returns 400 when batch exceeds MAX_BATCH_ITEMS', async () => {
      const huge = Array.from({ length: 101 }, (_, i) => ({
        id: `t-${i}`,
        canvas_position_x: 0,
        canvas_position_y: 0,
      }));
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ teams: huge, projects: [] });
      expect(res.status).toBe(400);
    });

    it('returns 403 when member lacks permission', async () => {
      setTableResponse('organization_members', 'single', { data: { role: 'viewer' }, error: null });
      setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [{ id: teamId, canvas_position_x: 10, canvas_position_y: 20 }],
          projects: [],
        });
      expect(res.status).toBe(403);
    });

    it('returns 200 with updated teams and empty projects for team-only batch', async () => {
      setRpcResponse('update_canvas_positions_batch', {
        data: { teams: [teamRow], projects: [] },
        error: null,
      });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [{ id: teamId, canvas_position_x: 10, canvas_position_y: 20 }],
          projects: [],
        });
      expect(res.status).toBe(200);
      expect(res.body.teams).toHaveLength(1);
      expect(res.body.teams[0].canvas_position_x).toBe(10);
      expect(res.body.projects).toHaveLength(0);
    });

    it('returns 200 with empty teams and updated projects for project-only batch', async () => {
      setRpcResponse('update_canvas_positions_batch', {
        data: { teams: [], projects: [projectRow] },
        error: null,
      });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [],
          projects: [{ id: projectId, canvas_position_x: 50, canvas_position_y: -30 }],
        });
      expect(res.status).toBe(200);
      expect(res.body.teams).toHaveLength(0);
      expect(res.body.projects).toHaveLength(1);
      expect(res.body.projects[0].canvas_position_y).toBe(-30);
    });

    it('returns 200 with a mixed team+project batch', async () => {
      setRpcResponse('update_canvas_positions_batch', {
        data: { teams: [teamRow], projects: [projectRow] },
        error: null,
      });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [{ id: teamId, canvas_position_x: 10, canvas_position_y: 20 }],
          projects: [{ id: projectId, canvas_position_x: 50, canvas_position_y: -30 }],
        });
      expect(res.status).toBe(200);
      expect(res.body.teams).toHaveLength(1);
      expect(res.body.projects).toHaveLength(1);
    });

    it('returns 404 when RPC raises "not found in this organization"', async () => {
      setRpcResponse('update_canvas_positions_batch', {
        data: null,
        error: { code: 'P0001', message: 'one or more teams not found in this organization' },
      });
      const res = await request(app)
        .patch(url)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          teams: [{ id: 'nonexistent', canvas_position_x: 10, canvas_position_y: 20 }],
          projects: [],
        });
      expect(res.status).toBe(404);
    });
  });

  // ── rate limiting ──────────────────────────────────────────────────────────

  describe('rate limiting', () => {
    it('returns 429 when the per-user rate limit is exceeded', async () => {
      const { checkRateLimit } = require('../../lib/rate-limit');
      (checkRateLimit as jest.Mock).mockResolvedValueOnce({
        allowed: false,
        remaining: 0,
        retryAfterSeconds: 30,
      });
      const res = await request(app)
        .patch(`/api/organizations/${orgId}/canvas/teams/${teamId}/position`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ canvas_position_x: 10, canvas_position_y: 20 });
      expect(res.status).toBe(429);
      expect(res.body.retry_after_seconds).toBe(30);
    });
  });
});
