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

describe('Flow Routes', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';
  const flowId = 'flow-1';

  const baseFlow = {
    id: flowId,
    flow_type: 'notification',
    scope: 'organization',
    scope_id: orgId,
    organization_id: orgId,
    name: 'Test flow',
    description: null,
    graph: { version: 1, nodes: [], edges: [] },
    version: 1,
    active: true,
    dry_run: false,
    snoozed_until: null,
    created_by_user_id: mockUser.id,
    created_at: '2026-04-19T00:00:00Z',
    updated_at: '2026-04-19T00:00:00Z',
  };

  const validGraph = {
    version: 1,
    nodes: [
      {
        id: 'n1',
        type: 'trigger.event',
        position: { x: 0, y: 0 },
        config: { event_types: ['vulnerability_discovered'] },
      },
      {
        id: 'n2',
        type: 'destination.in_app',
        position: { x: 200, y: 0 },
        config: {},
      },
    ],
    edges: [{ id: 'e1', source: 'n1', sourceHandle: 'out', target: 'n2', targetHandle: 'in' }],
  };

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
  });

  // Org owner sets up: org member as owner with all perms.
  function asOwner() {
    setTableResponse('organization_members', 'single', {
      data: { role: 'owner' },
      error: null,
    });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { manage_notifications: true, manage_policies: true, manage_statuses: true } },
      error: null,
    });
  }

  // Org member with no relevant permissions.
  function asViewerOnly() {
    setTableResponse('organization_members', 'single', {
      data: { role: 'member' },
      error: null,
    });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { view_overview: true } },
      error: null,
    });
  }

  // Not a member of the org at all.
  function asNonMember() {
    setTableResponse('organization_members', 'single', {
      data: null,
      error: { code: 'PGRST116' },
    });
  }

  describe('Auth', () => {
    it('401 when no Authorization header', async () => {
      const res = await request(app).get(`/api/flows?organization_id=${orgId}`);
      expect(res.status).toBe(401);
    });
  });

  describe('GET /api/flows', () => {
    it('200 lists flows for org member', async () => {
      asOwner();
      setTableResponse('flows', 'then', { data: [baseFlow], error: null });

      const res = await request(app)
        .get(`/api/flows?organization_id=${orgId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(Array.isArray(res.body)).toBe(true);
      expect(res.body[0].id).toBe(flowId);
    });

    it('400 when organization_id missing', async () => {
      asOwner();
      const res = await request(app)
        .get(`/api/flows`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(400);
    });

    it('404 when not an org member', async () => {
      asNonMember();
      const res = await request(app)
        .get(`/api/flows?organization_id=${orgId}`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(404);
    });
  });

  describe('GET /api/flows/:id', () => {
    it('200 returns the flow for an org member', async () => {
      // First call hits flows.single (loadFlow), then organization_members.single (canViewOrg).
      setTableResponse('flows', 'single', { data: baseFlow, error: null });
      setTableResponse('organization_members', 'single', {
        data: { role: 'member' },
        error: null,
      });

      const res = await request(app)
        .get(`/api/flows/${flowId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.id).toBe(flowId);
    });

    it('404 when flow does not exist', async () => {
      setTableResponse('flows', 'single', { data: null, error: null });
      const res = await request(app)
        .get(`/api/flows/missing`)
        .set('Authorization', `Bearer ${mockToken}`);
      expect(res.status).toBe(404);
    });
  });

  describe('POST /api/flows', () => {
    it('201 creates a flow when user has permission', async () => {
      asOwner();
      setTableResponse('flows', 'single', { data: { ...baseFlow, graph: validGraph }, error: null });
      setTableResponse('flow_versions', 'single', { data: { id: 'v1' }, error: null });

      const res = await request(app)
        .post(`/api/flows`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          organization_id: orgId,
          flow_type: 'notification',
          scope: 'organization',
          scope_id: orgId,
          name: 'My flow',
          graph: validGraph,
        });

      expect(res.status).toBe(201);
      expect(res.body.id).toBe(flowId);
      expect(queryBuilder.insert).toHaveBeenCalledWith(
        expect.objectContaining({
          flow_type: 'notification',
          scope: 'organization',
          name: 'My flow',
          version: 1,
        }),
      );
    });

    it('403 when user lacks permission for the flow_type', async () => {
      asViewerOnly();

      const res = await request(app)
        .post(`/api/flows`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          organization_id: orgId,
          flow_type: 'notification',
          scope: 'organization',
          scope_id: orgId,
          name: 'My flow',
        });

      expect(res.status).toBe(403);
    });

    it('400 when graph references missing node', async () => {
      asOwner();

      const res = await request(app)
        .post(`/api/flows`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          organization_id: orgId,
          flow_type: 'notification',
          scope: 'organization',
          scope_id: orgId,
          name: 'Bad',
          graph: {
            version: 1,
            nodes: [{ id: 'a', type: 't', position: { x: 0, y: 0 }, config: {} }],
            edges: [{ id: 'e1', source: 'a', sourceHandle: 'out', target: 'ghost', targetHandle: 'in' }],
          },
        });

      expect(res.status).toBe(400);
    });

    it('400 when flow_type is invalid', async () => {
      asOwner();

      const res = await request(app)
        .post(`/api/flows`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({
          organization_id: orgId,
          flow_type: 'invalid_type',
          scope: 'organization',
          scope_id: orgId,
          name: 'Bad',
        });

      expect(res.status).toBe(400);
    });
  });

  describe('PUT /api/flows/:id', () => {
    it('200 bumps version when graph changes', async () => {
      // loadFlow.single, then canManageFlow: org_members.single + org_roles.single.
      pushTableResponse('flows', { data: baseFlow, error: null }); // loadFlow
      pushTableResponse('flows', { data: { ...baseFlow, version: 2, graph: validGraph }, error: null }); // update.single
      asOwner();
      setTableResponse('flow_versions', 'single', { data: { id: 'v2' }, error: null });

      const res = await request(app)
        .put(`/api/flows/${flowId}`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ graph: validGraph, change_summary: 'add destination' });

      expect(res.status).toBe(200);
      expect(res.body.version).toBe(2);
      // The update should include version: 2 (flow.version + 1).
      expect(queryBuilder.update).toHaveBeenCalledWith(
        expect.objectContaining({ version: 2 }),
      );
    });

    it('200 does not bump version when only name changes', async () => {
      pushTableResponse('flows', { data: baseFlow, error: null });
      pushTableResponse('flows', { data: { ...baseFlow, name: 'Renamed' }, error: null });
      asOwner();

      const res = await request(app)
        .put(`/api/flows/${flowId}`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'Renamed' });

      expect(res.status).toBe(200);
      // The update payload should NOT carry a version field.
      const call = (queryBuilder.update as jest.Mock).mock.calls.find(
        (c) => c[0].name === 'Renamed',
      );
      expect(call?.[0].version).toBeUndefined();
    });

    it('403 when user lacks permission', async () => {
      pushTableResponse('flows', { data: baseFlow, error: null });
      asViewerOnly();

      const res = await request(app)
        .put(`/api/flows/${flowId}`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ name: 'Renamed' });

      expect(res.status).toBe(403);
    });
  });

  describe('DELETE /api/flows/:id', () => {
    it('204 deletes for permitted user', async () => {
      pushTableResponse('flows', { data: baseFlow, error: null });
      asOwner();

      const res = await request(app)
        .delete(`/api/flows/${flowId}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(204);
      expect(queryBuilder.delete).toHaveBeenCalled();
    });
  });

  describe('PATCH /api/flows/:id/active', () => {
    it('200 toggles active', async () => {
      pushTableResponse('flows', { data: baseFlow, error: null });
      asOwner();
      pushTableResponse('flows', { data: { ...baseFlow, active: false }, error: null });

      const res = await request(app)
        .patch(`/api/flows/${flowId}/active`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ active: false });

      expect(res.status).toBe(200);
      expect(res.body.active).toBe(false);
    });

    it('400 when active is not a boolean', async () => {
      pushTableResponse('flows', { data: baseFlow, error: null });
      asOwner();

      const res = await request(app)
        .patch(`/api/flows/${flowId}/active`)
        .set('Authorization', `Bearer ${mockToken}`)
        .send({ active: 'yes' });

      expect(res.status).toBe(400);
    });
  });
});
