import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  pushTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

describe('PUT /api/flows/:id — save-time validation', () => {
  const mockUser = { id: 'user-123', email: 'test@example.com' };
  const mockToken = 'valid-token';
  const orgId = 'org-1';
  const flowId = 'flow-1';

  function makeFlow(overrides: Record<string, unknown> = {}) {
    return {
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
      created_at: '2026-04-30T00:00:00Z',
      updated_at: '2026-04-30T00:00:00Z',
      ...overrides,
    };
  }

  function asOwner() {
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { manage_notifications: true } },
      error: null,
    });
  }

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    delete process.env.ALLOW_UNVALIDATED_SAVE;
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: mockUser }, error: null });
  });

  it('200 when graph has no code-mode nodes', async () => {
    asOwner();
    const flow = makeFlow();
    setTableResponse('flows', 'single', { data: flow, error: null });
    pushTableResponse('flows', { data: { ...flow, version: 2 }, error: null });
    pushTableResponse('flow_versions', { data: null, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        graph: {
          version: 1,
          nodes: [
            { id: 'n1', type: 'trigger', position: { x: 0, y: 0 }, config: { event_type: 'vulnerability_discovered' } },
            { id: 'n2', type: 'destination.in_app', position: { x: 200, y: 0 }, config: {} },
          ],
          edges: [{ id: 'e1', source: 'n1', sourceHandle: 'out', target: 'n2', targetHandle: 'in' }],
        },
      });
    expect(res.status).toBe(200);
  });

  it('200 when code-mode condition body is valid', async () => {
    asOwner();
    const flow = makeFlow();
    setTableResponse('flows', 'single', { data: flow, error: null });
    pushTableResponse('flows', { data: { ...flow, version: 2 }, error: null });
    pushTableResponse('flow_versions', { data: null, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        graph: {
          version: 1,
          nodes: [
            { id: 't', type: 'trigger', position: { x: 0, y: 0 }, config: { event_type: 'vulnerability_discovered' } },
            { id: 'c', type: 'condition', position: { x: 200, y: 0 }, config: {
              mode: 'code',
              code: 'function evaluate(context) { return context.vulnerability.severity === "high"; }',
            } },
            { id: 'd', type: 'destination.in_app', position: { x: 400, y: 0 }, config: {} },
          ],
          edges: [
            { id: 'e1', source: 't', sourceHandle: 'out', target: 'c', targetHandle: 'in' },
            { id: 'e2', source: 'c', sourceHandle: 'out', target: 'd', targetHandle: 'in' },
          ],
        },
      });
    expect(res.status).toBe(200);
  });

  it('400 with errors[] when code-mode condition has a syntax error', async () => {
    asOwner();
    const flow = makeFlow();
    setTableResponse('flows', 'single', { data: flow, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        graph: {
          version: 1,
          nodes: [
            { id: 't', type: 'trigger', position: { x: 0, y: 0 }, config: { event_type: 'vulnerability_discovered' } },
            { id: 'c', type: 'condition', position: { x: 200, y: 0 }, config: {
              mode: 'code',
              code: 'function evaluate(context) { return @# }',
            } },
          ],
          edges: [{ id: 'e1', source: 't', sourceHandle: 'out', target: 'c', targetHandle: 'in' }],
        },
      });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe('code_validation_failed');
    expect(res.body.errors).toHaveLength(1);
    expect(res.body.errors[0].nodeId).toBe('c');
    expect(res.body.errors[0].stage).toBe('parse');
  });

  it('400 when code-mode condition returns wrong type', async () => {
    asOwner();
    const flow = makeFlow();
    setTableResponse('flows', 'single', { data: flow, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        graph: {
          version: 1,
          nodes: [
            { id: 't', type: 'trigger', position: { x: 0, y: 0 }, config: { event_type: 'vulnerability_discovered' } },
            { id: 'c', type: 'condition', position: { x: 200, y: 0 }, config: {
              mode: 'code',
              code: 'function evaluate(context) { return "yes"; }',
            } },
          ],
          edges: [{ id: 'e1', source: 't', sourceHandle: 'out', target: 'c', targetHandle: 'in' }],
        },
      });
    expect(res.status).toBe(400);
    expect(res.body.errors[0].stage).toBe('returnShape');
  });

  it('400 when code-mode node has no upstream trigger event_type', async () => {
    asOwner();
    const flow = makeFlow();
    setTableResponse('flows', 'single', { data: flow, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        graph: {
          version: 1,
          nodes: [
            // No trigger at all → save-validation refuses code-mode condition.
            { id: 'c', type: 'condition', position: { x: 200, y: 0 }, config: {
              mode: 'code',
              code: 'function evaluate(context) { return true; }',
            } },
          ],
          edges: [],
        },
      });
    expect(res.status).toBe(400);
    expect(res.body.errors[0].message).toMatch(/trigger/i);
  });

  it('409 when expected_updated_at does not match current', async () => {
    asOwner();
    const flow = makeFlow({ updated_at: '2026-04-30T12:00:00Z' });
    setTableResponse('flows', 'single', { data: flow, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        expected_updated_at: '2026-04-30T11:00:00Z', // stale
        name: 'Renamed',
      });
    expect(res.status).toBe(409);
    expect(res.body.error).toBe('flow_modified_elsewhere');
    expect(res.body.current_updated_at).toBe('2026-04-30T12:00:00Z');
  });

  it('200 when expected_updated_at matches', async () => {
    asOwner();
    const flow = makeFlow({ updated_at: '2026-04-30T12:00:00Z' });
    setTableResponse('flows', 'single', { data: flow, error: null });
    pushTableResponse('flows', { data: { ...flow, name: 'Renamed' }, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        expected_updated_at: '2026-04-30T12:00:00Z',
        name: 'Renamed',
      });
    expect(res.status).toBe(200);
  });

  it('skips validation for visual-mode condition nodes', async () => {
    // Visual-mode condition with garbage in `code` field should still save —
    // the runtime ignores `code` when mode === 'visual'.
    asOwner();
    const flow = makeFlow();
    setTableResponse('flows', 'single', { data: flow, error: null });
    pushTableResponse('flows', { data: { ...flow, version: 2 }, error: null });
    pushTableResponse('flow_versions', { data: null, error: null });

    const res = await request(app)
      .put(`/api/flows/${flowId}`)
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        graph: {
          version: 1,
          nodes: [
            { id: 't', type: 'trigger', position: { x: 0, y: 0 }, config: { event_type: 'vulnerability_discovered' } },
            { id: 'c', type: 'condition', position: { x: 200, y: 0 }, config: {
              mode: 'visual',
              code: 'this is not valid js {{{{',
              conditions: [{ field: 'project.name', operator: 'equals', value: 'a' }],
            } },
          ],
          edges: [{ id: 'e1', source: 't', sourceHandle: 'out', target: 'c', targetHandle: 'in' }],
        },
      });
    expect(res.status).toBe(200);
  });
});
