import request from 'supertest';
import app from '../../index';
import {
  supabase,
  setTableResponse,
  clearTableRegistry,
} from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

// In-memory Redis stand-in: emulates the subset of @upstash/redis we use
// (set with nx/ex, get, del). Lets us exercise the lock + cache code paths
// without spinning a real redis instance.
let mockRedisStore: Record<string, { value: any; expiresAt: number }> = {};
const mockRedisClient = {
  set: jest.fn(async (key: string, value: any, opts?: { nx?: boolean; ex?: number }) => {
    if (opts?.nx) {
      const existing = mockRedisStore[key];
      if (existing && existing.expiresAt > Date.now()) return null;
    }
    mockRedisStore[key] = {
      value,
      expiresAt: Date.now() + (opts?.ex ?? 300) * 1000,
    };
    return 'OK';
  }),
  get: jest.fn(async (key: string) => {
    const entry = mockRedisStore[key];
    if (!entry || entry.expiresAt <= Date.now()) return null;
    return entry.value;
  }),
  del: jest.fn(async (key: string) => {
    delete mockRedisStore[key];
    return 1;
  }),
};

jest.mock('../../lib/cache', () => ({
  getRedisClient: jest.fn(() => mockRedisClient),
}));

describe('POST /api/flows/validate-code', () => {
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
    graph: { version: 1, nodes: [], edges: [] },
    version: 1,
    active: true,
    dry_run: false,
    created_by_user_id: mockUser.id,
    created_at: '2026-04-30T00:00:00Z',
    updated_at: '2026-04-30T00:00:00Z',
  };

  function asOwner() {
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: { manage_notifications: true } },
      error: null,
    });
  }

  function asViewerOnly() {
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('organization_roles', 'single', {
      data: { permissions: {} },
      error: null,
    });
  }

  function withFlow(flow = baseFlow) {
    setTableResponse('flows', 'single', { data: flow, error: null });
  }

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    mockRedisStore = {};
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: mockUser }, error: null });
  });

  it('401 without Authorization header', async () => {
    const res = await request(app).post('/api/flows/validate-code').send({});
    expect(res.status).toBe(401);
  });

  it('400 when required fields missing', async () => {
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'condition' });
    expect(res.status).toBe(400);
  });

  it('400 when code exceeds 50KB cap', async () => {
    asOwner();
    withFlow();
    const code = 'x'.repeat(50_001);
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'condition', eventType: 'vulnerability_discovered', code });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/cap/i);
  });

  it('400 when nodeType is unknown', async () => {
    asOwner();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'transform', eventType: 'vulnerability_discovered', code: 'return true;' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Unknown nodeType/);
  });

  it('400 when eventType is unknown', async () => {
    asOwner();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'condition', eventType: 'no_such_event', code: 'return true;' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Unknown eventType/);
  });

  it('404 when flow does not exist', async () => {
    asOwner();
    setTableResponse('flows', 'single', { data: null, error: null });
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'condition', eventType: 'vulnerability_discovered', code: 'return true;' });
    expect(res.status).toBe(404);
  });

  it('403 when user lacks manage_notifications permission', async () => {
    asViewerOnly();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'condition', eventType: 'vulnerability_discovered', code: 'return true;' });
    expect(res.status).toBe(403);
  });

  it('200 happy path: valid condition body returns boolean', async () => {
    asOwner();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        flowId,
        nodeType: 'condition',
        eventType: 'vulnerability_discovered',
        code: `return context.vulnerability.severity === 'high';`,
      });
    expect(res.status).toBe(200);
    expect(res.body.syntaxOk).toBe(true);
    expect(res.body.runOk).toBe(true);
    expect(res.body.returnValue).toBe(true);
    expect(res.body.cached).toBeUndefined();
  });

  it('200 with parse error: syntaxOk false, error.stage = parse', async () => {
    asOwner();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        flowId,
        nodeType: 'condition',
        eventType: 'vulnerability_discovered',
        code: 'return ;;}}{{',
      });
    expect(res.status).toBe(200);
    expect(res.body.syntaxOk).toBe(false);
    expect(res.body.runOk).toBe(false);
    expect(res.body.error.stage).toBe('parse');
  });

  it('200 with returnShape error when body returns non-boolean', async () => {
    asOwner();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        flowId,
        nodeType: 'condition',
        eventType: 'vulnerability_discovered',
        code: 'return "yes";',
      });
    expect(res.status).toBe(200);
    expect(res.body.syntaxOk).toBe(true);
    expect(res.body.runOk).toBe(false);
    expect(res.body.error.stage).toBe('returnShape');
  });

  it('cache hit: second identical request returns cached: true', async () => {
    asOwner();
    withFlow();
    const payload = {
      flowId,
      nodeType: 'condition',
      eventType: 'vulnerability_discovered',
      code: 'return true;',
    };
    const r1 = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send(payload);
    expect(r1.status).toBe(200);
    expect(r1.body.cached).toBeUndefined();

    // Re-stub auth + RBAC for the second call (the mocks reset per request flow).
    asOwner();
    withFlow();
    const r2 = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send(payload);
    expect(r2.status).toBe(200);
    expect(r2.body.cached).toBe(true);
    expect(r2.body.runOk).toBe(true);
  });

  it('customContext bypasses cache and runs against user-supplied JSON', async () => {
    asOwner();
    withFlow();
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({
        flowId,
        nodeType: 'condition',
        eventType: 'vulnerability_discovered',
        code: `return context.vulnerability.severity === 'critical';`,
        customContext: {
          project: { name: 'a', tier: 'p', framework: 'react' },
          dependency: { name: 'x', version: '1.0.0', isDirect: true },
          vulnerability: {
            osvId: 'X', severity: 'critical', cvssScore: 10, epssScore: 0.9,
            cisaKev: true, isReachable: true, reachabilityLevel: 'confirmed', depscore: 99,
          },
        },
      });
    expect(res.status).toBe(200);
    expect(res.body.runOk).toBe(true);
    expect(res.body.returnValue).toBe(true);
  });

  it('in-flight lock: concurrent request from same user returns 429', async () => {
    asOwner();
    withFlow();
    // Pre-populate the lock as if another request is already running.
    mockRedisStore[`flow:validate-code:lock:${mockUser.id}`] = {
      value: '1',
      expiresAt: Date.now() + 10_000,
    };
    const res = await request(app)
      .post('/api/flows/validate-code')
      .set('Authorization', `Bearer ${mockToken}`)
      .send({ flowId, nodeType: 'condition', eventType: 'vulnerability_discovered', code: 'return true;' });
    expect(res.status).toBe(429);
  });
});
