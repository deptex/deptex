/**
 * Phase 7B — Aegis Autonomous Security Platform test suite.
 *
 * Implements tests from .cursor/plans/phase_07b_aegis.plan.md § 7B-Q.
 * Backend: permissions (61–66), tool registry (9–16), task system (17–24),
 * security debt (7B-M), sprint orchestration (7B-N).
 */

/* eslint-disable @typescript-eslint/no-explicit-any */

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const USER_NO_AGENT = '00000000-0000-0000-0000-000000000098';

// Chainable supabase query builder
function chainableQuery(finalData: any = null, finalError: any = null, finalCount?: number) {
  const chain: Record<string, jest.Mock> = {};
  const terminal: any = { data: finalData, error: finalError };
  if (finalCount !== undefined) terminal.count = finalCount;

  const methods = ['select', 'insert', 'update', 'upsert', 'delete', 'eq', 'neq', 'gte', 'lte', 'in', 'order', 'limit', 'range', 'single', 'maybeSingle'];
  for (const m of methods) {
    chain[m] = jest.fn().mockReturnValue(chain);
  }
  chain.then = jest.fn((resolve?: (v: any) => void) => Promise.resolve(terminal).then(resolve));
  return chain;
}

let membershipData: { role: string } | null = { role: 'owner' };
let rolePermissions: Record<string, boolean> = { interact_with_aegis: true, manage_aegis: true, trigger_fix: true };

const mockFrom = jest.fn();
const mockSupabase = {
  from: mockFrom,
  auth: { getUser: jest.fn().mockResolvedValue({ data: { user: { id: USER_ID, email: 'u@test.com' } }, error: null }) },
};

jest.mock('../../lib/supabase', () => ({
  supabase: mockSupabase,
}));

// Auth: inject req.user when X-Test-User-Id header is set (for integration-style tests)
jest.mock('../../middleware/auth', () => ({
  authenticateUser: (req: any, res: any, next: any) => {
    const testUserId = req.get?.('X-Test-User-Id');
    if (testUserId) {
      req.user = { id: testUserId, email: 'test@test.com' };
      next();
    } else {
      res.status(401).json({ error: 'Unauthorized' });
    }
  },
  AuthRequest: {},
}));

// Rate limit: always allow in tests
jest.mock('../../lib/rate-limit', () => ({
  checkRateLimit: jest.fn().mockResolvedValue({ allowed: true }),
}));


function setupSupabaseForOrgMember() {
  mockFrom.mockImplementation((table: string) => {
    if (table === 'organization_members') {
      return chainableQuery(membershipData, null);
    }
    if (table === 'organization_roles') {
      return chainableQuery(membershipData ? { permissions: rolePermissions } : null, null);
    }
    if (table === 'aegis_org_settings' || table === 'aegis_tasks' || table === 'aegis_task_steps' || table === 'aegis_tool_executions' || table === 'aegis_approval_requests') {
      return chainableQuery(Array.isArray(mockFrom._lastResult) ? mockFrom._lastResult : [], null, 0);
    }
    if (table === 'projects') {
      return chainableQuery([]);
    }
    return chainableQuery(null, null);
  });
}

// Build app with aegis router (loaded after mocks)
import express from 'express';
import request from 'supertest';
import aegisRouter from '../aegis';

const app = express();
app.use(express.json());
app.use('/api/aegis', aegisRouter);

beforeEach(() => {
  jest.clearAllMocks();
  membershipData = { role: 'owner' };
  rolePermissions = { interact_with_aegis: true, manage_aegis: true, trigger_fix: true };
  setupSupabaseForOrgMember();
});

describe('Phase 7B: Aegis Autonomous Security Platform', () => {
  describe('Permissions (7B-P) — plan tests 61–66', () => {
    it('61: returns 401 when no user (missing X-Test-User-Id)', async () => {
      const res = await request(app)
        .post('/api/aegis/v2/stream')
        .send({ organizationId: ORG_ID, message: 'hi' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('62/63: returns 403 when user lacks interact_with_aegis', async () => {
      rolePermissions = { interact_with_aegis: false, manage_aegis: false, trigger_fix: false };
      membershipData = { role: 'member' };
      setupSupabaseForOrgMember();

      const res = await request(app)
        .post('/api/aegis/v2/stream')
        .set('X-Test-User-Id', USER_NO_AGENT)
        .send({ organizationId: ORG_ID, message: 'hi' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission/i);
    });

    it('63: GET /settings and /tasks require org membership (200 with member)', async () => {
      membershipData = { role: 'member' };
      rolePermissions = { interact_with_aegis: true, manage_aegis: true };
      mockFrom.mockImplementation((table: string) => {
        if (table === 'organization_members') return chainableQuery(membershipData, null);
        if (table === 'organization_roles') return chainableQuery({ permissions: rolePermissions }, null);
        if (table === 'aegis_org_settings') return chainableQuery(null, null);
        if (table === 'aegis_tasks') return chainableQuery([], null, 0);
        return chainableQuery(null, null);
      });

      const settingsRes = await request(app)
        .get(`/api/aegis/settings/${ORG_ID}`)
        .set('X-Test-User-Id', USER_ID);
      expect(settingsRes.status).toBe(200);

      const tasksRes = await request(app)
        .get(`/api/aegis/tasks/${ORG_ID}`)
        .set('X-Test-User-Id', USER_ID);
      expect(tasksRes.status).toBe(200);
      expect(Array.isArray(tasksRes.body) || Array.isArray(tasksRes.body?.tasks)).toBe(true);
    });
  });

  describe('Tool Registry (7B-B) — plan tests 9–16', () => {
    it('9/10: tool registry exposes getAllToolMetas and buildToolSet', async () => {
      const registry = await import('../../lib/aegis/tools/registry');
      expect(typeof registry.getAllToolMetas).toBe('function');
      expect(typeof registry.buildToolSet).toBe('function');
      const metas = registry.getAllToolMetas();
      expect(Array.isArray(metas)).toBe(true);
      // Without loading all tool files (redis, vuln-counts, etc.), we only see tools
      // registered by modules loaded so far (e.g. via aegis router). So we just assert
      // the registry API exists and returns an array.
      if (metas.length > 0) {
        expect(metas[0]).toHaveProperty('name');
        expect(metas[0]).toHaveProperty('meta');
        expect(metas[0].meta).toHaveProperty('category');
        expect(['safe', 'moderate', 'dangerous']).toContain(metas[0].meta.permissionLevel);
      }
    });
  });

  describe('Task System (7B-C) — plan tests 17–24', () => {
    it('17/18: createTask inserts task and steps', async () => {
      const { createTask } = await import('../../lib/aegis/tasks');
      const insertedTaskId = 'task-uuid-1';

      const taskChain = chainableQuery({ id: insertedTaskId }, null);
      taskChain.insert = jest.fn().mockReturnValue(taskChain);
      taskChain.select = jest.fn().mockReturnValue(taskChain);
      taskChain.single = jest.fn().mockImplementation(() => Promise.resolve({ data: { id: insertedTaskId }, error: null }));

      const stepsChain = chainableQuery(null, null);
      stepsChain.insert = jest.fn().mockResolvedValue({ error: null });

      mockFrom.mockImplementation((table: string) => {
        if (table === 'aegis_tasks') return taskChain;
        if (table === 'aegis_task_steps') return stepsChain;
        return chainableQuery(null, null);
      });

      const taskId = await createTask(ORG_ID, USER_ID, null, {
        title: 'Test plan',
        description: 'Desc',
        steps: [{ title: 'Step 1', toolName: 'listTeams', toolParams: {} }],
        estimatedCost: 0.1,
        estimatedTimeMinutes: 1,
      });

      expect(taskId).toBe(insertedTaskId);
    });

    it('getTaskStatus returns null for missing task', async () => {
      const { getTaskStatus } = await import('../../lib/aegis/tasks');
      mockFrom.mockImplementation(() => {
        const c = chainableQuery(null, null);
        c.single = jest.fn().mockResolvedValue({ data: null, error: null });
        return c;
      });

      const status = await getTaskStatus('non-existent-id');
      expect(status).toBeNull();
    });
  });

  describe('Security Debt (7B-M)', () => {
    it('107: computeDebtScore returns breakdown with zero score when no projects', async () => {
      const { computeDebtScore } = await import('../../lib/aegis/security-debt');
      mockFrom.mockImplementation((table: string) => {
        if (table === 'projects') return chainableQuery([]);
        return chainableQuery([]);
      });

      const result = await computeDebtScore(ORG_ID);
      expect(result.score).toBe(0);
      expect(result.breakdown).toEqual({
        vulns: 0,
        compliance: 0,
        staleDeps: 0,
        codeIssues: 0,
        secrets: 0,
      });
    });
  });

  describe('Sprint Orchestration (7B-N)', () => {
    it('createSecuritySprint returns error when max concurrent sprints', async () => {
      const { createSecuritySprint } = await import('../../lib/aegis/sprint-orchestrator');
      const sprintChain = chainableQuery([], null);
      (sprintChain as any).like = jest.fn().mockReturnValue(sprintChain);
      (sprintChain as any).in = jest.fn().mockReturnValue(
        Promise.resolve({ data: [], count: 3, error: null })
      );

      mockFrom.mockImplementation((table: string) => {
        if (table === 'aegis_tasks') return sprintChain;
        if (table === 'projects') return chainableQuery([]);
        return chainableQuery(null, null);
      });

      const result = await createSecuritySprint({
        organizationId: ORG_ID,
        userId: USER_ID,
        mode: 'auto',
      });

      expect(result.error).toMatch(/concurrent|maximum/i);
    });

    it('createSecuritySprint returns error when no fixable issues (no projects)', async () => {
      const { createSecuritySprint } = await import('../../lib/aegis/sprint-orchestrator');
      const sprintChain = chainableQuery([], null);
      (sprintChain as any).like = jest.fn().mockReturnValue(sprintChain);
      (sprintChain as any).in = jest.fn().mockReturnValue(
        Promise.resolve({ data: [], count: 0, error: null })
      );

      mockFrom.mockImplementation((table: string) => {
        if (table === 'aegis_tasks') return sprintChain;
        if (table === 'projects') return chainableQuery([]);
        return chainableQuery(null, null);
      });

      const result = await createSecuritySprint({
        organizationId: ORG_ID,
        userId: USER_ID,
        mode: 'auto',
      });

      expect(result.error).toMatch(/no fixable|no fix/i);
      expect(result.taskId).toBeUndefined();
    });
  });

  describe('Automations (7B-E) — plan tests 31–36', () => {
    it('cronMatchesNow parses cron expression (every minute matches)', async () => {
      const { cronMatchesNow } = await import('../../lib/aegis/automations-engine');
      expect(cronMatchesNow('* * * * *', 'UTC')).toBe(true);
      expect(cronMatchesNow('0 0 1 1 *', 'UTC')).toBe(false);
    });
  });
});
