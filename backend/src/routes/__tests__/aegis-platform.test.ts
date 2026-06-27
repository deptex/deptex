/**
 * Aegis platform test suite.
 *
 * Backend: permissions, security debt, automations. (The legacy aegis-v2 task
 * system, tool registry, and sprint orchestration were removed with the v2 task
 * primitive; the new Aegis Task is covered by aegis-tasks tests + the PGLite
 * rollup-trigger test.)
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
    if (table === 'aegis_org_settings') {
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
import aegisV3Router from '../aegis-v3';

const app = express();
app.use(express.json());
app.use('/api/aegis', aegisRouter);
app.use('/api/aegis/v3', aegisV3Router);

beforeEach(() => {
  jest.clearAllMocks();
  membershipData = { role: 'owner' };
  rolePermissions = { interact_with_aegis: true, manage_aegis: true, trigger_fix: true };
  setupSupabaseForOrgMember();
});

describe('Aegis platform', () => {
  describe('Permissions (7B-P) — plan tests 61–66', () => {
    it('61: returns 401 when no user (missing X-Test-User-Id)', async () => {
      const res = await request(app)
        .post('/api/aegis/v3/stream')
        .send({ organizationId: ORG_ID, message: 'hi' });

      expect(res.status).toBe(401);
      expect(res.body.error).toBe('Unauthorized');
    });

    it('62/63: returns 403 when user lacks interact_with_aegis', async () => {
      rolePermissions = { interact_with_aegis: false, manage_aegis: false, trigger_fix: false };
      membershipData = { role: 'member' };
      setupSupabaseForOrgMember();

      const res = await request(app)
        .post('/api/aegis/v3/stream')
        .set('X-Test-User-Id', USER_NO_AGENT)
        .send({ organizationId: ORG_ID, message: 'hi' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/permission/i);
    });

    it('63: GET /settings requires org membership (200 with member)', async () => {
      membershipData = { role: 'member' };
      rolePermissions = { interact_with_aegis: true, manage_aegis: true };
      mockFrom.mockImplementation((table: string) => {
        if (table === 'organization_members') return chainableQuery(membershipData, null);
        if (table === 'organization_roles') return chainableQuery({ permissions: rolePermissions }, null);
        if (table === 'aegis_org_settings') return chainableQuery(null, null);
        return chainableQuery(null, null);
      });

      const settingsRes = await request(app)
        .get(`/api/aegis/settings/${ORG_ID}`)
        .set('X-Test-User-Id', USER_ID);
      expect(settingsRes.status).toBe(200);
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

  describe('Automations (7B-E) — plan tests 31–36', () => {
    it('cronMatchesNow parses cron expression (every minute matches)', async () => {
      const { cronMatchesNow } = await import('../../lib/aegis/automations-engine');
      expect(cronMatchesNow('* * * * *', 'UTC')).toBe(true);
      expect(cronMatchesNow('0 0 1 1 *', 'UTC')).toBe(false);
    });
  });
});
