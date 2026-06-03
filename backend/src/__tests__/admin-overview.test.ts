import express from 'express';
import request from 'supertest';
import { clearTableRegistry } from '../test/mocks/supabaseSingleton';

const USER_ID = '00000000-0000-0000-0000-000000000099';

// Mutable so each test can swap the authenticated identity. `mock`-prefixed so
// babel-plugin-jest-hoist allows referencing it inside the factory; the factory
// body only reads it per-request, well after the module finishes initializing.
let mockAuthUser: { id: string; email: string } = { id: USER_ID, email: 'admin@deptex.dev' };
jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = mockAuthUser;
    next();
  },
}));

import adminRouter from '../routes/admin';

const app = express();
app.use(express.json());
app.use('/api/admin', adminRouter);

const ORIGINAL_ADMIN_EMAIL = process.env.ADMIN_EMAIL;

describe('admin overview — GET /api/admin/overview', () => {
  beforeEach(() => {
    clearTableRegistry();
    mockAuthUser = { id: USER_ID, email: 'admin@deptex.dev' };
    process.env.ADMIN_EMAIL = 'admin@deptex.dev';
  });

  afterAll(() => {
    if (ORIGINAL_ADMIN_EMAIL === undefined) delete process.env.ADMIN_EMAIL;
    else process.env.ADMIN_EMAIL = ORIGINAL_ADMIN_EMAIL;
  });

  it('403s when ADMIN_EMAIL is not configured (fails closed)', async () => {
    delete process.env.ADMIN_EMAIL;
    const res = await request(app).get('/api/admin/overview');
    expect(res.status).toBe(403);
  });

  it('403s a user whose email is not on the allowlist', async () => {
    process.env.ADMIN_EMAIL = 'admin@deptex.dev';
    mockAuthUser = { id: USER_ID, email: 'intruder@evil.com' };
    const res = await request(app).get('/api/admin/overview');
    expect(res.status).toBe(403);
  });

  it('honours a comma-separated allowlist, case-insensitively', async () => {
    process.env.ADMIN_EMAIL = 'someone@x.com, ADMIN@Deptex.dev ';
    mockAuthUser = { id: USER_ID, email: 'admin@deptex.dev' };
    const res = await request(app).get('/api/admin/overview');
    expect(res.status).toBe(200);
  });

  it('returns the platform-overview contract for an allowlisted admin', async () => {
    const res = await request(app).get('/api/admin/overview');
    expect(res.status).toBe(200);
    expect(res.body.totals).toEqual(
      expect.objectContaining({
        organizations: expect.any(Number),
        projects: expect.any(Number),
        users: expect.any(Number),
        scans30d: expect.any(Number),
      }),
    );
    expect(Array.isArray(res.body.growthSeries)).toBe(true);
  });
});

describe('admin billing — GET /api/admin/billing', () => {
  beforeEach(() => {
    clearTableRegistry();
    mockAuthUser = { id: USER_ID, email: 'admin@deptex.dev' };
    process.env.ADMIN_EMAIL = 'admin@deptex.dev';
  });

  afterAll(() => {
    if (ORIGINAL_ADMIN_EMAIL === undefined) delete process.env.ADMIN_EMAIL;
    else process.env.ADMIN_EMAIL = ORIGINAL_ADMIN_EMAIL;
  });

  it('403s a non-allowlisted user', async () => {
    mockAuthUser = { id: USER_ID, email: 'intruder@evil.com' };
    const res = await request(app).get('/api/admin/billing');
    expect(res.status).toBe(403);
  });

  it('returns the billing contract for an allowlisted admin', async () => {
    const res = await request(app).get('/api/admin/billing');
    expect(res.status).toBe(200);
    expect(res.body.financials).toEqual(
      expect.objectContaining({
        depositsCents: expect.any(Number),
        deposits30dCents: expect.any(Number),
        grossMarginCents: expect.any(Number),
        freeCreditBurnedCents: expect.any(Number),
        realBalanceHeldCents: expect.any(Number),
        freeCreditOutstandingCents: expect.any(Number),
        estimated: expect.any(Boolean),
        truncated: expect.any(Boolean),
      }),
    );
    expect(Array.isArray(res.body.revenueSeries)).toBe(true);
    expect(Array.isArray(res.body.recentActivity)).toBe(true);
  });
});

// The requireAdmin gate is applied router-wide, but pin it on EVERY endpoint so a
// future route added before the .use() — or an ungated sibling — can't slip through.
const ADMIN_ENDPOINTS = [
  '/api/admin/ping',
  '/api/admin/fleet-metrics',
  '/api/admin/extraction-failures',
  '/api/admin/extraction-trend',
  '/api/admin/overview',
  '/api/admin/billing',
];

describe('admin gate — every /api/admin endpoint is fail-closed', () => {
  beforeEach(() => {
    clearTableRegistry();
    mockAuthUser = { id: USER_ID, email: 'admin@deptex.dev' };
    process.env.ADMIN_EMAIL = 'admin@deptex.dev';
  });

  afterAll(() => {
    if (ORIGINAL_ADMIN_EMAIL === undefined) delete process.env.ADMIN_EMAIL;
    else process.env.ADMIN_EMAIL = ORIGINAL_ADMIN_EMAIL;
  });

  it.each(ADMIN_ENDPOINTS)('403s a non-allowlisted user on %s', async (path) => {
    process.env.ADMIN_EMAIL = 'admin@deptex.dev';
    mockAuthUser = { id: USER_ID, email: 'intruder@evil.com' };
    const res = await request(app).get(path);
    expect(res.status).toBe(403);
  });

  it.each(ADMIN_ENDPOINTS)('403s when ADMIN_EMAIL is unset on %s', async (path) => {
    delete process.env.ADMIN_EMAIL;
    const res = await request(app).get(path);
    expect(res.status).toBe(403);
  });
});
