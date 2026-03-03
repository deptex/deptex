/**
 * Phase 10B: Organization Watchtower API tests (overview, projects).
 */

import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
const mockGetCached = jest.fn().mockResolvedValue(null);
jest.mock('../../../../ee/backend/lib/cache', () => ({
  getCached: (...args: unknown[]) => mockGetCached(...args),
  setCached: jest.fn().mockResolvedValue(undefined),
  CACHE_TTL_SECONDS: {},
}));

describe('Organization Watchtower (Phase 10B)', () => {
  const mockUser = { id: 'user-1', email: 'u@example.com' };
  const orgId = 'org-1';

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    mockGetCached.mockResolvedValue(null);
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
  });

  describe('GET /api/organizations/:id/watchtower/overview', () => {
    it('returns 401 when not authenticated', async () => {
      (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: null }, error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/watchtower/overview`);

      expect(res.status).toBe(401);
    });

    it('returns 403 when not org member', async () => {
      setTableResponse('organization_members', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/watchtower/overview`)
        .set('Authorization', 'Bearer token');

      expect([403, 404]).toContain(res.status);
    });

    it('returns 200 with cached overview when cache hit', async () => {
      const cached = { projects_active: 2, packages_monitored: 50, active_alerts: 0, blocked_versions: 0 };
      mockGetCached.mockResolvedValueOnce(cached);

      const res = await request(app)
        .get(`/api/organizations/${orgId}/watchtower/overview`)
        .set('Authorization', 'Bearer token');

      expect(res.status).toBe(200);
      expect(res.body).toEqual(cached);
    });
  });

  describe('GET /api/organizations/:id/watchtower/projects', () => {
    it('returns 401 when not authenticated', async () => {
      (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: null }, error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/watchtower/projects`);

      expect(res.status).toBe(401);
    });

    it('returns 403 when not org member', async () => {
      setTableResponse('organization_members', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/watchtower/projects`)
        .set('Authorization', 'Bearer token');

      expect([403, 404]).toContain(res.status);
    });
  });
});
