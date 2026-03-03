/**
 * Phase 10B: Project Watchtower API tests (toggle, stats).
 * Requires DEPTEX_EDITION=ee (EE routes mounted).
 */

import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({ ...require('../../test/mocks/supabaseSingleton'), createUserClient: jest.fn() }));
const mockGetCached = jest.fn().mockResolvedValue(null);
const mockInvalidateCache = jest.fn().mockResolvedValue(undefined);
jest.mock('../../../../ee/backend/lib/cache', () => ({
  getCached: (...args: unknown[]) => mockGetCached(...args),
  setCached: jest.fn().mockResolvedValue(undefined),
  invalidateCache: (...args: unknown[]) => mockInvalidateCache(...args),
  CACHE_TTL_SECONDS: {},
}));

const mockQueueWatchtowerJobs = jest.fn().mockResolvedValue({ success: true, count: 0 });
jest.mock('../../../../ee/backend/lib/watchtower-queue', () => ({
  queueWatchtowerJob: jest.fn().mockResolvedValue({ success: true }),
  queueWatchtowerJobs: (...args: unknown[]) => mockQueueWatchtowerJobs(...args),
}));

describe('Project Watchtower (Phase 10B)', () => {
  const mockUser = { id: 'user-1', email: 'u@example.com' };
  const orgId = 'org-1';
  const projectId = 'proj-1';

  beforeEach(() => {
    jest.clearAllMocks();
    clearTableRegistry();
    mockGetCached.mockResolvedValue(null);
    (supabase.auth.getUser as jest.Mock).mockResolvedValue({
      data: { user: mockUser },
      error: null,
    });
    setTableResponse('organization_members', 'single', { data: { role: 'owner' }, error: null });
    setTableResponse('organizations', 'single', { data: { mfa_enforced: false }, error: null });
  });

  describe('POST /api/organizations/:orgId/projects/:projectId/watchtower/toggle', () => {
    it('returns 401 when not authenticated', async () => {
      (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: null }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/watchtower/toggle`)
        .send({ enabled: true });

      expect(res.status).toBe(401);
    });

    it('returns 403 when user is not org member', async () => {
      setTableResponse('organization_members', 'single', { data: null, error: { message: 'Not found' } });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/watchtower/toggle`)
        .set('Authorization', 'Bearer token')
        .send({ enabled: true });

      expect([403, 404]).toContain(res.status);
      if (res.body.error) expect(res.body.error).toMatch(/member|organization|not found|access/i);
    });

    it('returns 200 and enables Watchtower when no direct deps (packages_watched 0)', async () => {
      setTableResponse('project_dependencies', 'then', { data: [], error: null });
      setTableResponse('projects', 'single', { data: { watchtower_enabled: true }, error: null });

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/watchtower/toggle`)
        .set('Authorization', 'Bearer token')
        .send({ enabled: true });

      expect(res.status).toBe(200);
      expect(res.body.watchtower_enabled).toBe(true);
      expect(res.body.packages_watched).toBe(0);
      expect(mockInvalidateCache).toHaveBeenCalledWith(`watchtower-project-stats:${projectId}`);
      expect(mockInvalidateCache).toHaveBeenCalledWith(`watchtower-org-stats:${orgId}`);
    });

    it('returns 200 and disables Watchtower', async () => {
      queryBuilder.single.mockResolvedValueOnce({ data: { role: 'owner' }, error: null });
      queryBuilder.update.mockReturnValueOnce({ eq: jest.fn().mockResolvedValue({ error: null }) });
      queryBuilder.then.mockImplementationOnce((resolve: any) => resolve({ data: [], error: null })); // project_watchlist rows for delete

      const res = await request(app)
        .post(`/api/organizations/${orgId}/projects/${projectId}/watchtower/toggle`)
        .set('Authorization', 'Bearer token')
        .send({ enabled: false });

      expect(res.status).toBe(200);
      expect(res.body.watchtower_enabled).toBe(false);
      expect(res.body.packages_watched).toBe(0);
    });
  });

  describe('GET /api/organizations/:orgId/projects/:projectId/watchtower/stats', () => {
    it('returns 401 when not authenticated', async () => {
      (supabase.auth.getUser as jest.Mock).mockResolvedValue({ data: { user: null }, error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/watchtower/stats`);

      expect(res.status).toBe(401);
    });

    it('returns 200 with cached stats when cache hit', async () => {
      const cached = { enabled: true, packages_monitored: 10, security_alerts: 0 };
      mockGetCached.mockResolvedValueOnce(cached);

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/watchtower/stats`)
        .set('Authorization', 'Bearer token');

      expect(res.status).toBe(200);
      expect(res.body).toEqual(cached);
    });

    it('returns 200 with enabled: false when project has Watchtower disabled', async () => {
      setTableResponse('projects', 'single', { data: { watchtower_enabled: false }, error: null });

      const res = await request(app)
        .get(`/api/organizations/${orgId}/projects/${projectId}/watchtower/stats`)
        .set('Authorization', 'Bearer token');

      expect(res.status).toBe(200);
      expect(res.body.enabled).toBe(false);
    });
  });
});
