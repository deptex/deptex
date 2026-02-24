/**
 * Tests for Watchtower API routes: access control, summary, and commits.
 */

import request from 'supertest';
import app from '../../index';
import { supabase, queryBuilder } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase');
jest.mock('../../lib/cache', () => ({
  getWatchtowerSummaryCacheKey: jest.fn((name: string, depId?: string) => `watchtower-summary:${name}:${depId || 'none'}`),
  getCached: jest.fn().mockResolvedValue(null),
  setCached: jest.fn().mockResolvedValue(undefined),
  CACHE_TTL_SECONDS: { WATCHTOWER_SUMMARY: 300 },
}));

const mockUser = { id: 'user-123', email: 'test@example.com' };
const mockToken = 'valid-token';
const packageName = 'lodash';

function setupWatchtowerAccessGranted() {
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  // checkWatchtowerAccess: 1) organization_members
  queryBuilder.then.mockImplementationOnce((resolve: any) =>
    resolve({ data: [{ organization_id: 'org-1' }], error: null })
  );
  // 2) dependencies by name
  queryBuilder.single.mockResolvedValueOnce({ data: { id: 'dep-1' }, error: null });
  // 3) organization_watchlist
  queryBuilder.then.mockImplementationOnce((resolve: any) =>
    resolve({ data: [{ organization_id: 'org-1' }], error: null })
  );
  // 4) watched_packages
  queryBuilder.single.mockResolvedValueOnce({ data: { id: 'wp-1' }, error: null });
}

function setupWatchtowerAccessDeniedNoOrgs() {
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  queryBuilder.then.mockImplementationOnce((resolve: any) =>
    resolve({ data: [], error: null })
  );
}

function setupWatchtowerAccessDeniedNotOnWatchlist() {
  (supabase.auth.getUser as jest.Mock).mockResolvedValue({
    data: { user: mockUser },
    error: null,
  });
  queryBuilder.then.mockImplementationOnce((resolve: any) =>
    resolve({ data: [{ organization_id: 'org-1' }], error: null })
  );
  queryBuilder.single.mockResolvedValueOnce({ data: { id: 'dep-1' }, error: null });
  queryBuilder.then.mockImplementationOnce((resolve: any) =>
    resolve({ data: [], error: null })
  );
}

describe('Watchtower Routes', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    queryBuilder.single.mockReset();
    queryBuilder.then.mockReset();
    queryBuilder.maybeSingle.mockReset();
    queryBuilder.single.mockResolvedValue({ data: {}, error: null });
    queryBuilder.maybeSingle.mockResolvedValue({ data: {}, error: null });
    queryBuilder.then.mockImplementation((resolve: any) => resolve({ data: [], error: null }));
  });

  describe('GET /api/watchtower/:packageName/summary', () => {
    it('returns 401 when not authenticated', async () => {
      (supabase.auth.getUser as jest.Mock).mockResolvedValue({
        data: { user: null },
        error: null,
      });

      const res = await request(app)
        .get(`/api/watchtower/${encodeURIComponent(packageName)}/summary`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(401);
    });

    it('returns 404 when user has no org with package on watchlist', async () => {
      setupWatchtowerAccessDeniedNotOnWatchlist();

      const res = await request(app)
        .get(`/api/watchtower/${encodeURIComponent(packageName)}/summary`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(404);
      expect(res.body.error).toMatch(/not being watched|not found/i);
    });

    it('returns 200 and summary when user has access', async () => {
      setupWatchtowerAccessGranted();
      // Summary handler: watched_packages with dependencies join (one .single())
      queryBuilder.single.mockResolvedValueOnce({
        data: {
          id: 'wp-1',
          status: 'ready',
          dependency_id: 'dep-1',
          dependencies: { name: packageName, latest_version: '4.18.0', latest_release_date: '2025-01-01' },
        },
        error: null,
      });
      // Promise.all: 3 count queries (each uses .then()), 1 top anomaly (.single())
      queryBuilder.then
        .mockImplementationOnce((resolve: any) => resolve({ data: null, error: null, count: 10 }))
        .mockImplementationOnce((resolve: any) => resolve({ data: null, error: null, count: 3 }))
        .mockImplementationOnce((resolve: any) => resolve({ data: null, error: null, count: 1 }));
      queryBuilder.single.mockResolvedValueOnce({
        data: { anomaly_score: 0.5 },
        error: null,
      });

      const res = await request(app)
        .get(`/api/watchtower/${encodeURIComponent(packageName)}/summary`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.name).toBe(packageName);
      expect(res.body.status).toBe('ready');
      expect(res.body.latest_version).toBe('4.18.0');
      expect(res.body.commits_count).toBe(10);
    });
  });

  describe('GET /api/watchtower/:packageName (full analysis)', () => {
    it('returns 403 when user has no org memberships', async () => {
      setupWatchtowerAccessDeniedNoOrgs();

      const res = await request(app)
        .get(`/api/watchtower/${encodeURIComponent(packageName)}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(403);
    });

    it('returns 200 and analysis when access granted', async () => {
      setupWatchtowerAccessGranted();
      queryBuilder.single.mockResolvedValueOnce({
        data: {
          id: 'wp-1',
          status: 'ready',
          dependency_id: 'dep-1',
          dependencies: {
            name: packageName,
            license: 'MIT',
            openssf_score: 80,
            weekly_downloads: 1e6,
            last_published_at: null,
          },
        },
        error: null,
      });

      const res = await request(app)
        .get(`/api/watchtower/${encodeURIComponent(packageName)}`)
        .set('Authorization', `Bearer ${mockToken}`);

      expect(res.status).toBe(200);
      expect(res.body.name).toBe(packageName);
      expect(res.body.status).toBe('ready');
      expect(res.body.license).toBe('MIT');
    });
  });
});
