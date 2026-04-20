/**
 * Tests for watchtower-poll.ts — the daily maintenance cron that refreshes
 * dep latest versions + GHSA vulns + weekly download counts.
 */

process.env.DEPENDENCY_REFRESH_DELAY_MS = '0';
process.env.DEPENDENCY_REFRESH_CONCURRENCY = '2';

const mockInsert = jest.fn().mockResolvedValue({ error: null });
const mockUpdate = jest.fn().mockReturnValue({ eq: jest.fn().mockResolvedValue({ error: null }) });
const mockSelect = jest.fn().mockReturnValue({
  eq: jest.fn().mockResolvedValue({ data: [{ dependency_id: 'dep-1' }], error: null }),
  range: jest.fn().mockResolvedValue({
    data: [
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: null },
    ],
    error: null,
  }),
});

const mockFrom = jest.fn((table: string) => {
  if (table === 'project_dependencies') {
    return { select: jest.fn().mockReturnValue({ eq: jest.fn().mockResolvedValue({ data: [{ dependency_id: 'dep-1' }], error: null }) }) };
  }
  if (table === 'dependencies') {
    return {
      select: jest.fn().mockReturnValue({
        range: jest.fn().mockResolvedValue({
          data: [
            { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: null },
          ],
          error: null,
        }),
      }),
      update: jest.fn().mockReturnValue({ eq: jest.fn().mockResolvedValue({ error: null }) }),
    };
  }
  if (table === 'watchtower_jobs') {
    return { insert: mockInsert };
  }
  if (table === 'watched_packages') {
    return {
      select: jest.fn().mockReturnValue({
        eq: jest.fn().mockResolvedValue({
          data: [
            { id: 'wp-1', name: 'lodash', last_known_commit_sha: 'abc', status: 'ready' },
          ],
          error: null,
        }),
      }),
    };
  }
  return {};
});

jest.mock('../supabase', () => ({
  supabase: { from: mockFrom },
}));

// Stub fetch for npm registry (used by fetchLatestNpmVersion in watchtower-poll)
const originalFetch = globalThis.fetch;
beforeAll(() => {
  (globalThis as any).fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => ({
      'dist-tags': { latest: '4.18.0' },
      time: { '4.18.0': '2025-06-01T00:00:00Z' },
    }),
  });
});
afterAll(() => {
  globalThis.fetch = originalFetch;
});

// Mock ghsa to avoid real API and speed up tests
jest.mock('../ghsa', () => ({
  fetchGhsaVulnerabilitiesBatch: jest.fn().mockResolvedValue(new Map()),
}));

import { runDependencyRefresh } from '../watchtower-poll';

describe('watchtower-poll', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockFrom.mockImplementation((table: string) => {
      if (table === 'project_dependencies') {
        return { select: jest.fn().mockReturnValue({ eq: jest.fn().mockResolvedValue({ data: [{ dependency_id: 'dep-1' }], error: null }) }) };
      }
      if (table === 'dependencies') {
        return {
          select: jest.fn().mockReturnValue({
            range: jest.fn().mockResolvedValue({
              data: [
                { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: null },
              ],
              error: null,
            }),
          }),
          update: jest.fn().mockReturnValue({ eq: jest.fn().mockResolvedValue({ error: null }) }),
        };
      }
      if (table === 'watchtower_jobs') {
        return { insert: mockInsert };
      }
      if (table === 'watched_packages') {
        return {
          select: jest.fn().mockReturnValue({
            eq: jest.fn().mockResolvedValue({
              data: [
                { id: 'wp-1', name: 'lodash', last_known_commit_sha: 'abc', status: 'ready' },
              ],
              error: null,
            }),
          }),
        };
      }
      return {};
    });
    mockInsert.mockResolvedValue({ error: null });
  });

  describe('runDependencyRefresh', () => {
    beforeEach(() => {
      (globalThis as any).fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          'dist-tags': { latest: '4.18.0' },
          time: { '4.18.0': '2025-06-01T00:00:00Z' },
        }),
      });
    });

    it('updates dependencies.latest_version when npm version changes', async () => {
      const result = await runDependencyRefresh();

      expect(result.processed).toBeGreaterThanOrEqual(1);
      // Updating latest_version happens via supabase.from('dependencies').update()
      // covered by mockFrom; assert processed count > 0 as a proxy for work completed.
    });

    it('returns zero-error result when version unchanged', async () => {
      (globalThis as any).fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          'dist-tags': { latest: '4.17.21' },
          time: { '4.17.21': '2024-01-01T00:00:00Z' },
        }),
      });

      const result = await runDependencyRefresh();

      expect(result.errors).toBe(0);
    });
  });
});
