/**
 * Phase 10B: Tests for watchtower-poll.ts (runDependencyRefresh, runPollSweep).
 * Ensures BUG 2+3 fixes: version change enqueues new_version jobs + startWatchtowerMachine;
 * poll sweep enqueues poll_sweep jobs + startWatchtowerMachine.
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

const mockStartWatchtowerMachine = jest.fn().mockResolvedValue('machine-1');
jest.mock('../../../../ee/backend/lib/fly-machines', () => ({
  startWatchtowerMachine: (...args: unknown[]) => mockStartWatchtowerMachine(...args),
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

import { runDependencyRefresh, runPollSweep } from '../watchtower-poll';

describe('watchtower-poll (Phase 10B)', () => {
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

    it('inserts new_version jobs into watchtower_jobs when npm version changes', async () => {
      const result = await runDependencyRefresh();

      expect(result.processed).toBeGreaterThanOrEqual(1);
      expect(result.newVersionJobs).toBe(1);
      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          job_type: 'new_version',
          priority: 1,
          package_name: 'lodash',
          dependency_id: 'dep-1',
          payload: expect.objectContaining({
            type: 'new_version',
            new_version: '4.18.0',
            latest_release_date: '2025-06-01T00:00:00Z',
          }),
        })
      );
      expect(mockStartWatchtowerMachine).toHaveBeenCalled();
    });

    it('does not insert jobs or start machine when version unchanged', async () => {
      (globalThis as any).fetch = jest.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          'dist-tags': { latest: '4.17.21' },
          time: { '4.17.21': '2024-01-01T00:00:00Z' },
        }),
      });

      const result = await runDependencyRefresh();

      expect(result.newVersionJobs).toBe(0);
      expect(mockInsert).not.toHaveBeenCalled();
      expect(mockStartWatchtowerMachine).not.toHaveBeenCalled();
    });

    it('returns newVersionJobs count and does not throw when fly-machines unavailable', async () => {
      mockStartWatchtowerMachine.mockRejectedValueOnce(new Error('FLY_API_TOKEN missing'));
      const result = await runDependencyRefresh();
      expect(result.newVersionJobs).toBe(1);
    });
  });

  describe('runPollSweep', () => {
    it('inserts poll_sweep jobs for each ready watched_packages row', async () => {
      const result = await runPollSweep();

      expect(result.packagesPolled).toBe(1);
      expect(result.jobsQueued).toBe(1);
      expect(mockInsert).toHaveBeenCalledWith([
        expect.objectContaining({
          job_type: 'poll_sweep',
          priority: 5,
          package_name: 'lodash',
          payload: expect.objectContaining({
            watched_package_id: 'wp-1',
            last_known_commit_sha: 'abc',
          }),
        }),
      ]);
      expect(mockStartWatchtowerMachine).toHaveBeenCalled();
    });

    it('returns zeros when no ready watched packages', async () => {
      mockFrom.mockImplementation((table: string) => {
        if (table === 'watched_packages') {
          return {
            select: jest.fn().mockReturnValue({
              eq: jest.fn().mockResolvedValue({ data: [], error: null }),
            }),
          };
        }
        return {};
      });

      const result = await runPollSweep();

      expect(result.packagesPolled).toBe(0);
      expect(result.jobsQueued).toBe(0);
      expect(mockInsert).not.toHaveBeenCalled();
      expect(mockStartWatchtowerMachine).not.toHaveBeenCalled();
    });

    it('returns jobsQueued 0 when insert fails and does not start machine', async () => {
      mockInsert.mockResolvedValueOnce({ error: { message: 'DB error' } });

      const result = await runPollSweep();

      expect(result.packagesPolled).toBe(1);
      expect(result.jobsQueued).toBe(0);
      expect(mockStartWatchtowerMachine).not.toHaveBeenCalled();
    });
  });
});
