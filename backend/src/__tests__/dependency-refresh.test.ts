/**
 * Tests for dependency-refresh (runDependencyRefresh).
 * Covers scenarios P1–P4 from test.md.
 */

// Set fast delay so tests run quickly
process.env.DEPENDENCY_REFRESH_DELAY_MS = '0';
process.env.DEPENDENCY_REFRESH_CONCURRENCY = '1';
// Provide fake env vars so the storage module doesn't throw on import
process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

// ── Mock storage with explicit factory (module has top-level env var check) ──

const mockGetDirectIds = jest.fn();
const mockGetAllDeps = jest.fn();
const mockUpdateLatest = jest.fn();
const mockUpsertVulns = jest.fn();
const mockEnsureVersion = jest.fn();
const mockHasQuarantineExpired = jest.fn();

jest.mock('../../watchtower-poller/src/storage', () => ({
  getDirectDependencyIds: mockGetDirectIds,
  getAllDependencies: mockGetAllDeps,
  updateDependenciesLatestByName: mockUpdateLatest,
  upsertDependencyVulnerabilities: mockUpsertVulns,
  ensureDependencyVersion: mockEnsureVersion,
  hasQuarantineExpiredForDependency: mockHasQuarantineExpired,
  DependencyVulnerabilityInsert: {},
}));

const mockFetchNpm = jest.fn();
const mockFetchVulns = jest.fn();
const mockFetchAdvisories = jest.fn();
const mockProcessVuln = jest.fn();
const mockProcessAdvisory = jest.fn();

jest.mock('../../watchtower-poller/src/osv-checker', () => ({
  fetchLatestNpmVersion: mockFetchNpm,
  fetchAllPackageVulnerabilities: mockFetchVulns,
  fetchNpmAdvisories: mockFetchAdvisories,
  processVulnerability: mockProcessVuln,
  processNpmAdvisory: mockProcessAdvisory,
}));

const mockEnqueueJob = jest.fn();

jest.mock('../../watchtower-poller/src/scheduler', () => ({
  enqueueNewVersionJob: mockEnqueueJob,
}));

const mockFetchGhsaBatch = jest.fn();
jest.mock('../../watchtower-poller/src/ghsa', () => ({
  fetchGhsaVulnerabilitiesBatch: mockFetchGhsaBatch,
  ghsaVulnToInsert: (depId: string, v: { ghsaId: string }) => ({
    dependency_id: depId,
    osv_id: v.ghsaId,
    severity: 'high',
    summary: null,
    details: null,
    aliases: [],
    affected_versions: null,
    fixed_versions: [],
    published_at: null,
    modified_at: null,
  }),
}));

import { runDependencyRefresh } from '../../watchtower-poller/src/dependency-refresh';

describe('runDependencyRefresh', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUpdateLatest.mockResolvedValue(undefined);
    mockEnsureVersion.mockResolvedValue(undefined);
    mockEnqueueJob.mockResolvedValue(undefined);
    mockHasQuarantineExpired.mockResolvedValue(false);
    mockFetchGhsaBatch.mockResolvedValue(new Map());
  });

  // P1: Version changed → enqueue new_version job
  it('P1: should enqueue new_version job when npm version changes', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.18.0',
      publishedAt: '2025-06-01T00:00:00Z',
    });

    await runDependencyRefresh();

    expect(mockUpdateLatest).toHaveBeenCalledWith('lodash', '4.18.0', '2025-06-01T00:00:00Z');
    expect(mockEnsureVersion).toHaveBeenCalledWith('dep-1', '4.18.0');
    expect(mockEnqueueJob).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'new_version',
        dependency_id: 'dep-1',
        name: 'lodash',
        new_version: '4.18.0',
      })
    );
  });

  // P2: Quarantine expired → enqueue quarantine_expired job
  it('P2: should enqueue quarantine_expired job when quarantine has expired', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    // npm version matches DB → no version change
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.17.21',
      publishedAt: '2025-01-01',
    });
    mockHasQuarantineExpired.mockResolvedValue(true);

    await runDependencyRefresh();

    // Should enqueue quarantine_expired, not new_version
    expect(mockEnqueueJob).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'quarantine_expired',
        dependency_id: 'dep-1',
        name: 'lodash',
      })
    );
    // Should NOT have enqueued new_version since version didn't change
    expect(mockEnqueueJob).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: 'new_version' })
    );
  });

  // P3: No version change, quarantine not expired → no jobs
  it('P3: should not enqueue any jobs when no version change and quarantine not expired', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.17.21',
      publishedAt: '2025-01-01',
    });
    mockHasQuarantineExpired.mockResolvedValue(false);

    await runDependencyRefresh();

    expect(mockEnqueueJob).not.toHaveBeenCalled();
  });

  // P4: Only transitive dependencies → no jobs enqueued
  it('P4: should not enqueue jobs for transitive-only dependencies', async () => {
    // dep-1 is NOT in directIds → transitive only
    mockGetDirectIds.mockResolvedValue(new Set([]));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);

    await runDependencyRefresh();

    // No npm fetch for transitive deps
    expect(mockFetchNpm).not.toHaveBeenCalled();
    expect(mockEnqueueJob).not.toHaveBeenCalled();
  });

  // P1 + P2: Version changed AND quarantine expired should enqueue both
  it('should enqueue both new_version and quarantine_expired when both apply', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.18.0',
      publishedAt: '2025-06-01T00:00:00Z',
    });
    mockHasQuarantineExpired.mockResolvedValue(true);

    await runDependencyRefresh();

    expect(mockEnqueueJob).toHaveBeenCalledTimes(2);
    expect(mockEnqueueJob).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'new_version' })
    );
    expect(mockEnqueueJob).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'quarantine_expired' })
    );
  });

  // Multiple packages: one direct, one transitive
  it('should only process direct dependencies for npm checks', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
      { id: 'dep-2', name: 'express', latest_version: '4.18.0', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.18.0',
      publishedAt: '2025-06-01T00:00:00Z',
    });
    mockHasQuarantineExpired.mockResolvedValue(false);

    await runDependencyRefresh();

    // npm only called for lodash (direct), not express (transitive)
    expect(mockFetchNpm).toHaveBeenCalledTimes(1);
    expect(mockFetchNpm).toHaveBeenCalledWith('lodash');
  });

  // Vuln sync uses GHSA only (batched), not OSV
  it('should call GHSA batch for vulnerability sync, not OSV', async () => {
    mockGetDirectIds.mockResolvedValue(new Set([]));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    mockFetchGhsaBatch.mockResolvedValue(new Map());

    await runDependencyRefresh();

    expect(mockFetchGhsaBatch).toHaveBeenCalledWith(['lodash']);
    expect(mockUpsertVulns).not.toHaveBeenCalled();
  });

  it('should upsert vulns when GHSA returns advisories', async () => {
    mockGetDirectIds.mockResolvedValue(new Set([]));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    mockFetchGhsaBatch.mockResolvedValue(
      new Map([
        [
          'lodash',
          [
            {
              ghsaId: 'GHSA-xxx',
              summary: 'test',
              description: null,
              severity: 'HIGH',
              vulnerableVersionRange: '<4.17.21',
              firstPatchedVersion: '4.17.21',
              publishedAt: null,
              updatedAt: null,
              identifiers: [],
            },
          ],
        ],
      ])
    );

    await runDependencyRefresh();

    expect(mockUpsertVulns).toHaveBeenCalled();
    const inserts = mockUpsertVulns.mock.calls[0][0];
    expect(inserts.length).toBe(1);
    expect(inserts[0].osv_id).toBe('GHSA-xxx');
    expect(inserts[0].dependency_id).toBe('dep-1');
  });

  // P6: Version unchanged, only release date changed → update DB, do NOT enqueue new_version
  it('P6: should update DB when only release date changes, but not enqueue new_version', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.18.0', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.18.0',
      publishedAt: '2025-06-15T00:00:00Z',
    });
    mockHasQuarantineExpired.mockResolvedValue(false);

    await runDependencyRefresh();

    expect(mockUpdateLatest).toHaveBeenCalledWith('lodash', '4.18.0', '2025-06-15T00:00:00Z');
    expect(mockEnqueueJob).not.toHaveBeenCalled();
    expect(mockEnsureVersion).not.toHaveBeenCalled();
  });

  // P7: npm returns null latest (e.g. 404) → no DB update, no new_version job
  it('P7: should not update or enqueue when npm returns no latest version', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'missing-pkg', latest_version: '1.0.0', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({ latestVersion: null, publishedAt: null });
    mockHasQuarantineExpired.mockResolvedValue(false);

    await runDependencyRefresh();

    expect(mockUpdateLatest).not.toHaveBeenCalled();
    expect(mockEnqueueJob).not.toHaveBeenCalledWith(expect.objectContaining({ type: 'new_version' }));
  });

  // P10: One package name with two direct dependency IDs → ensureDependencyVersion for each, one new_version job
  it('P10: should call ensureDependencyVersion for every direct id but enqueue one new_version job', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1', 'dep-2']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
      { id: 'dep-2', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm.mockResolvedValue({
      latestVersion: '4.18.0',
      publishedAt: '2025-06-01T00:00:00Z',
    });
    mockHasQuarantineExpired.mockResolvedValue(false);

    await runDependencyRefresh();

    expect(mockEnsureVersion).toHaveBeenCalledTimes(2);
    expect(mockEnsureVersion).toHaveBeenCalledWith('dep-1', '4.18.0');
    expect(mockEnsureVersion).toHaveBeenCalledWith('dep-2', '4.18.0');
    expect(mockEnqueueJob).toHaveBeenCalledTimes(1);
    expect(mockEnqueueJob).toHaveBeenCalledWith(
      expect.objectContaining({
        type: 'new_version',
        dependency_id: 'dep-1',
        name: 'lodash',
        new_version: '4.18.0',
      })
    );
  });

  // P13: More than 100 unique package names → GHSA in chunks of 100
  it(
    'P13: should chunk GHSA requests into batches of 100 names',
    async () => {
      const names = Array.from({ length: 250 }, (_, i) => `pkg-${i}`);
      mockGetDirectIds.mockResolvedValue(new Set([]));
      mockGetAllDeps.mockResolvedValue(
        names.map((name, i) => ({
          id: `dep-${i}`,
          name,
          latest_version: '1.0.0',
          latest_release_date: null,
        }))
      );
      mockFetchGhsaBatch.mockResolvedValue(new Map());

      await runDependencyRefresh();

      expect(mockFetchGhsaBatch).toHaveBeenCalledTimes(3);
      expect(mockFetchGhsaBatch).toHaveBeenNthCalledWith(1, names.slice(0, 100));
      expect(mockFetchGhsaBatch).toHaveBeenNthCalledWith(2, names.slice(100, 200));
      expect(mockFetchGhsaBatch).toHaveBeenNthCalledWith(3, names.slice(200, 250));
    },
    60000
  );

  // P16: One package throws → others still processed, errors count incremented
  it('P16: should continue and increment errors when one package throws', async () => {
    mockGetDirectIds.mockResolvedValue(new Set(['dep-1', 'dep-2']));
    mockGetAllDeps.mockResolvedValue([
      { id: 'dep-1', name: 'lodash', latest_version: '4.17.21', latest_release_date: '2025-01-01' },
      { id: 'dep-2', name: 'express', latest_version: '4.18.0', latest_release_date: '2025-01-01' },
    ]);
    mockFetchNpm
      .mockResolvedValueOnce({ latestVersion: '4.18.0', publishedAt: '2025-06-01T00:00:00Z' })
      .mockRejectedValueOnce(new Error('npm registry timeout'));
    mockHasQuarantineExpired.mockResolvedValue(false);

    const result = await runDependencyRefresh();

    expect(mockUpdateLatest).toHaveBeenCalledWith('lodash', '4.18.0', '2025-06-01T00:00:00Z');
    expect(mockEnqueueJob).toHaveBeenCalledWith(
      expect.objectContaining({ type: 'new_version', name: 'lodash' })
    );
    expect(result.errors).toBe(1);
  });
});
