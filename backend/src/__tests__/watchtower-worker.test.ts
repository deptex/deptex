/**
 * Tests for watchtower-worker processNewVersionJob and runAutoBumpPrLogic.
 * Covers scenarios W1–W14 and E from test.md.
 */

// Mock environment so the module can be imported without Redis
process.env.NODE_ENV = 'test';
process.env.UPSTASH_REDIS_URL = '';
process.env.UPSTASH_REDIS_TOKEN = '';

// ── Mock all external dependencies BEFORE importing the module ──────────────
// Use explicit factories to prevent loading real modules with problematic deps (oxc-parser ESM)

const mockAnalyzePackage = jest.fn();
const mockAnalyzePackageVersion = jest.fn();
const mockCleanupTempDir = jest.fn();

jest.mock('../../watchtower-worker/src/analyzer', () => ({
  analyzePackage: mockAnalyzePackageVersion, // not used in these tests but needed for module shape
  analyzePackageVersion: mockAnalyzePackageVersion,
  cleanupTempDir: mockCleanupTempDir,
}));

const mockGetCandidates = jest.fn();
const mockGetLatestVersion = jest.fn();
const mockGetLatestReleaseDate = jest.fn();
const mockGetWatchlistRow = jest.fn();
const mockUpdateQuarantineNext = jest.fn();
const mockClearQuarantine = jest.fn();
const mockSetLatestAllowed = jest.fn();
const mockSetVersionError = jest.fn();
const mockUpdateAnalysis = jest.fn();
const mockUpdateWatchedPackageStatus = jest.fn();
const mockUpdateWatchedPackageResults = jest.fn();
const mockUpsertAnalysis = jest.fn();
const mockGetDepIdForWatched = jest.fn();
const mockGetDepVersionRowId = jest.fn();
const mockSetProjectDepVersionId = jest.fn();
const mockStoreCommits = jest.fn();
const mockStoreContributors = jest.fn();
const mockStoreAnomalies = jest.fn();
const mockGetDependencyVulnerabilities = jest.fn();

jest.mock('../../watchtower-worker/src/storage', () => ({
  updateWatchedPackageStatus: mockUpdateWatchedPackageStatus,
  updateWatchedPackageResults: mockUpdateWatchedPackageResults,
  upsertDependencyVersionAnalysis: mockUpsertAnalysis,
  getDependencyIdForWatchedPackage: mockGetDepIdForWatched,
  getDependencyVersionRowId: mockGetDepVersionRowId,
  setProjectDependencyVersionId: mockSetProjectDepVersionId,
  storePackageCommits: mockStoreCommits,
  storeContributorProfiles: mockStoreContributors,
  storeAnomalies: mockStoreAnomalies,
  updateDependencyVersionAnalysis: mockUpdateAnalysis,
  getCandidateProjectsForAutoBump: mockGetCandidates,
  getDependencyLatestVersion: mockGetLatestVersion,
  getDependencyLatestReleaseDate: mockGetLatestReleaseDate,
  getWatchlistRow: mockGetWatchlistRow,
  updateWatchlistQuarantineNextRelease: mockUpdateQuarantineNext,
  updateWatchlistClearQuarantineAndSetLatest: mockClearQuarantine,
  updateWatchlistSetLatestAllowed: mockSetLatestAllowed,
  setDependencyVersionError: mockSetVersionError,
  getDependencyVulnerabilities: mockGetDependencyVulnerabilities,
}));

const mockCreatePr = jest.fn();

jest.mock('../../watchtower-worker/src/create-bump-pr', () => ({
  createBumpPrForProject: mockCreatePr,
}));

// Now safe to import — all problematic transitive deps are mocked
import {
  processNewVersionJob,
  runAutoBumpPrLogic,
  type NewVersionJob,
} from '../../watchtower-worker/src/index';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makePassingAnalysis() {
  return {
    success: true,
    tmpDir: '/tmp/test',
    data: {
      name: 'lodash',
      latestVersion: '4.18.0',
      publishedAt: null,
      hasInstallScripts: false,
      registryIntegrity: {} as any,
      scriptCapabilities: {} as any,
      entropyAnalysis: {} as any,
      commitsAnalyzed: 0,
      contributorsFound: 0,
      anomaliesDetected: 0,
      topAnomalyScore: 0,
      registryIntegrityStatus: 'pass' as const,
      installScriptsStatus: 'pass' as const,
      entropyAnalysisStatus: 'pass' as const,
      maintainerAnalysisStatus: 'pass' as const,
    },
  };
}

function makeFailingAnalysis(field: 'registryIntegrityStatus' | 'installScriptsStatus' | 'entropyAnalysisStatus') {
  const analysis = makePassingAnalysis();
  (analysis.data as any)[field] = 'fail';
  return analysis;
}

const baseJob: NewVersionJob = {
  type: 'new_version',
  dependency_id: 'dep-1',
  name: 'lodash',
  new_version: '4.18.0',
  latest_release_date: '2025-06-01T00:00:00Z',
};

// ── Test suites ──────────────────────────────────────────────────────────────

describe('processNewVersionJob', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockCleanupTempDir.mockImplementation(() => {});
    mockGetCandidates.mockResolvedValue([]);
    mockUpdateAnalysis.mockResolvedValue(undefined);
    mockSetVersionError.mockResolvedValue(undefined);
    mockGetDependencyVulnerabilities.mockResolvedValue([]);
  });

  // W1: new_version – analysis fails (registry)
  it('W1a: should not create PR when registry integrity fails', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makeFailingAnalysis('registryIntegrityStatus'));

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(false);
    expect(result.error).toContain('checks failed');
    expect(mockSetVersionError).toHaveBeenCalledWith('dep-1', '4.18.0', expect.stringContaining('registry=fail'));
    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W1: new_version – analysis fails (install scripts)
  it('W1b: should not create PR when install scripts check fails', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makeFailingAnalysis('installScriptsStatus'));

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(false);
    expect(mockSetVersionError).toHaveBeenCalled();
    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W1: new_version – analysis fails (entropy)
  it('W1c: should not create PR when entropy analysis fails', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makeFailingAnalysis('entropyAnalysisStatus'));

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(false);
    expect(mockSetVersionError).toHaveBeenCalled();
    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W1: new_version – analysis itself errors (success: false)
  it('W1d: should not create PR when analysis returns success=false', async () => {
    mockAnalyzePackageVersion.mockResolvedValue({
      success: false,
      error: 'npm fetch failed',
      tmpDir: '/tmp/test',
    });

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(false);
    expect(result.error).toBe('npm fetch failed');
    expect(mockSetVersionError).toHaveBeenCalledWith('dep-1', '4.18.0', 'npm fetch failed');
    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W2: new_version – analysis passes → calls runAutoBumpPrLogic
  it('W2: should proceed to auto-bump logic when analysis passes', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makePassingAnalysis());
    mockGetCandidates.mockResolvedValue([]);

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(true);
    expect(mockUpdateAnalysis).toHaveBeenCalled();
    expect(mockGetCandidates).toHaveBeenCalledWith('dep-1', 'lodash');
  });

  // Target version vulnerable → skip auto-bump (do not create PR)
  it('should skip auto-bump when target version is affected by a known vulnerability', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makePassingAnalysis());
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockGetDependencyVulnerabilities.mockResolvedValue([
      {
        osv_id: 'GHSA-xxx',
        affected_versions: [{ versions: ['4.18.0'] }],
        fixed_versions: [],
      },
    ]);

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(true);
    expect(mockCreatePr).not.toHaveBeenCalled();
    expect(mockGetDependencyVulnerabilities).toHaveBeenCalledWith('dep-1');
  });

  // Target in affected range but also in fixed_versions (patched) → not vulnerable, create PR
  it('should create PR when target version is in affected range but is fixed (fixed_versions)', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makePassingAnalysis());
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr.mockResolvedValue({ pr_url: 'https://github.com/org/repo/pull/1', pr_number: 1 });
    // Range: affected < 4.18.0, fixed in 4.18.0 — so 4.18.0 is NOT vulnerable
    mockGetDependencyVulnerabilities.mockResolvedValue([
      {
        osv_id: 'GHSA-yyy',
        affected_versions: [
          { ranges: [{ events: [{ introduced: '0.0.0', fixed: '4.18.0' }] }] },
        ],
        fixed_versions: ['4.18.0'],
      },
    ]);

    const result = await processNewVersionJob(baseJob);

    expect(result.success).toBe(true);
    expect(mockCreatePr).toHaveBeenCalled();
  });

  // W3: quarantine_expired – no latest_version in DB
  it('W3: should skip when quarantine_expired has no latest_version', async () => {
    mockGetLatestVersion.mockResolvedValue(null);

    const result = await processNewVersionJob({
      type: 'quarantine_expired',
      dependency_id: 'dep-1',
      name: 'lodash',
    });

    expect(result.success).toBe(false);
    expect(result.error).toBe('No latest_version');
    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W3b: quarantine_expired – has latest_version → uses it
  it('W3b: should use latest_version as target for quarantine_expired', async () => {
    mockGetLatestVersion.mockResolvedValue('4.18.0');
    mockGetCandidates.mockResolvedValue([]);

    const result = await processNewVersionJob({
      type: 'quarantine_expired',
      dependency_id: 'dep-1',
      name: 'lodash',
    });

    expect(result.success).toBe(true);
    // Should NOT run analysis for quarantine_expired
    expect(mockAnalyzePackageVersion).not.toHaveBeenCalled();
    expect(mockGetCandidates).toHaveBeenCalledWith('dep-1', 'lodash');
  });

  // Edge: missing new_version field
  it('should fail when new_version job has no version', async () => {
    const result = await processNewVersionJob({
      type: 'new_version',
      dependency_id: 'dep-1',
      name: 'lodash',
    });

    expect(result.success).toBe(false);
    expect(result.error).toBe('Missing new_version');
  });

  // Cleanup: tmpDir is always cleaned
  it('should cleanup tmpDir even when analysis fails', async () => {
    mockAnalyzePackageVersion.mockResolvedValue(makeFailingAnalysis('registryIntegrityStatus'));

    await processNewVersionJob(baseJob);

    expect(mockCleanupTempDir).toHaveBeenCalledWith('/tmp/test');
  });
});

describe('runAutoBumpPrLogic', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockUpdateQuarantineNext.mockResolvedValue(undefined);
    mockClearQuarantine.mockResolvedValue(undefined);
    mockSetLatestAllowed.mockResolvedValue(undefined);
  });

  // W4: No candidates
  it('W4: should do nothing when no candidate projects exist', async () => {
    mockGetCandidates.mockResolvedValue([]);

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockCreatePr).not.toHaveBeenCalled();
    expect(mockGetWatchlistRow).not.toHaveBeenCalled();
  });

  // Zombie / removal PR: getCandidateProjectsForAutoBump excludes zombies and projects with removal PR
  it('should not create bump PR when all candidates are zombies or have removal PR (storage returns empty)', async () => {
    mockGetCandidates.mockResolvedValue([]);

    await runAutoBumpPrLogic('dep-1', 'some-pkg', '2.0.0', null);

    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W5/W6: Has candidates, not in watchlist → create PR
  it('W6: should create PR when candidate is not in watchlist', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr.mockResolvedValue({ pr_url: 'https://github.com/org/repo/pull/1', pr_number: 1 });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockCreatePr).toHaveBeenCalledWith('org-1', 'proj-1', 'lodash', '4.18.0', '4.17.21');
  });

  // W7: In watchlist, quarantine_next_release = true → sets quarantine, no PR
  it('W7: should set quarantine and skip PR when quarantine_next_release is true', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue({
      id: 'wl-1',
      organization_id: 'org-1',
      dependency_id: 'dep-1',
      quarantine_next_release: true,
      is_current_version_quarantined: false,
      quarantine_until: null,
      latest_allowed_version: null,
    });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', '2025-06-01T00:00:00Z');

    expect(mockUpdateQuarantineNext).toHaveBeenCalledWith('wl-1', expect.any(String));
    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // W8: In watchlist, current quarantined, not expired → skip
  it('W8: should skip when current version is quarantined and not expired', async () => {
    const futureDate = new Date(Date.now() + 3 * 24 * 60 * 60 * 1000).toISOString();
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue({
      id: 'wl-1',
      organization_id: 'org-1',
      dependency_id: 'dep-1',
      quarantine_next_release: false,
      is_current_version_quarantined: true,
      quarantine_until: futureDate,
      latest_allowed_version: null,
    });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockCreatePr).not.toHaveBeenCalled();
    expect(mockClearQuarantine).not.toHaveBeenCalled();
  });

  // W9: In watchlist, current quarantined, expired → clear quarantine, set latest, create PR
  it('W9: should clear quarantine and create PR when quarantine has expired', async () => {
    const pastDate = new Date(Date.now() - 1 * 24 * 60 * 60 * 1000).toISOString();
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue({
      id: 'wl-1',
      organization_id: 'org-1',
      dependency_id: 'dep-1',
      quarantine_next_release: false,
      is_current_version_quarantined: true,
      quarantine_until: pastDate,
      latest_allowed_version: null,
    });
    mockCreatePr.mockResolvedValue({ pr_url: 'https://github.com/org/repo/pull/2', pr_number: 2 });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockClearQuarantine).toHaveBeenCalledWith('wl-1', '4.18.0');
    expect(mockCreatePr).toHaveBeenCalled();
  });

  // W10: In watchlist, normal (not quarantined) → set latest_allowed_version, create PR
  it('W10: should set latest_allowed and create PR when in watchlist without quarantine', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue({
      id: 'wl-1',
      organization_id: 'org-1',
      dependency_id: 'dep-1',
      quarantine_next_release: false,
      is_current_version_quarantined: false,
      quarantine_until: null,
      latest_allowed_version: '4.17.21',
    });
    mockCreatePr.mockResolvedValue({ pr_url: 'https://github.com/org/repo/pull/3', pr_number: 3 });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockSetLatestAllowed).toHaveBeenCalledWith('wl-1', '4.18.0');
    expect(mockCreatePr).toHaveBeenCalledWith('org-1', 'proj-1', 'lodash', '4.18.0', '4.17.21');
  });

  // W11: PR already recorded → createBumpPrForProject returns existing
  it('W11: should handle existing PR gracefully', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr.mockResolvedValue({ pr_url: 'https://github.com/org/repo/pull/99', pr_number: 99, already_exists: true });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockCreatePr).toHaveBeenCalled();
  });

  // W12: createBumpPrForProject returns error (no GitHub App)
  it('W12: should log warning when createBumpPrForProject returns no GitHub App error', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr.mockResolvedValue({ error: 'no GitHub App' });

    // Should not throw
    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);
    expect(mockCreatePr).toHaveBeenCalled();
  });

  // W13: no GitHub repository error
  it('W13: should handle no GitHub repository error', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr.mockResolvedValue({ error: 'no GitHub repository' });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);
    expect(mockCreatePr).toHaveBeenCalled();
  });

  // W14: transitive-only error
  it('W14: should handle transitive-only error', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr.mockResolvedValue({ error: 'dependency is transitive' });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);
    expect(mockCreatePr).toHaveBeenCalled();
  });

  // E: Project auto_bump = false → not a candidate (getCandidateProjectsForAutoBump filters them)
  it('E: should not create PR when auto_bump=false (no candidates returned)', async () => {
    mockGetCandidates.mockResolvedValue([]);

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockCreatePr).not.toHaveBeenCalled();
  });

  // Multiple candidates: mixed watchlist states
  it('W5: should process each candidate independently', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.20' },
      { project_id: 'proj-2', organization_id: 'org-2', current_version: '4.17.19' },
    ]);

    // org-1: in watchlist, quarantine next
    mockGetWatchlistRow
      .mockResolvedValueOnce({
        id: 'wl-1',
        organization_id: 'org-1',
        dependency_id: 'dep-1',
        quarantine_next_release: true,
        is_current_version_quarantined: false,
        quarantine_until: null,
        latest_allowed_version: null,
      })
      // org-2: not in watchlist
      .mockResolvedValueOnce(null);

    mockCreatePr.mockResolvedValue({ pr_url: 'https://github.com/org/repo/pull/5', pr_number: 5 });

    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', '2025-06-01T00:00:00Z');

    // proj-1 quarantined → no PR
    expect(mockUpdateQuarantineNext).toHaveBeenCalledWith('wl-1', expect.any(String));
    // proj-2 not in watchlist → PR created
    expect(mockCreatePr).toHaveBeenCalledTimes(1);
    expect(mockCreatePr).toHaveBeenCalledWith('org-2', 'proj-2', 'lodash', '4.18.0', '4.17.19');
  });

  // createBumpPrForProject throws → should not crash
  it('should handle createBumpPrForProject throwing an error gracefully', async () => {
    mockGetCandidates.mockResolvedValue([
      { project_id: 'proj-1', organization_id: 'org-1', current_version: '4.17.21' },
      { project_id: 'proj-2', organization_id: 'org-2', current_version: '4.17.21' },
    ]);
    mockGetWatchlistRow.mockResolvedValue(null);
    mockCreatePr
      .mockRejectedValueOnce(new Error('Network error'))
      .mockResolvedValueOnce({ pr_url: 'https://github.com/org/repo/pull/6', pr_number: 6 });

    // Should not throw
    await runAutoBumpPrLogic('dep-1', 'lodash', '4.18.0', null);

    expect(mockCreatePr).toHaveBeenCalledTimes(2);
  });
});
