/**
 * Regression guard for the "always clones default_branch" bug.
 *
 * The worker historically cloned `job.default_branch` and ignored the scan
 * job's requested `branch` / `commit_sha`, so a webhook push to a non-default
 * branch (or a pinned-SHA re-scan) silently scanned the wrong tree. These tests
 * lock the ref/SHA selection in cloneByProvider:
 *   - prefer job.branch over job.default_branch
 *   - thread job.commit_sha through to the clone (which checks it out)
 * across all three providers (github / gitlab / bitbucket).
 *
 * NOTE on the payload->ExtractionJob mapping (index.ts processExtractionJob):
 * that is a trivial field copy (`branch: payload.branch`, `commit_sha:
 * payload.commit_sha`) verified by tsc. The load-bearing behavior — that those
 * fields actually steer the clone — is what's exercised here.
 */

process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

const mockCloneRepository = jest.fn().mockResolvedValue('/tmp/gh-clone');
const mockCheckoutCommit = jest.fn().mockResolvedValue(undefined);
jest.mock('../github', () => ({
  cloneRepository: (...a: unknown[]) => mockCloneRepository(...a),
  cleanupRepository: jest.fn(),
  checkoutCommit: (...a: unknown[]) => mockCheckoutCommit(...a),
}));

// Mock simple-git so the gitlab/bitbucket internal cloneWithToken path captures
// the clone args without shelling out to a real `git clone`.
const mockClone = jest.fn().mockResolvedValue(undefined);
jest.mock('simple-git', () => ({
  __esModule: true,
  default: jest.fn(() => ({ clone: (...a: unknown[]) => mockClone(...a) })),
}));

// getIntegrationToken() reads from Supabase for non-github providers.
const mockSingle = jest.fn();
const mockSupabase = {
  from: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  single: (...a: unknown[]) => mockSingle(...a),
};
jest.mock('@supabase/supabase-js', () => ({
  createClient: jest.fn(() => mockSupabase),
}));

import { cloneByProvider } from '../clone';

const baseJob = {
  projectId: 'p',
  organizationId: 'o',
  repo_full_name: 'owner/repo',
  installation_id: '123',
  default_branch: 'main',
} as any;

describe('cloneByProvider branch/commit selection', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockCloneRepository.mockResolvedValue('/tmp/gh-clone');
    mockClone.mockResolvedValue(undefined);
  });

  describe('github', () => {
    it('clones default_branch when no branch/commit requested', async () => {
      await cloneByProvider({ ...baseJob });
      expect(mockCloneRepository).toHaveBeenCalledWith('123', 'owner/repo', 'main', undefined);
    });

    it('prefers the requested branch over default_branch (non-default push)', async () => {
      await cloneByProvider({ ...baseJob, branch: 'feature/x' });
      expect(mockCloneRepository).toHaveBeenCalledWith('123', 'owner/repo', 'feature/x', undefined);
    });

    it('threads the requested commit_sha through to the clone', async () => {
      await cloneByProvider({ ...baseJob, branch: 'feature/x', commit_sha: 'deadbeef' });
      expect(mockCloneRepository).toHaveBeenCalledWith('123', 'owner/repo', 'feature/x', 'deadbeef');
    });

    it('falls back to default_branch but still pins the commit when only commit_sha is set', async () => {
      await cloneByProvider({ ...baseJob, commit_sha: 'cafef00d' });
      expect(mockCloneRepository).toHaveBeenCalledWith('123', 'owner/repo', 'main', 'cafef00d');
    });
  });

  describe('gitlab', () => {
    beforeEach(() => {
      mockSingle.mockResolvedValue({
        data: { access_token: 'tok', provider: 'gitlab', metadata: {} },
        error: null,
      });
    });

    it('clones the requested branch and checks out the requested commit', async () => {
      await cloneByProvider({
        ...baseJob,
        provider: 'gitlab',
        integration_id: 'int1',
        branch: 'feature/y',
        commit_sha: 'abc123',
      });
      const cloneArgs = mockClone.mock.calls[0];
      // simple-git clone(repoUrl, targetDir, optionsArray)
      expect(cloneArgs[2]).toEqual(['--branch', 'feature/y', '--depth', '1', '--single-branch']);
      expect(mockCheckoutCommit).toHaveBeenCalledWith(expect.any(String), 'abc123');
    });

    it('falls back to default_branch and skips checkout when nothing is pinned', async () => {
      await cloneByProvider({ ...baseJob, provider: 'gitlab', integration_id: 'int1' });
      const cloneArgs = mockClone.mock.calls[0];
      expect(cloneArgs[2]).toEqual(['--branch', 'main', '--depth', '1', '--single-branch']);
      expect(mockCheckoutCommit).not.toHaveBeenCalled();
    });
  });

  describe('bitbucket', () => {
    beforeEach(() => {
      mockSingle.mockResolvedValue({
        data: { access_token: 'tok', provider: 'bitbucket', metadata: {} },
        error: null,
      });
    });

    it('clones the requested branch', async () => {
      await cloneByProvider({
        ...baseJob,
        provider: 'bitbucket',
        integration_id: 'int2',
        branch: 'release/1.0',
      });
      const cloneArgs = mockClone.mock.calls[0];
      expect(cloneArgs[2]).toEqual(['--branch', 'release/1.0', '--depth', '1', '--single-branch']);
      expect(mockCheckoutCommit).not.toHaveBeenCalled();
    });
  });
});
