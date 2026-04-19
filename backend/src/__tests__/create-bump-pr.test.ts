/**
 * Tests for watchtower-worker create-bump-pr (createBumpPrForProject).
 * B1: 422 + existing open PR → reuse and return that PR.
 * B2: 422 + no open PR → retry with suffixed branch name; if still 422 return clear error.
 * B3: Existing bump PR for same (project, name, target_version) → return existing without creating branch.
 */

process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

const mockUpsert = jest.fn().mockResolvedValue({});
const mockInsert = jest.fn().mockResolvedValue({});

let existingBumpPrData: { pr_url: string; pr_number: number } | null = null;
let watchtowerPrsCallCount = 0;

function makeChain() {
  const c: any = {
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    neq: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn(),
    single: jest.fn(),
    upsert: mockUpsert,
    insert: mockInsert,
  };
  // Supabase chain is thenable when awaited (e.g. oldBumpPrs query)
  c.then = (onFulfilled: (v: { data: any }) => void) =>
    Promise.resolve({ data: [] }).then(onFulfilled);
  return c;
}

const mockFrom = jest.fn((table: string) => {
  const c = makeChain();
  c.maybeSingle.mockImplementation(() => {
    if (table === 'dependencies') {
      return Promise.resolve({ data: { id: 'dep-1' } });
    }
    if (table === 'dependency_prs') {
      watchtowerPrsCallCount++;
      if (watchtowerPrsCallCount === 1) {
        return Promise.resolve({ data: existingBumpPrData });
      }
      return Promise.resolve({ data: [] });
    }
    if (table === 'project_repositories') {
      return Promise.resolve({
        data: { repo_full_name: 'org/repo', default_branch: 'main', installation_id: '123' },
      });
    }
    return Promise.resolve({ data: null });
  });
  c.single.mockImplementation(() => {
    if (table === 'organizations') {
      return Promise.resolve({ data: { github_installation_id: '123' } });
    }
    return Promise.resolve({ data: null });
  });
  return c;
});

jest.mock('../../watchtower-worker/src/supabase', () => ({
  supabase: {
    from: mockFrom,
  },
}));

const mockCreateInstallationToken = jest.fn().mockResolvedValue('ghp_token');
const mockGetBranchSha = jest.fn().mockResolvedValue('abc123');
const mockCreateBranch = jest.fn();
const mockListPullRequestsByHead = jest.fn();
const mockGetRepositoryFileWithSha = jest.fn().mockResolvedValue({ content: '{"dependencies":{"lodash":"^4.17.21"}}', sha: 'f1' });
const mockCreateOrUpdateFileOnBranch = jest.fn().mockResolvedValue(undefined);
const mockCreatePullRequest = jest.fn().mockResolvedValue({ html_url: 'https://github.com/o/r/pull/1', number: 1 });

jest.mock('../../watchtower-worker/src/github-app', () => ({
  createInstallationToken: mockCreateInstallationToken,
  getBranchSha: mockGetBranchSha,
  createBranch: mockCreateBranch,
  listPullRequestsByHead: mockListPullRequestsByHead,
  getRepositoryFileWithSha: mockGetRepositoryFileWithSha,
  createOrUpdateFileOnBranch: mockCreateOrUpdateFileOnBranch,
  createPullRequest: mockCreatePullRequest,
}));

import { createBumpPrForProject } from '../../watchtower-worker/src/create-bump-pr';

describe('createBumpPrForProject', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    watchtowerPrsCallCount = 0;
    existingBumpPrData = null;
    mockCreateBranch.mockResolvedValue(undefined);
    mockListPullRequestsByHead.mockResolvedValue([]);
  });

  // B3: Existing bump PR for same (project, name, target_version) → return existing without creating branch
  it('B3: should return existing PR when one is already recorded for same project/name/target', async () => {
    existingBumpPrData = { pr_url: 'https://github.com/o/r/pull/99', pr_number: 99 };

    const result = await createBumpPrForProject('org-1', 'proj-1', 'lodash', '4.18.0', '4.17.21');

    expect(result).toEqual({ pr_url: 'https://github.com/o/r/pull/99', pr_number: 99 });
    expect(mockCreateBranch).not.toHaveBeenCalled();
  });

  // B1: 422 "Reference already exists" + open PR exists for head → record and return that PR
  it('B1: should reuse existing open PR when branch exists (422) and listPullRequestsByHead returns PR', async () => {
    mockCreateBranch.mockRejectedValue(new Error('422 Reference already exists'));
    mockListPullRequestsByHead.mockResolvedValue([
      { html_url: 'https://github.com/o/r/pull/42', number: 42 },
    ]);

    const result = await createBumpPrForProject('org-1', 'proj-1', 'lodash', '4.18.0', '4.17.21');

    expect(mockListPullRequestsByHead).toHaveBeenCalled();
    expect(mockUpsert).toHaveBeenCalledWith(
      expect.objectContaining({
        project_id: 'proj-1',
        dependency_id: 'dep-1',
        type: 'bump',
        target_version: '4.18.0',
        pr_url: 'https://github.com/o/r/pull/42',
        pr_number: 42,
      }),
      expect.any(Object)
    );
    expect(result).toEqual({ pr_url: 'https://github.com/o/r/pull/42', pr_number: 42 });
    expect(mockCreatePullRequest).not.toHaveBeenCalled();
  });

  // B2: 422 + no open PR → retry with suffixed branch name; if still 422 return clear error
  it('B2: should retry with suffixed branch name when 422 and no open PR, then return error if still 422', async () => {
    mockCreateBranch.mockRejectedValue(new Error('422 Reference already exists'));
    mockListPullRequestsByHead.mockResolvedValue([]);

    const result = await createBumpPrForProject('org-1', 'proj-1', 'lodash', '4.18.0', '4.17.21');

    expect(mockCreateBranch).toHaveBeenCalledTimes(2);
    expect(result).toEqual(
      expect.objectContaining({
        error: expect.stringContaining('branch for this bump already exists'),
      })
    );
  });
});
