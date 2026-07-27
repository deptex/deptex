// cloneBranchHead's base-ref fetch: an amend-mode agent needs origin/<base>
// to compare against or restore files from (the lockfile-heal incident — a
// --single-branch clone of the PR branch has no other refs). The fetch is
// best-effort: a failure degrades to the single-ref clone, never throws.

jest.mock('child_process', () => ({ execSync: jest.fn(), spawnSync: jest.fn() }));

import { execSync, spawnSync } from 'child_process';
import { cloneBranchHead } from '../sandbox';

const logger = {
  info: jest.fn(async () => {}),
  warn: jest.fn(async () => {}),
  error: jest.fn(async () => {}),
  success: jest.fn(async () => {}),
} as any;

const OPTS = {
  workDir: '/work/fix-1',
  installationToken: 'tok',
  repoFullName: 'o/r',
  branch: 'aegis/prior',
  logger,
};

function execCmds(): string[] {
  return (execSync as jest.Mock).mock.calls.map((c) => String(c[0]));
}

afterEach(() => jest.clearAllMocks());

describe('cloneBranchHead — base-ref fetch', () => {
  test('fetches the base branch into refs/remotes/origin/<base> when requested', async () => {
    (spawnSync as jest.Mock).mockReturnValue({ status: 0, stdout: '', stderr: 'cloned' });
    await cloneBranchHead({ ...OPTS, alsoFetchBranch: 'master' });
    expect(
      execCmds().some((c) =>
        c.includes('fetch --depth 1 origin +refs/heads/master:refs/remotes/origin/master'),
      ),
    ).toBe(true);
  });

  test('skips the fetch when alsoFetchBranch is absent or equals the cloned branch', async () => {
    (spawnSync as jest.Mock).mockReturnValue({ status: 0, stdout: '', stderr: 'cloned' });
    await cloneBranchHead({ ...OPTS });
    await cloneBranchHead({ ...OPTS, alsoFetchBranch: 'aegis/prior' });
    // No base-ref FETCH happens (the only execSync calls are the post-clone
    // tokenless-origin rewrite — never a fetch).
    expect(execCmds().some((c) => c.includes('fetch'))).toBe(false);
  });

  test('a failed base-ref fetch warns and degrades — the clone still succeeds', async () => {
    (spawnSync as jest.Mock).mockReturnValue({ status: 0, stdout: '', stderr: 'cloned' });
    (execSync as jest.Mock).mockImplementation(() => {
      throw new Error("couldn't find remote ref refs/heads/master");
    });
    await expect(cloneBranchHead({ ...OPTS, alsoFetchBranch: 'master' })).resolves.toContain('cloned');
    expect(logger.warn).toHaveBeenCalledWith('clone', expect.stringContaining('master'));
  });

  test('a clone failure still throws (the fetch never masks it)', async () => {
    (spawnSync as jest.Mock).mockReturnValue({ status: 128, stdout: '', stderr: 'fatal: repository not found' });
    await expect(cloneBranchHead({ ...OPTS, alsoFetchBranch: 'master' })).rejects.toThrow(/git clone failed/);
    expect(execSync).not.toHaveBeenCalled();
  });
});
