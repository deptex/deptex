// Amend-mode commit/push behaviour with child_process fully scripted: an
// empty STAGED diff is NOT proof there's nothing to push — a prior amend
// attempt may have already committed locally and failed only at the push;
// retrying then stages nothing, and returning noChanges would silently drop
// the user's fix. Only when BOTH the staged diff and the
// origin/<branch>..HEAD ahead-count are empty is the amend a true no-op.

jest.mock('child_process', () => ({ execSync: jest.fn(), spawnSync: jest.fn() }));

import { execSync, spawnSync } from 'child_process';
import { commitAndPushFix } from '../pr';

const logger = { info: jest.fn(async () => {}), warn: jest.fn(), error: jest.fn(), success: jest.fn() } as any;
const plan = {
  summary: 's',
  finding: { type: 'vulnerability', id: 'CVE-1' },
  description: 'd',
  fileChanges: [],
  testCommand: '',
  language: 'other',
  estimatedDiffSize: 'medium',
  wallClockBudgetSec: 0,
} as any;

/** Script execSync by first-match-wins substring; unmatched commands return ''. */
function scriptExec(map: Array<[string, string]>) {
  (execSync as jest.Mock).mockImplementation((cmd: string) => {
    for (const [key, out] of map) if (String(cmd).includes(key)) return out;
    return '';
  });
}

function amendOpts() {
  return {
    workDir: '/work/fix-1',
    fixId: 'fix-1',
    plan,
    installationToken: 'tok',
    repoFullName: 'o/r',
    baseBranch: 'main',
    logger,
    mode: 'amend' as const,
    existingBranch: 'aegis/prior',
  };
}

function execCmds(): string[] {
  return (execSync as jest.Mock).mock.calls.map((c) => String(c[0]));
}

afterEach(() => jest.clearAllMocks());

describe('commitAndPushFix — amend mode', () => {
  test('empty staged diff + unpushed local commit → pushes WITHOUT re-committing (noChanges false)', async () => {
    scriptExec([
      ['diff --cached --stat', ''],
      ['rev-list --count', '1\n'],
      ['diff --stat', ' package.json | 2 +-\n 1 file changed'],
    ]);
    (spawnSync as jest.Mock).mockReturnValue({ status: 0, stdout: '', stderr: 'pushed to aegis/prior' });
    const res = await commitAndPushFix(amendOpts());
    expect(res.noChanges).toBe(false);
    expect(res.prBranch).toBe('aegis/prior');
    // The diff summary comes from the committed (unpushed) range, not staging.
    expect(res.diffSummary).toContain('package.json');
    expect(spawnSync).toHaveBeenCalledWith('git', ['push', 'origin', 'aegis/prior'], expect.anything());
    // The already-committed change must NOT be committed a second time.
    expect(execCmds().some((c) => c.includes('commit -F'))).toBe(false);
  });

  test('empty staged diff + nothing unpushed → true noChanges, no commit, no push', async () => {
    scriptExec([
      ['diff --cached --stat', ''],
      ['rev-list --count', '0\n'],
    ]);
    const res = await commitAndPushFix(amendOpts());
    expect(res.noChanges).toBe(true);
    expect(res.diffSummary).toBe('');
    expect(spawnSync).not.toHaveBeenCalled();
    expect(execCmds().some((c) => c.includes('commit -F'))).toBe(false);
  });

  test('an unreadable ahead-count degrades to noChanges (matches the old behaviour)', async () => {
    scriptExec([['diff --cached --stat', '']]);
    (execSync as jest.Mock).mockImplementation((cmd: string) => {
      if (String(cmd).includes('rev-list --count')) throw new Error('unknown revision');
      return '';
    });
    const res = await commitAndPushFix(amendOpts());
    expect(res.noChanges).toBe(true);
    expect(spawnSync).not.toHaveBeenCalled();
  });

  test('staged changes commit then push (normal amend)', async () => {
    scriptExec([['diff --cached --stat', ' index.js | 1 +']]);
    (spawnSync as jest.Mock).mockReturnValue({ status: 0, stdout: '', stderr: 'ok' });
    const res = await commitAndPushFix(amendOpts());
    expect(res.noChanges).toBe(false);
    expect(res.diffSummary).toContain('index.js');
    expect(execCmds().some((c) => c.includes('commit -F'))).toBe(true);
    // No -u / --set-upstream: the clone is the branch head, the push fast-forwards.
    expect(spawnSync).toHaveBeenCalledWith('git', ['push', 'origin', 'aegis/prior'], expect.anything());
  });
});
