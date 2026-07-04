// Behavioural gates for the autonomous agent's toolbox: the lease fence (a
// requeued run must not double-push), the dup-guard, the terminal writers, and
// secret-diff redaction (the removed line IS the plaintext credential).

import { execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

jest.mock('../pr', () => ({
  commitAndPushFix: jest.fn(async () => ({ prBranch: 'aegis/x', diffSummary: 'd', pushOutput: 'pushed' })),
  openPullRequest: jest.fn(async () => ({ prUrl: 'u', prNumber: 7, prBranch: 'aegis/x', prRepoFullName: 'o/r', diffSummary: 'd' })),
}));
jest.mock('../job-db', () => ({
  markCompleted: jest.fn(async () => {}),
  markFailed: jest.fn(async () => {}),
  markAnswered: jest.fn(async () => {}),
  isJobCancelled: jest.fn(async () => false),
}));
jest.mock('../task-chat', () => ({
  narrateStep: jest.fn(async () => {}),
  postPrReadyCard: jest.fn(async () => {}),
  postFailureCard: jest.fn(async () => {}),
  describeFailure: () => ({ headline: 'h', explanation: 'e', nextStep: 'n', leadIn: 'l', stepLabel: 's' }),
  markTaskFromFix: jest.fn(async () => {}),
  makeTaskNarrator: () => async () => {},
}));
jest.mock('../logger', () => ({ FixLogger: class {} }));

import { buildAgentTools, finalizeFailure, type AgentRunState, type AgentToolDeps } from '../agent/tools';
import { commitAndPushFix, openPullRequest } from '../pr';
import { markCompleted, markFailed, markAnswered } from '../job-db';
import { markTaskFromFix } from '../task-chat';

function fakeSupabase(leaseRow: any) {
  return {
    from: () => ({ select: () => ({ eq: () => ({ single: async () => ({ data: leaseRow }) }) }) }),
  } as any;
}

function makeDeps(over: Partial<AgentToolDeps> = {}): AgentToolDeps {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tools-'));
  const state: AgentRunState = {
    prOpened: false,
    terminal: false,
    progressCalls: 0,
    editedFiles: new Set<string>(),
    pendingSteps: [],
    pendingAfter: [],
  };
  return {
    supabase: fakeSupabase({ machine_id: 'me', status: 'executing' }),
    fixId: 'fix-1',
    machineId: 'me',
    organizationId: 'org-1',
    projectId: 'proj-1',
    threadId: 'thread-1',
    taskId: 'task-1',
    repoRoot: workDir,
    projectDir: workDir,
    installationToken: 'tok',
    repoFullName: 'o/r',
    baseBranch: 'main',
    fixType: 'vulnerability',
    finding: { type: 'vulnerability', id: 'CVE-1' },
    projectName: 'proj',
    logger: { info: jest.fn(), warn: jest.fn(), error: jest.fn(), success: jest.fn() } as any,
    model: {} as any,
    state,
    resumeMode: null,
    runSeq: 0,
    resumePriorStatus: null,
    ...over,
  };
}

/**
 * open_pull_request's change-set narration runs REAL git commands in the work
 * dir — init a repo there so `git add -A` is scoped to the temp dir and can't
 * escape into a parent repo (e.g. a dotfiles repo in $HOME above os.tmpdir(),
 * where it would try to stage the entire home directory and hang the test).
 */
function makeGitDeps(over: Partial<AgentToolDeps> = {}): AgentToolDeps {
  const deps = makeDeps(over);
  execSync('git init -q', { cwd: deps.repoRoot });
  return deps;
}

afterEach(() => jest.clearAllMocks());

describe('agent tools', () => {
  test('write_file for a secret finding redacts the diff (never narrates the value)', async () => {
    const deps = makeDeps({ fixType: 'secret', finding: { type: 'secret', id: 's1' } });
    const tools = buildAgentTools(deps);
    await (tools.write_file.execute as any)({ path: 'config.txt', content: 'API_KEY=super-secret-value\n' });
    // The file is written, but the queued step must carry NO diff.
    expect(fs.existsSync(path.join(deps.repoRoot, 'config.txt'))).toBe(true);
    const stepArg = deps.state.pendingSteps.at(-1);
    expect(stepArg?.icon).toBe('edit');
    expect(stepArg?.diff).toBeUndefined();
  });

  test('write_file shows a real content diff for a genuine change and records the file', async () => {
    const deps = makeDeps({ fixType: 'vulnerability', finding: { type: 'vulnerability', id: 'CVE-1' } });
    fs.writeFileSync(path.join(deps.repoRoot, 'pkg.json'), '{"v":"1.0.0"}\n');
    const tools = buildAgentTools(deps);
    await (tools.write_file.execute as any)({ path: 'pkg.json', content: '{"v":"2.0.0"}\n' });
    const stepArg = deps.state.pendingSteps.at(-1);
    expect(stepArg?.icon).toBe('edit');
    expect(stepArg?.diff).toContain('2.0.0');
    expect(deps.state.editedFiles.has('pkg.json')).toBe(true);
  });

  test('write_file skips a no-op write (no card)', async () => {
    const deps = makeDeps();
    fs.writeFileSync(path.join(deps.repoRoot, 'same.txt'), 'unchanged\n');
    const tools = buildAgentTools(deps);
    const res = await (tools.write_file.execute as any)({ path: 'same.txt', content: 'unchanged\n' });
    expect(String(res)).toMatch(/nothing to change/i);
    expect(deps.state.pendingSteps).toHaveLength(0);
  });

  test('str_replace makes a surgical edit and shows the diff', async () => {
    const deps = makeDeps({ fixType: 'vulnerability', finding: { type: 'vulnerability', id: 'CVE-1' } });
    fs.writeFileSync(path.join(deps.repoRoot, 'f.txt'), 'line1\nold value\nline3\n');
    const tools = buildAgentTools(deps);
    await (tools.str_replace.execute as any)({ path: 'f.txt', old_string: 'old value', new_string: 'new value' });
    expect(fs.readFileSync(path.join(deps.repoRoot, 'f.txt'), 'utf-8')).toContain('new value');
    const stepArg = deps.state.pendingSteps.at(-1);
    expect(stepArg?.icon).toBe('edit');
    expect(stepArg?.diff).toContain('new value');
    expect(deps.state.editedFiles.has('f.txt')).toBe(true);
  });

  test('str_replace refuses a non-unique match', async () => {
    const deps = makeDeps();
    fs.writeFileSync(path.join(deps.repoRoot, 'g.txt'), 'x\nx\n');
    const tools = buildAgentTools(deps);
    const res = await (tools.str_replace.execute as any)({ path: 'g.txt', old_string: 'x', new_string: 'y' });
    expect(String(res)).toMatch(/more than once/i);
    expect(deps.state.pendingSteps).toHaveLength(0);
  });

  test('open_pull_request no-ops (no push) when the lease is held by another machine', async () => {
    const deps = makeDeps({ supabase: fakeSupabase({ machine_id: 'other', status: 'executing' }) });
    const tools = buildAgentTools(deps);
    const res = await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(String(res)).toMatch(/reassigned/i);
    expect(commitAndPushFix).not.toHaveBeenCalled();
    expect(markCompleted).not.toHaveBeenCalled();
    expect(deps.state.prOpened).toBe(false);
  });

  test('open_pull_request dup-guard short-circuits when a PR was already opened', async () => {
    const deps = makeDeps();
    deps.state.prOpened = true;
    const tools = buildAgentTools(deps);
    const res = await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(String(res)).toMatch(/already/i);
    expect(commitAndPushFix).not.toHaveBeenCalled();
  });

  test('finish_task(failed) records an honest failure and never completes', async () => {
    const deps = makeDeps();
    const tools = buildAgentTools(deps);
    await (tools.finish_task.execute as any)({ status: 'failed', summary: 'no safe fix', category: 'not_fixable' });
    expect(markFailed).toHaveBeenCalledTimes(1);
    // The terminal write is machine-fenced (zombie runs must not clobber a reclaim).
    expect(markFailed).toHaveBeenCalledWith(
      expect.anything(),
      'fix-1',
      'no safe fix',
      'not_fixable',
      expect.anything(),
      'me',
    );
    expect(markCompleted).not.toHaveBeenCalled();
    expect(deps.state.terminal).toBe(true);
  });

  test('finish_task(completed) with no PR opened is recorded as a failure, not a success', async () => {
    const deps = makeDeps();
    const tools = buildAgentTools(deps);
    await (tools.finish_task.execute as any)({ status: 'completed', summary: 'done' });
    expect(markFailed).toHaveBeenCalledTimes(1);
    expect(markCompleted).not.toHaveBeenCalled();
  });

  test('finalizeFailure is idempotent under the terminal guard', async () => {
    const deps = makeDeps();
    await finalizeFailure(deps, 'not_fixable', 'first');
    await finalizeFailure(deps, 'not_fixable', 'second');
    expect(markFailed).toHaveBeenCalledTimes(1);
  });
});

// Wake-the-task-agent: the resume/amend behaviours.
describe('agent tools — resume mode', () => {
  const RESUME = { prNumber: 42, prUrl: 'https://github.com/o/r/pull/42', branch: 'aegis/prior' };

  // open_pull_request runs real (best-effort) git narration commands in the
  // temp dir — give the spawns headroom on slow Windows CI boxes.
  const GIT_SPAWN_TIMEOUT = 30_000;

  test('open_pull_request in amend mode pushes to the existing branch and re-stamps the same PR', async () => {
    const deps = makeGitDeps({ resumeMode: { ...RESUME }, runSeq: 1, resumePriorStatus: 'completed' });
    const tools = buildAgentTools(deps);
    const res = await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(commitAndPushFix).toHaveBeenCalledWith(
      expect.objectContaining({ mode: 'amend', existingBranch: 'aegis/prior' }),
    );
    // No second PR: the GitHub create endpoint is never hit.
    expect(openPullRequest).not.toHaveBeenCalled();
    // markCompleted re-stamps the EXISTING PR coordinates, machine-fenced.
    expect(markCompleted).toHaveBeenCalledWith(
      expect.anything(),
      'fix-1',
      expect.objectContaining({ prNumber: 42, prUrl: RESUME.prUrl, prBranch: 'aegis/prior' }),
      'me',
    );
    // No duplicate PR-ready card queued (the run-1 card live-renders from this fixId).
    expect(deps.state.pendingAfter).toHaveLength(0);
    expect(deps.state.prOpened).toBe(true);
    expect(deps.state.terminal).toBe(true);
    expect(String(res)).toMatch(/update to pull request #42/i);
  }, GIT_SPAWN_TIMEOUT);

  test('an amend with no new changes is not terminal and does not re-stamp', async () => {
    (commitAndPushFix as jest.Mock).mockResolvedValueOnce({
      prBranch: 'aegis/prior',
      diffSummary: '',
      pushOutput: '',
      noChanges: true,
    });
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    const tools = buildAgentTools(deps);
    const res = await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(String(res)).toMatch(/no new changes/i);
    expect(markCompleted).not.toHaveBeenCalled();
    expect(deps.state.prOpened).toBe(false);
    expect(deps.state.terminal).toBe(false);
  }, GIT_SPAWN_TIMEOUT);

  test('answer-only finish_task(completed) with a standing PR marks answered, never failed', async () => {
    const deps = makeDeps({ resumeMode: { ...RESUME } });
    const tools = buildAgentTools(deps);
    const res = await (tools.finish_task.execute as any)({ status: 'completed', summary: 'answered the question' });
    expect(markAnswered).toHaveBeenCalledWith(expect.anything(), 'fix-1', 'me');
    expect(markCompleted).not.toHaveBeenCalled();
    expect(markFailed).not.toHaveBeenCalled();
    expect(deps.state.terminal).toBe(true);
    expect(String(res)).toMatch(/existing pull request stands/i);
  });

  test('answer-only finish_task(completed) after the prior PR was merged/closed still completes', async () => {
    // resumeMode is null (PR merged/closed) but the prior run genuinely
    // succeeded — an answer-only turn must NOT downgrade the task to failed.
    const deps = makeDeps({ resumeMode: null, resumePriorStatus: 'completed' });
    const tools = buildAgentTools(deps);
    const res = await (tools.finish_task.execute as any)({ status: 'completed', summary: 'answered' });
    expect(markAnswered).toHaveBeenCalledWith(expect.anything(), 'fix-1', 'me');
    expect(markFailed).not.toHaveBeenCalled();
    expect(markCompleted).not.toHaveBeenCalled();
    expect(markTaskFromFix).toHaveBeenCalledWith(expect.anything(), 'task-1', {
      status: 'completed',
      summary: 'answered',
    });
    expect(deps.state.terminal).toBe(true);
    expect(String(res)).toMatch(/original fix already stands/i);
  });

  test('Stop of a resume-of-completed restores the success instead of failing it', async () => {
    const deps = makeDeps({ resumePriorStatus: 'completed' });
    await finalizeFailure(deps, 'cancelled', 'Task stopped by user.');
    expect(markAnswered).toHaveBeenCalledWith(expect.anything(), 'fix-1', 'me');
    expect(markFailed).not.toHaveBeenCalled();
    expect(markTaskFromFix).toHaveBeenCalledWith(expect.anything(), 'task-1', { status: 'completed' });
    expect(deps.state.terminal).toBe(true);
  });

  test('a not_fixable outcome of a resume-of-completed restores the success (never downgrades)', async () => {
    const deps = makeDeps({ resumePriorStatus: 'completed' });
    await finalizeFailure(deps, 'not_fixable', 'nothing further to change');
    expect(markAnswered).toHaveBeenCalledWith(expect.anything(), 'fix-1', 'me');
    expect(markFailed).not.toHaveBeenCalled();
    expect(markTaskFromFix).toHaveBeenCalledWith(expect.anything(), 'task-1', { status: 'completed' });
    expect(deps.state.terminal).toBe(true);
  });

  test('a system_error on a resume-of-completed also restores instead of failing', async () => {
    const deps = makeDeps({ resumePriorStatus: 'completed' });
    await finalizeFailure(deps, 'system_error', 'provider exploded');
    expect(markAnswered).toHaveBeenCalledTimes(1);
    expect(markFailed).not.toHaveBeenCalled();
  });

  test('a resume of a FAILED prior run still fails honestly (no restore)', async () => {
    const deps = makeDeps({ resumePriorStatus: 'failed' });
    await finalizeFailure(deps, 'not_fixable', 'still no safe fix');
    expect(markAnswered).not.toHaveBeenCalled();
    expect(markFailed).toHaveBeenCalledTimes(1);
  });

  test('zombie fence: finalizeFailure threads this machine id into the terminal write', async () => {
    // The row may have been re-woken and reclaimed by ANOTHER machine; the
    // machine-fenced update makes this (old) run's write a DB no-op.
    const deps = makeDeps({ machineId: 'old-machine' });
    await finalizeFailure(deps, 'system_error', 'boom');
    expect(markFailed).toHaveBeenCalledWith(
      expect.anything(),
      'fix-1',
      'boom',
      'system_error',
      expect.anything(),
      'old-machine',
    );
  });

  test('lockfile regen is skipped on an edit-free amend (answer-only turn stays a true noChanges)', async () => {
    (commitAndPushFix as jest.Mock).mockResolvedValueOnce({
      prBranch: 'aegis/prior',
      diffSummary: '',
      pushOutput: '',
      noChanges: true,
    });
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
    const tools = buildAgentTools(deps);
    expect(deps.state.editedFiles.size).toBe(0);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(deps.logger.info).not.toHaveBeenCalledWith('setup', expect.stringContaining('Regenerated lockfile'));
  }, GIT_SPAWN_TIMEOUT);

  test('create path with runSeq>0 uses a run-unique branch suffix', async () => {
    const deps = makeGitDeps({ runSeq: 1 });
    const tools = buildAgentTools(deps);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(commitAndPushFix).toHaveBeenCalledWith(expect.objectContaining({ branchSuffix: '-r1' }));
    expect(openPullRequest).toHaveBeenCalledTimes(1);
  }, GIT_SPAWN_TIMEOUT);

  test('create path on a first run passes no branch suffix', async () => {
    const deps = makeGitDeps();
    const tools = buildAgentTools(deps);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(commitAndPushFix).toHaveBeenCalledWith(expect.objectContaining({ branchSuffix: undefined }));
  }, GIT_SPAWN_TIMEOUT);
});
