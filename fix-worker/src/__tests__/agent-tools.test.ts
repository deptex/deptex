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
jest.mock('../task-chat', () => {
  // A shared, assertable narrator: makeTaskNarrator always hands back this fn
  // so tests can check the exact prose beats (e.g. the amend closing beat).
  const narrator = jest.fn(async () => {});
  return {
    narrateStep: jest.fn(async () => {}),
    postPrReadyCard: jest.fn(async () => {}),
    postFailureCard: jest.fn(async () => {}),
    describeFailure: () => ({ headline: 'h', explanation: 'e', nextStep: 'n', leadIn: 'l', stepLabel: 's' }),
    markTaskFromFix: jest.fn(async () => {}),
    makeTaskNarrator: jest.fn(() => narrator),
    __narrator: narrator,
  };
});
jest.mock('../logger', () => ({ FixLogger: class {} }));

import {
  buildAgentTools,
  buildSafeEnv,
  scrubOutput,
  finalizeFailure,
  maybeFinalizeAnsweredNaturalStop,
  revertImplausibleLockfileRegen,
  type AgentRunState,
  type AgentToolDeps,
} from '../agent/tools';
import { commitAndPushFix, openPullRequest } from '../pr';
import { markCompleted, markFailed, markAnswered } from '../job-db';
import { markTaskFromFix, narrateStep, postPrReadyCard } from '../task-chat';

const taskChatNarrator = (jest.requireMock('../task-chat') as any).__narrator as jest.Mock;

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
    seenCalls: new Set<string>(),
    novelCalls: 0,
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

/** Commit everything in the test repo (identity + autocrlf pinned for byte-stable restores). */
function commitAll(repoRoot: string) {
  execSync('git config core.autocrlf false', { cwd: repoRoot });
  execSync('git config user.email "t@deptex.dev"', { cwd: repoRoot });
  execSync('git config user.name "t"', { cwd: repoRoot });
  execSync('git add -A', { cwd: repoRoot });
  execSync('git commit -qm init', { cwd: repoRoot });
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

  test('read-only tools count novelty once per distinct call (repeats are the spin signal)', async () => {
    const deps = makeDeps();
    fs.writeFileSync(path.join(deps.repoRoot, 'a.txt'), 'hello\n');
    const tools = buildAgentTools(deps);
    await (tools.read_file.execute as any)({ path: 'a.txt' });
    await (tools.read_file.execute as any)({ path: 'a.txt' }); // repeat — not novel
    expect(deps.state.novelCalls).toBe(1);
    await (tools.grep.execute as any)({ pattern: 'hello' });
    await (tools.grep.execute as any)({ pattern: 'hello' }); // repeat — not novel
    expect(deps.state.novelCalls).toBe(2);
    await (tools.grep.execute as any)({ pattern: 'hello', glob: 'src' }); // different glob = novel
    await (tools.list_dir.execute as any)({ path: '.' });
    expect(deps.state.novelCalls).toBe(4);
    // Read-only calls never count as side-effecting progress.
    expect(deps.state.progressCalls).toBe(0);
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
  // temp dir — give the spawns headroom on slow Windows CI boxes. Tests that
  // reach the LIVE npm lockfile regen need more.
  const GIT_SPAWN_TIMEOUT = 30_000;
  const NPM_LIVE_TIMEOUT = 120_000;

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
    // No duplicate PR-ready card (the run-1 card live-renders from this fixId) —
    // instead ONE deferred closing text beat so the timeline doesn't end
    // abruptly on the step row.
    expect(postPrReadyCard).not.toHaveBeenCalled();
    expect(deps.state.pendingAfter).toHaveLength(1);
    await deps.state.pendingAfter[0]();
    expect(taskChatNarrator).toHaveBeenCalledWith('The update is up — same pull request, one new commit.');
    expect(postPrReadyCard).not.toHaveBeenCalled();
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

  // maybeFinalizeAnsweredNaturalStop: a weak model on a resume routinely writes
  // its answer as prose and stops WITHOUT calling finish_task. A clean tree +
  // narrated text = an answer-only turn; resolving it here is what stops the
  // "I couldn't complete that follow-up" being appended to a perfect answer
  // (the PR #16 wake bug). A freshly `git init`'d empty repo has a clean
  // porcelain status, so no seed commit is needed for the clean-tree cases.
  test('natural stop on a still-open-PR resume with a clean tree + narration marks answered', async () => {
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    const resolved = await maybeFinalizeAnsweredNaturalStop(deps, true);
    expect(resolved).toBe(true);
    expect(markAnswered).toHaveBeenCalledWith(expect.anything(), 'fix-1', 'me');
    expect(markFailed).not.toHaveBeenCalled();
    expect(markTaskFromFix).toHaveBeenCalledWith(expect.anything(), 'task-1', { status: 'completed' });
    expect(deps.state.terminal).toBe(true);
  }, GIT_SPAWN_TIMEOUT);

  test('natural stop on a prior-completed resume (PR merged/closed) with a clean tree marks answered', async () => {
    const deps = makeGitDeps({ resumeMode: null, resumePriorStatus: 'completed' });
    const resolved = await maybeFinalizeAnsweredNaturalStop(deps, true);
    expect(resolved).toBe(true);
    expect(markAnswered).toHaveBeenCalledTimes(1);
    expect(deps.state.terminal).toBe(true);
  }, GIT_SPAWN_TIMEOUT);

  test('natural stop with a DIRTY tree does NOT mark answered (half-made edits must not pass as success)', async () => {
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    fs.writeFileSync(path.join(deps.repoRoot, 'package.json'), '{"half":"edited"}\n');
    const resolved = await maybeFinalizeAnsweredNaturalStop(deps, true);
    expect(resolved).toBe(false);
    expect(markAnswered).not.toHaveBeenCalled();
    expect(deps.state.terminal).toBe(false);
  }, GIT_SPAWN_TIMEOUT);

  test('natural stop with NO narration is not an answer (leaves the failure path to resolve it)', async () => {
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    const resolved = await maybeFinalizeAnsweredNaturalStop(deps, false);
    expect(resolved).toBe(false);
    expect(markAnswered).not.toHaveBeenCalled();
    expect(deps.state.terminal).toBe(false);
  }, GIT_SPAWN_TIMEOUT);

  test('natural stop on a FIRST run (no resume) is never an answer-only completion', async () => {
    const deps = makeGitDeps({ resumeMode: null, resumePriorStatus: null });
    const resolved = await maybeFinalizeAnsweredNaturalStop(deps, true);
    expect(resolved).toBe(false);
    expect(markAnswered).not.toHaveBeenCalled();
  }, GIT_SPAWN_TIMEOUT);

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

  test('lockfile regen is skipped on a CLEAN-tree amend (answer-only turn stays a true noChanges)', async () => {
    (commitAndPushFix as jest.Mock).mockResolvedValueOnce({
      prBranch: 'aegis/prior',
      diffSummary: '',
      pushOutput: '',
      noChanges: true,
    });
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
    commitAll(deps.repoRoot); // clean working tree = a true edit-free amend
    const tools = buildAgentTools(deps);
    expect(deps.state.editedFiles.size).toBe(0);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(deps.logger.info).not.toHaveBeenCalledWith('setup', expect.stringContaining('Regenerated lockfile'));
  }, GIT_SPAWN_TIMEOUT);

  test('an amend dirtied by a SHELL-side change (editor ledger empty) still runs the regen', async () => {
    (commitAndPushFix as jest.Mock).mockResolvedValueOnce({
      prBranch: 'aegis/prior',
      diffSummary: 'd',
      pushOutput: 'p',
      noChanges: false,
    });
    const deps = makeGitDeps({ resumeMode: { ...RESUME } });
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
    commitAll(deps.repoRoot);
    // Simulate the heal-2 incident: a tracked file changed via run_command
    // (e.g. `git checkout origin/master -- package-lock.json`) — the tree is
    // dirty but state.editedFiles never saw it. The skip must ask GIT, not the
    // editor ledger, so the regen still runs.
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.1"}\n');
    const tools = buildAgentTools(deps);
    expect(deps.state.editedFiles.size).toBe(0);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(deps.logger.info).toHaveBeenCalledWith('setup', expect.stringContaining('Regenerated lockfile'));
  }, NPM_LIVE_TIMEOUT);

  test('a NON-vulnerability fix that edits package.json still runs the regen (PR #20 container catch)', async () => {
    // A container fix added an npm "overrides" entry; the old fixType gate
    // skipped the regen and shipped an out-of-sync lockfile (npm ci EUSAGE).
    // The regen must key on GIT (npm files dirty), not the finding type.
    const deps = makeGitDeps({ fixType: 'container', finding: { type: 'container', id: 'CVE-X' } });
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
    commitAll(deps.repoRoot);
    fs.writeFileSync(
      path.join(deps.projectDir, 'package.json'),
      '{"name":"x","version":"1.0.0","overrides":{"minimist":">=1.2.6"}}\n',
    );
    const tools = buildAgentTools(deps);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    expect(deps.logger.info).toHaveBeenCalledWith('setup', expect.stringContaining('Regenerated lockfile'));
  }, NPM_LIVE_TIMEOUT);

  test('a code-only fix (no npm file touched) skips the regen entirely', async () => {
    const deps = makeGitDeps({ fixType: 'semgrep', finding: { type: 'semgrep', id: 's1' } });
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
    fs.writeFileSync(path.join(deps.projectDir, 'app.js'), 'const a = 1;\n');
    commitAll(deps.repoRoot);
    fs.writeFileSync(path.join(deps.projectDir, 'app.js'), 'const a = 2;\n'); // source dirty, npm files clean
    const tools = buildAgentTools(deps);
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

// Failure copy: 'stall' and 'budget_exhausted' (wall-clock) must never say
// "budget/room" — a paying user reads that as their prepaid BILLING balance.
describe('finalizeFailure — stall & time-limit copy', () => {
  test("a stall says 'no clear fix found' and invites a reply-to-resume hint", async () => {
    const deps = makeDeps();
    await finalizeFailure(deps, 'stall', 'Stopped making progress and was halted.');
    expect(markFailed).toHaveBeenCalledWith(
      expect.anything(),
      'fix-1',
      'Stopped making progress and was halted.',
      'stall',
      expect.objectContaining({
        headline: "I couldn't find a clear fix",
        explanation: expect.stringContaining('stopped rather than guess'),
        nextStep: expect.stringContaining('Reply with a hint'),
      }),
      'me',
    );
    expect(narrateStep).toHaveBeenCalledWith(expect.anything(), 'thread-1', {
      icon: 'failed',
      label: 'Stopped — no clear fix found',
    });
    // The money-sounding words must not appear anywhere in the stored copy.
    const details = (markFailed as jest.Mock).mock.calls[0][4];
    expect(JSON.stringify(details)).not.toMatch(/budget|ran out of room/i);
  });

  test("a wall-clock exhaustion says 'time limit' and invites a reply-to-resume", async () => {
    const deps = makeDeps();
    await finalizeFailure(deps, 'budget_exhausted', 'Reached the 1800s time budget before finishing.');
    expect(markFailed).toHaveBeenCalledWith(
      expect.anything(),
      'fix-1',
      expect.any(String),
      'budget_exhausted',
      expect.objectContaining({
        headline: 'This ran past my time limit',
        explanation: 'The task needed more time than a single run allows.',
        nextStep: expect.stringContaining("Reply and I'll pick it up again"),
      }),
      'me',
    );
    expect(narrateStep).toHaveBeenCalledWith(expect.anything(), 'thread-1', {
      icon: 'failed',
      label: 'Hit the time limit',
    });
    // The USER-FACING copy must not sound like money ('budget'/'room'); the
    // internal category key ('budget_exhausted') is DB-only and never rendered.
    const details = (markFailed as jest.Mock).mock.calls[0][4];
    expect(`${details.headline} ${details.explanation} ${details.nextStep}`).not.toMatch(/budget|ran out of room/i);
  });
});

// Lockfile stub guard: npm quirks (a "//" comment key inside "overrides") can
// silently treat the manifest as EMPTY and rewrite the lockfile as a 7-line
// stub — the guard reverts implausible shrinkage so the stub never reaches
// the PR (prod bug: PR #16 committed a -27509-line lockfile).
describe('revertImplausibleLockfileRegen — lockfile stub guard', () => {
  const LOCK = 'package-lock.json';
  const GIT_TIMEOUT = 30_000;
  const NPM_TIMEOUT = 120_000;

  test('restores a committed lockfile that shrank implausibly', async () => {
    const deps = makeGitDeps();
    const big = `{"name":"x","padding":"${'p'.repeat(30000)}"}\n`;
    fs.writeFileSync(path.join(deps.projectDir, LOCK), big);
    commitAll(deps.repoRoot);
    fs.writeFileSync(path.join(deps.projectDir, LOCK), '{"name":"x","packages":{}}\n'); // the stub
    const tripped = await revertImplausibleLockfileRegen(deps.projectDir, deps.repoRoot, big.length, deps.logger);
    expect(tripped).toBe(true);
    const restored = fs.readFileSync(path.join(deps.projectDir, LOCK), 'utf-8');
    expect(restored.length).toBeGreaterThan(20000);
    expect(deps.logger.warn).toHaveBeenCalledWith('setup', expect.stringContaining('implausibly small'));
  }, GIT_TIMEOUT);

  test('a sane shrink is left untouched', async () => {
    const deps = makeGitDeps();
    const big = `{"name":"x","padding":"${'p'.repeat(30000)}"}\n`;
    fs.writeFileSync(path.join(deps.projectDir, LOCK), big);
    commitAll(deps.repoRoot);
    const smaller = `{"name":"x","padding":"${'q'.repeat(20000)}"}\n`;
    fs.writeFileSync(path.join(deps.projectDir, LOCK), smaller);
    const tripped = await revertImplausibleLockfileRegen(deps.projectDir, deps.repoRoot, big.length, deps.logger);
    expect(tripped).toBe(false);
    expect(fs.readFileSync(path.join(deps.projectDir, LOCK), 'utf-8')).toBe(smaller);
    expect(deps.logger.warn).not.toHaveBeenCalled();
  }, GIT_TIMEOUT);

  test('a tiny fresh stub where no lockfile existed is deleted', async () => {
    const deps = makeDeps();
    fs.writeFileSync(path.join(deps.projectDir, LOCK), '{"packages":{}}\n');
    const tripped = await revertImplausibleLockfileRegen(deps.projectDir, deps.repoRoot, 0, deps.logger);
    expect(tripped).toBe(true);
    expect(fs.existsSync(path.join(deps.projectDir, LOCK))).toBe(false);
    expect(deps.logger.warn).toHaveBeenCalledWith('setup', expect.stringContaining('implausibly small'));
  });

  test('a real new lockfile where none existed is kept', async () => {
    const deps = makeDeps();
    const real = `{"name":"x","padding":"${'p'.repeat(50000)}"}\n`;
    fs.writeFileSync(path.join(deps.projectDir, LOCK), real);
    const tripped = await revertImplausibleLockfileRegen(deps.projectDir, deps.repoRoot, 0, deps.logger);
    expect(tripped).toBe(false);
    expect(fs.readFileSync(path.join(deps.projectDir, LOCK), 'utf-8')).toBe(real);
    expect(deps.logger.warn).not.toHaveBeenCalled();
  });

  test('the PR-time regen call site guards with the pre-regen size (live npm)', async () => {
    const deps = makeGitDeps();
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.0"}\n');
    // A plausible committed lockfile that a dep-less regen will rewrite as a
    // ~250-byte stub — exactly the prod failure shape.
    const big = `{"name":"x","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{"":{"name":"x","version":"1.0.0","padding":"${'p'.repeat(30000)}"}}}\n`;
    fs.writeFileSync(path.join(deps.projectDir, LOCK), big);
    commitAll(deps.repoRoot);
    // Dirty the manifest (the agent's edit) — the regen keys on git now, so a
    // fully-clean tree wouldn't trigger it.
    fs.writeFileSync(path.join(deps.projectDir, 'package.json'), '{"name":"x","version":"1.0.1"}\n');
    const tools = buildAgentTools(deps);
    await (tools.open_pull_request.execute as any)({ title: 't', body: 'b' });
    // The regen ran…
    expect(deps.logger.info).toHaveBeenCalledWith('setup', expect.stringContaining('Regenerated lockfile'));
    // …shrank the lockfile implausibly, and the guard restored the original.
    expect(deps.logger.warn).toHaveBeenCalledWith('setup', expect.stringContaining('implausibly small'));
    expect(fs.readFileSync(path.join(deps.projectDir, LOCK), 'utf-8').length).toBeGreaterThan(20000);
  }, NPM_TIMEOUT);
});

// ---------------------------------------------------------------------------
// Security boundary (Tranche 1): the run_command env deny-list, the shared
// secret scrubber on every surfaced string, and symlink path confinement.
// These guard the CRIT-1 (secret exfil) / HIGH-1 (symlink escape) fixes.
// ---------------------------------------------------------------------------
describe('security — run_command env deny-list (buildSafeEnv)', () => {
  test('strips every secret-shaped var but keeps the toolchain vars', () => {
    const safe = buildSafeEnv({
      PATH: '/usr/bin',
      HOME: '/root',
      NODE_OPTIONS: '--max-old-space-size=512',
      LANG: 'C.UTF-8',
      // secrets that MUST NOT survive into the agent's shell:
      GITHUB_APP_PRIVATE_KEY: '-----BEGIN RSA PRIVATE KEY-----x',
      SUPABASE_SERVICE_ROLE_KEY: 'eyJ.a.b',
      SUPABASE_ANON_KEY: 'eyJ.c.d',
      OPENAI_API_KEY: 'sk-abc',
      ANTHROPIC_API_KEY: 'sk-ant-abc',
      INTERNAL_API_KEY: 'internal',
      STRIPE_SECRET_KEY: 'sk_live_x',
      FLY_API_TOKEN: 'fly',
      QSTASH_TOKEN: 'q',
      AI_ENCRYPTION_KEY: 'aes',
      GITHUB_WEBHOOK_SECRET: 'wh',
    });
    // Toolchain kept.
    expect(safe.PATH).toBe('/usr/bin');
    expect(safe.HOME).toBe('/root');
    expect(safe.NODE_OPTIONS).toBe('--max-old-space-size=512');
    expect(safe.LANG).toBe('C.UTF-8');
    // Every secret dropped.
    for (const k of [
      'GITHUB_APP_PRIVATE_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_ANON_KEY',
      'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'INTERNAL_API_KEY', 'STRIPE_SECRET_KEY',
      'FLY_API_TOKEN', 'QSTASH_TOKEN', 'AI_ENCRYPTION_KEY', 'GITHUB_WEBHOOK_SECRET',
    ]) {
      expect(safe[k]).toBeUndefined();
    }
  });
});

describe('security — scrubOutput redacts secrets on surfaced strings', () => {
  test('masks the install token and pattern-scrubs AI / PEM / JWT keys', () => {
    const token = 'ghs_installtoken1234567890abcdef';
    const raw =
      `cloned with ${token}\n` +
      `OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwx\n` +
      `ANTHROPIC=sk-ant-abcdefghijklmnopqrstuv\n` +
      `-----BEGIN RSA PRIVATE KEY-----\nMIIBparts\n-----END RSA PRIVATE KEY-----`;
    const out = scrubOutput(raw, token);
    expect(out).not.toContain(token);
    expect(out).not.toContain('sk-abcdefghijklmnopqrstuvwx');
    expect(out).not.toContain('sk-ant-abcdefghijklmnopqrstuv');
    expect(out).not.toContain('MIIBparts');
    expect(out).toContain('[REDACTED_PRIVATE_KEY]');
  });
});

describe('security — symlink path confinement (resolveWithin via read_file)', () => {
  test('a symlink escaping the repo is rejected, not followed', async () => {
    const deps = makeDeps();
    // A secret file OUTSIDE the repo clone.
    const outsideDir = fs.mkdtempSync(path.join(os.tmpdir(), 'outside-'));
    const secretPath = path.join(outsideDir, 'secret.txt');
    fs.writeFileSync(secretPath, 'TOP SECRET');
    const linkPath = path.join(deps.repoRoot, 'escape');
    try {
      fs.symlinkSync(secretPath, linkPath);
    } catch {
      // Windows dev without symlink privilege — the confinement runs on the
      // Linux worker + CI (ubuntu), which is where this must hold.
      return;
    }
    const tools = buildAgentTools(deps);
    const result = await (tools.read_file.execute as any)({ path: 'escape' });
    expect(result).toBe('path is outside the repository');
    expect(result).not.toContain('TOP SECRET');
  });

  test('a normal in-repo file still reads fine (realpath check is not over-eager)', async () => {
    const deps = makeDeps();
    fs.writeFileSync(path.join(deps.repoRoot, 'ok.txt'), 'hello');
    const tools = buildAgentTools(deps);
    const result = await (tools.read_file.execute as any)({ path: 'ok.txt' });
    expect(result).toBe('hello');
  });
});
