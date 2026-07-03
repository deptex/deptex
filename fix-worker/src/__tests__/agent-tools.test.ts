// Behavioural gates for the autonomous agent's toolbox: the lease fence (a
// requeued run must not double-push), the dup-guard, the terminal writers, and
// secret-diff redaction (the removed line IS the plaintext credential).

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
import { commitAndPushFix } from '../pr';
import { markCompleted, markFailed } from '../job-db';
import { narrateStep } from '../task-chat';

function fakeSupabase(leaseRow: any) {
  return {
    from: () => ({ select: () => ({ eq: () => ({ single: async () => ({ data: leaseRow }) }) }) }),
  } as any;
}

function makeDeps(over: Partial<AgentToolDeps> = {}): AgentToolDeps {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-tools-'));
  const state: AgentRunState = { prOpened: false, terminal: false, progressCalls: 0 };
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
    ...over,
  };
}

afterEach(() => jest.clearAllMocks());

describe('agent tools', () => {
  test('write_file for a secret finding redacts the diff (never narrates the value)', async () => {
    const deps = makeDeps({ fixType: 'secret', finding: { type: 'secret', id: 's1' } });
    const tools = buildAgentTools(deps);
    await (tools.write_file.execute as any)({ path: 'config.txt', content: 'API_KEY=super-secret-value\n' });
    // The file is written, but the narrated step must carry NO diff.
    expect(fs.existsSync(path.join(deps.repoRoot, 'config.txt'))).toBe(true);
    const stepArg = (narrateStep as jest.Mock).mock.calls.at(-1)?.[2];
    expect(stepArg.icon).toBe('edit');
    expect(stepArg.diff).toBeUndefined();
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
