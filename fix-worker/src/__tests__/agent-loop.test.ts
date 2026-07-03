// Control-flow gates for the agent loop: it must ALWAYS reach a terminal state
// (a budget-exhausted / errored / cancelled run must never leave the row
// 'executing', or recovery re-runs the whole expensive agent). generateText and
// the loop's external collaborators are stubbed so the flow is deterministic.

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

jest.mock('ai', () => ({
  generateText: jest.fn(),
  stepCountIs: () => ({ type: 'stepCount' }),
  hasToolCall: () => ({ type: 'hasToolCall' }),
}));
jest.mock('../job-db', () => ({
  getOrgInstallationId: jest.fn(async () => ({ installationId: 'i', repoFullName: 'o/r', packageJsonPath: '' })),
  isJobCancelled: jest.fn(async () => false),
}));
jest.mock('../github', () => ({ createInstallationToken: jest.fn(async () => 'tok') }));
jest.mock('../sandbox', () => ({ cloneAtSha: jest.fn(async () => 'cloned output') }));
jest.mock('../llm', () => ({ getLanguageModelForOrg: jest.fn(async () => ({})) }));
jest.mock('../task-chat', () => ({ makeTaskNarrator: () => async () => {}, narrateStep: jest.fn(async () => {}) }));
jest.mock('../logger', () => ({ FixLogger: class {} }));
jest.mock('../agent/tools', () => ({ buildAgentTools: () => ({}), finalizeFailure: jest.fn(async () => {}) }));

import { generateText } from 'ai';
import { isJobCancelled } from '../job-db';
import { finalizeFailure } from '../agent/tools';
import { runTaskAgent, type AgentRunInput } from '../agent/loop';

function makeInput(): AgentRunInput {
  return {
    fixId: 'fix-1',
    organizationId: 'org-1',
    projectId: 'proj-1',
    threadId: 'thread-1',
    taskId: 'task-1',
    fixType: 'vulnerability',
    finding: { type: 'vulnerability', id: 'CVE-1' },
    summary: 'fix it',
    baseBranch: 'main',
    baseSha: 'deadbeef',
  };
}

function makeDeps() {
  const workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'agent-loop-'));
  return { machineId: 'me', projectName: 'proj', logger: {} as any, workDir };
}

afterEach(() => jest.clearAllMocks());

describe('runTaskAgent — always-terminal guarantee', () => {
  test('a run that never opens a PR / calls finish_task resolves to a failure', async () => {
    (generateText as jest.Mock).mockImplementation(async () => ({})); // model does nothing
    await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('not_fixable');
  });

  test('a cancelled run finalizes as cancelled', async () => {
    (isJobCancelled as jest.Mock).mockResolvedValue(true);
    (generateText as jest.Mock).mockImplementation(async (opts: any) => {
      await opts.onStepFinish({ text: '' });
      if (opts.abortSignal?.aborted) {
        const e = new Error('aborted');
        (e as any).name = 'AbortError';
        throw e;
      }
      return {};
    });
    await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('cancelled');
  });

  test('an unexpected model error still finalizes (never leaves the row executing)', async () => {
    (generateText as jest.Mock).mockImplementation(async () => {
      throw new Error('provider exploded');
    });
    await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('not_fixable');
    expect((finalizeFailure as jest.Mock).mock.calls[0][2]).toMatch(/provider exploded/);
  });
});
