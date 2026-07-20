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
  updateAgentRunStats: jest.fn(async () => {}),
}));
jest.mock('../github', () => ({ createInstallationToken: jest.fn(async () => 'tok') }));
jest.mock('../sandbox', () => ({
  cloneAtSha: jest.fn(async () => 'cloned output'),
  cloneBranchHead: jest.fn(async () => 'cloned branch tip'),
}));
jest.mock('../pr', () => ({ getPullRequestState: jest.fn(async () => 'open') }));
jest.mock('../agent/replay', () => ({
  reconstructAgentMessages: jest.fn(async () => ({
    messages: [{ role: 'user', content: 'replayed brief' }],
    replayedThrough: '2026-07-03T00:00:00Z',
  })),
}));
jest.mock('../llm', () => ({
  resolveOrgModel: jest.fn(async () => ({
    model: {},
    provider: 'anthropic',
    modelName: 'claude-sonnet-4-5-20250929',
    contextWindow: 200_000,
  })),
}));
jest.mock('../observability/capture', () => ({ captureInfraError: jest.fn() }));
jest.mock('../task-chat', () => ({ makeTaskNarrator: () => async () => {}, narrateStep: jest.fn(async () => {}) }));
jest.mock('../logger', () => ({ FixLogger: class {} }));
jest.mock('../agent/tools', () => ({
  buildAgentTools: jest.fn(() => ({})),
  finalizeFailure: jest.fn(async () => {}),
  // Default: not an answer-only turn, so the failure fallback runs and the
  // existing terminal-category assertions hold. The answer-only test overrides
  // this to return true.
  maybeFinalizeAnsweredNaturalStop: jest.fn(async () => false),
}));

import { generateText } from 'ai';
import { isJobCancelled } from '../job-db';
import { cloneAtSha, cloneBranchHead } from '../sandbox';
import { getPullRequestState } from '../pr';
import { captureInfraError } from '../observability/capture';
import { buildAgentTools, finalizeFailure, maybeFinalizeAnsweredNaturalStop } from '../agent/tools';
import { runTaskAgent, isContextLengthError, type AgentRunInput } from '../agent/loop';

/** The live AgentRunState of the current run, captured off the buildAgentTools mock. */
function capturedState(): any {
  const calls = (buildAgentTools as jest.Mock).mock.calls;
  return calls[calls.length - 1][0].state;
}

function makeInput(over: Partial<AgentRunInput> = {}): AgentRunInput {
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
    resume: false,
    runSeq: 0,
    resumePriorStatus: null,
    priorPr: null,
    ...over,
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

  test('a cancelled run finalizes as cancelled and reports cancelled=true (drain skip)', async () => {
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
    const res = await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('cancelled');
    // The caller skips the end-of-run drain on a user Stop.
    expect(res.cancelled).toBe(true);
    // The cancel probe carries this machine's id — a reassigned (zombie) run
    // aborts on machine mismatch, not just on status='rejected'.
    expect(isJobCancelled).toHaveBeenCalledWith(expect.anything(), 'fix-1', 'me');
    (isJobCancelled as jest.Mock).mockResolvedValue(false);
  });

  test('an unexpected model error finalizes as system_error (raw message kept for logs, not the user)', async () => {
    (generateText as jest.Mock).mockImplementation(async () => {
      throw new Error('provider exploded');
    });
    await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    // Unexpected exceptions must be system_error (generic user copy), never
    // not_fixable (which would surface the raw provider message).
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('system_error');
    // The raw message is still passed through — it lands in error_message (logs).
    expect((finalizeFailure as jest.Mock).mock.calls[0][2]).toMatch(/provider exploded/);
  });

  test('an answer-only natural stop (resume, clean tree, narration) completes — no failure fallback', async () => {
    // The PR #16 wake bug: on a resume the model answered in prose and stopped
    // without finish_task. maybeFinalizeAnsweredNaturalStop resolves it as
    // answered (returns true, sets state.terminal); finalizeFailure must NOT
    // run — otherwise the good answer gets "I couldn't complete that follow-up".
    (generateText as jest.Mock).mockImplementation(async (opts: any) => {
      await opts.onStepFinish({ text: 'Yes — the override forces set-value to 4.1.0.' });
      return {};
    });
    (maybeFinalizeAnsweredNaturalStop as jest.Mock).mockImplementation(async (deps: any) => {
      deps.state.terminal = true; // the real fn marks the row answered + terminal
      return true;
    });
    await runTaskAgent(
      {} as any,
      makeInput({
        resume: true,
        resumePriorStatus: 'completed',
        priorPr: { branch: 'aegis/fix-x-abc', number: 16, url: 'https://github.com/o/r/pull/16', repoFullName: 'o/r' },
      }),
      makeDeps(),
    );
    // The natural-stop path was consulted with narrated=true …
    expect(maybeFinalizeAnsweredNaturalStop).toHaveBeenCalledTimes(1);
    expect((maybeFinalizeAnsweredNaturalStop as jest.Mock).mock.calls[0][1]).toBe(true);
    // … and because it resolved the run, the failure writer never fired.
    expect(finalizeFailure).not.toHaveBeenCalled();
    (maybeFinalizeAnsweredNaturalStop as jest.Mock).mockResolvedValue(false);
  });
});

describe('isContextLengthError — provider overflow classification', () => {
  // The SDK's APICallError hides the real reason in different fields per
  // provider. Each of these MUST classify as an overflow so the loop maps it to
  // context_exhausted (reply-to-resume), not system_error ("try again later").
  test('OpenAI overflow in .message', () => {
    expect(
      isContextLengthError({
        statusCode: 400,
        message:
          "This model's maximum context length is 16385 tokens. However, your messages resulted in 21000 tokens. Please reduce the length of the messages.",
      }),
    ).toBe(true);
  });

  test('OpenAI/DeepInfra overflow ONLY in .responseBody (generic .message)', () => {
    // The message-only regex missed this: openai-compatible (DeepInfra) surfaces
    // a terse .message and leaves the detail in the raw body.
    expect(
      isContextLengthError({
        statusCode: 400,
        message: 'Bad Request',
        responseBody:
          '{"error":{"message":"This model\'s maximum context length is 131072 tokens. However, you requested 140000 tokens.","type":"invalid_request_error","code":"context_length_exceeded"}}',
      }),
    ).toBe(true);
  });

  test('Anthropic overflow ("prompt is too long")', () => {
    expect(isContextLengthError({ statusCode: 400, message: 'prompt is too long: 215000 tokens > 200000 maximum' })).toBe(
      true,
    );
  });

  test('Gemini overflow ("input token count … exceeds the maximum") — the case the old regex missed', () => {
    expect(
      isContextLengthError({
        statusCode: 400,
        message: 'The input token count (1500000) exceeds the maximum number of tokens allowed (1048575).',
      }),
    ).toBe(true);
  });

  test('reason nested under .cause', () => {
    expect(
      isContextLengthError({ message: 'AI_APICallError', cause: { message: 'prompt is too long: 300000 tokens' } }),
    ).toBe(true);
  });

  test('a plain overflow string still classifies', () => {
    expect(isContextLengthError('context length exceeded')).toBe(true);
  });

  test('NON-overflow errors do NOT misclassify (would loop the user forever on reply-to-resume)', () => {
    expect(isContextLengthError({ statusCode: 500, message: 'Internal server error', responseBody: 'upstream timeout' })).toBe(
      false,
    );
    expect(isContextLengthError({ statusCode: 429, message: 'Rate limit reached for gpt-4o' })).toBe(false);
    expect(isContextLengthError(new Error('ECONNRESET'))).toBe(false);
    expect(isContextLengthError(null)).toBe(false);
  });
});

describe('runTaskAgent — a provider overflow 400 resolves as context_exhausted', () => {
  test('a hard context-length 400 (not an abort) → context_exhausted, NOT system_error, and is not sent to Sentry', async () => {
    (generateText as jest.Mock).mockImplementation(async () => {
      // The provider rejected the over-long prompt before any step ran — the
      // soft-stop never got a usage reading to trip on. This is the belt to the
      // soft-stop's suspenders.
      throw Object.assign(new Error('Bad Request'), {
        statusCode: 400,
        responseBody:
          '{"error":{"message":"This model\'s maximum context length is 128000 tokens. However, your messages resulted in 150000 tokens.","code":"context_length_exceeded"}}',
      });
    });
    await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('context_exhausted');
    // A deterministic overflow is NOT a transient infra hiccup — it must not
    // page Sentry (only genuine loop errors do).
    expect(captureInfraError).not.toHaveBeenCalled();
  });
});

describe('runTaskAgent — novelty-aware stall detection', () => {
  const abortIfSignalled = (opts: any) => {
    if (opts.abortSignal?.aborted) {
      const e = new Error('aborted');
      (e as any).name = 'AbortError';
      throw e;
    }
  };

  test('7+ DISTINCT read-only calls across steps is investigation, not a stall', async () => {
    (generateText as jest.Mock).mockImplementation(async (opts: any) => {
      const state = capturedState();
      for (let i = 0; i < 8; i++) {
        state.novelCalls++; // each step read/listed/grepped something NEW
        await opts.onStepFinish({ text: '' });
        abortIfSignalled(opts);
      }
      return {};
    });
    await runTaskAgent({} as any, makeInput(), makeDeps());
    // No stall abort: the run ends through the ordinary no-PR fallback.
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('not_fixable');
  });

  test('6 steps of pure repetition (nothing new at all) aborts with category stall', async () => {
    (generateText as jest.Mock).mockImplementation(async (opts: any) => {
      const state = capturedState();
      state.novelCalls = 3; // some earlier investigation happened...
      for (let i = 0; i < 12; i++) {
        // ...but every later step only repeats calls already made (no novelty,
        // no side-effecting progress).
        await opts.onStepFinish({ text: '' });
        abortIfSignalled(opts);
      }
      return {};
    });
    await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('stall');
    // error_message stays the internal wording; the user copy lives in finalizeFailure.
    expect((finalizeFailure as jest.Mock).mock.calls[0][2]).toMatch(/stopped making progress/i);
  });

  test('a wall-clock abort still finalizes as budget_exhausted (the time-limit copy)', async () => {
    jest.useFakeTimers();
    try {
      (generateText as jest.Mock).mockImplementation(async (opts: any) => {
        // Fire the 30-min wall timer.
        jest.advanceTimersByTime(31 * 60 * 1000);
        abortIfSignalled(opts);
        return {};
      });
      await runTaskAgent({} as any, makeInput(), makeDeps());
    } finally {
      jest.useRealTimers();
    }
    expect(finalizeFailure).toHaveBeenCalledTimes(1);
    expect((finalizeFailure as jest.Mock).mock.calls[0][1]).toBe('budget_exhausted');
    expect((finalizeFailure as jest.Mock).mock.calls[0][2]).toMatch(/time budget/);
  });
});

describe('runTaskAgent — resume mode', () => {
  const PRIOR = { branch: 'aegis/fix-x-abc', number: 7, url: 'https://github.com/o/r/pull/7', repoFullName: 'o/r' };

  test('a first run pins to the base SHA, uses the prompt path, and returns a null watermark', async () => {
    (generateText as jest.Mock).mockImplementation(async () => ({}));
    const res = await runTaskAgent({} as any, makeInput(), makeDeps());
    expect(res).toEqual({ replayedThrough: null, cancelled: false });
    expect(cloneAtSha).toHaveBeenCalledTimes(1);
    expect(cloneBranchHead).not.toHaveBeenCalled();
    const call = (generateText as jest.Mock).mock.calls[0][0];
    expect(call.prompt).toBeDefined();
    expect(call.messages).toBeUndefined();
  });

  test('a resume with an OPEN prior PR clones the PR branch, replays the thread, and returns the watermark', async () => {
    (generateText as jest.Mock).mockImplementation(async () => ({}));
    const res = await runTaskAgent(
      {} as any,
      makeInput({ resume: true, runSeq: 1, priorPr: { ...PRIOR } }),
      makeDeps(),
    );
    expect(res).toEqual({ replayedThrough: '2026-07-03T00:00:00Z', cancelled: false });
    // The amend clone also fetches the BASE ref so the agent can compare
    // against / restore files from origin/<base> (the lockfile-heal gap).
    expect(cloneBranchHead).toHaveBeenCalledWith(
      expect.objectContaining({ branch: 'aegis/fix-x-abc', alsoFetchBranch: 'main' }),
    );
    expect(cloneAtSha).not.toHaveBeenCalled();
    const call = (generateText as jest.Mock).mock.calls[0][0];
    expect(call.messages).toEqual([{ role: 'user', content: 'replayed brief' }]);
    expect(call.prompt).toBeUndefined();
    // Amend-mode resume system names the PR it will update + the base ref,
    // and carries the shared anti-imitation instruction (a weak model must
    // not mimic the replay transcript as prose instead of calling tools).
    expect(String(call.system)).toContain('pull request #7');
    expect(String(call.system)).toContain('origin/main');
    expect(String(call.system)).toContain('never write a command as prose');
  });

  test('the amend resume system names the actual base branch (origin/master)', async () => {
    (generateText as jest.Mock).mockImplementation(async () => ({}));
    await runTaskAgent(
      {} as any,
      makeInput({ resume: true, runSeq: 1, priorPr: { ...PRIOR }, baseBranch: 'master' }),
      makeDeps(),
    );
    expect(cloneBranchHead).toHaveBeenCalledWith(expect.objectContaining({ alsoFetchBranch: 'master' }));
    const call = (generateText as jest.Mock).mock.calls[0][0];
    expect(String(call.system)).toContain('origin/master');
    expect(String(call.system)).toContain('git checkout origin/master --');
  });

  test('a resume whose prior PR is CLOSED clones the base tip and uses the no-PR resume system', async () => {
    (getPullRequestState as jest.Mock).mockResolvedValueOnce('closed');
    (generateText as jest.Mock).mockImplementation(async () => ({}));
    await runTaskAgent({} as any, makeInput({ resume: true, runSeq: 2, priorPr: { ...PRIOR } }), makeDeps());
    // Fallback clones the CURRENT base tip (not the stale accept-time SHA).
    expect(cloneBranchHead).toHaveBeenCalledWith(expect.objectContaining({ branch: 'main' }));
    expect(cloneAtSha).not.toHaveBeenCalled();
    const call = (generateText as jest.Mock).mock.calls[0][0];
    expect(String(call.system)).toContain('No open pull request');
  });

  test('a resume of a COMPLETED task whose PR was merged uses the prior-success system paragraph', async () => {
    (getPullRequestState as jest.Mock).mockResolvedValueOnce('closed');
    (generateText as jest.Mock).mockImplementation(async () => ({}));
    await runTaskAgent(
      {} as any,
      makeInput({ resume: true, runSeq: 1, resumePriorStatus: 'completed', priorPr: { ...PRIOR } }),
      makeDeps(),
    );
    const call = (generateText as jest.Mock).mock.calls[0][0];
    // The model must know the fix already stands and must never finish "failed".
    expect(String(call.system)).toContain('merged or closed');
    expect(String(call.system)).toContain('never "failed"');
  });

  test('an UNKNOWN prior-PR state throws (retryable) instead of forking a duplicate PR', async () => {
    (getPullRequestState as jest.Mock).mockResolvedValueOnce('unknown');
    await expect(
      runTaskAgent({} as any, makeInput({ resume: true, runSeq: 1, priorPr: { ...PRIOR } }), makeDeps()),
    ).rejects.toThrow(/Could not verify the state of the existing pull request/);
    expect(cloneBranchHead).not.toHaveBeenCalled();
    expect(cloneAtSha).not.toHaveBeenCalled();
    expect(generateText).not.toHaveBeenCalled();
  });

  test('an amend-clone failure that is NOT a missing branch rethrows (no duplicate-PR fallback)', async () => {
    (cloneBranchHead as jest.Mock).mockRejectedValueOnce(new Error('git clone failed: network unreachable'));
    await expect(
      runTaskAgent({} as any, makeInput({ resume: true, runSeq: 1, priorPr: { ...PRIOR } }), makeDeps()),
    ).rejects.toThrow(/network unreachable/);
    // No fresh-tip fallback clone, no model run.
    expect(cloneBranchHead).toHaveBeenCalledTimes(1);
    expect(generateText).not.toHaveBeenCalled();
  });

  test('an amend-clone failure for a MISSING branch falls through to the fresh-tip clone', async () => {
    (cloneBranchHead as jest.Mock).mockRejectedValueOnce(
      new Error('git clone failed: fatal: Remote branch aegis/fix-x-abc not found in upstream origin'),
    );
    (generateText as jest.Mock).mockImplementation(async () => ({}));
    await runTaskAgent({} as any, makeInput({ resume: true, runSeq: 1, priorPr: { ...PRIOR } }), makeDeps());
    // First call = PR branch (rejected), second = base tip fallback.
    expect(cloneBranchHead).toHaveBeenCalledTimes(2);
    expect((cloneBranchHead as jest.Mock).mock.calls[1][0]).toEqual(expect.objectContaining({ branch: 'main' }));
    const call = (generateText as jest.Mock).mock.calls[0][0];
    expect(String(call.system)).toContain('No open pull request');
  });
});
