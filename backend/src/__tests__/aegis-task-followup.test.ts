/**
 * Unit tests for the Wake-the-Task-Agent backend lib:
 *
 *   - sendTaskFollowup: persists the user turn, then idempotently wakes the
 *     task's agent fix row via the wake_agent_fix RPC (which does ALL re-open
 *     housekeeping itself). Terminal target -> woke + machine boot; active
 *     target -> queued (the worker's end-of-run drain picks the message up);
 *     zero-fix task -> canned "nothing in progress" reply; cross-org -> 404
 *     shaped error BEFORE any write.
 *
 *   - cancelTask Stop-restore split: an UNCLAIMED resume of a previously
 *     COMPLETED task (plan.resume + plan.prior_status='completed', not yet
 *     executing) is restored to 'completed' instead of 'rejected' — rejecting
 *     it would downgrade the original success in the rollup. Claimed
 *     (executing) rows still flip to 'rejected' so the worker aborts.
 */
import {
  setTableResponse,
  pushTableResponse,
  setRpcResponse,
  clearTableRegistry,
  clearRpcRegistry,
  supabase,
  queryBuilder,
} from '../test/mocks/supabaseSingleton';

jest.mock('../lib/fly-machines', () => ({
  startFixMachine: jest.fn().mockResolvedValue('machine-1'),
}));

// acceptTask fans out via insertAgentFixRow (which stamps the clone base from
// the live GitHub API) — stub it so the brief-enrichment tests can assert the
// findingBrief it receives without network.
jest.mock('../lib/aegis-v3/fix-request', () => ({
  insertAgentFixRow: jest.fn(),
}));

import { startFixMachine } from '../lib/fly-machines';
import { insertAgentFixRow } from '../lib/aegis-v3/fix-request';
import {
  sendTaskFollowup,
  cancelTask,
  acceptTask,
  vulnDependencyNote,
} from '../lib/aegis-v3/tasks';
import type { AegisTaskTarget } from '../lib/aegis-v3/task-types';

const ORG_A = '00000000-0000-0000-0000-0000000000a1';
const ORG_B = '00000000-0000-0000-0000-0000000000b1';
const TASK_ID = '00000000-0000-0000-0000-0000000000t1';
const THREAD_ID = '00000000-0000-0000-0000-0000000000d1';
const FIX_ID = '00000000-0000-0000-0000-0000000000f1';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const PROJECT_ID = '00000000-0000-0000-0000-0000000000c1';

const rpcMock = supabase.rpc as jest.Mock;

function wakeRpcCalls() {
  return rpcMock.mock.calls.filter((c: any[]) => c[0] === 'wake_agent_fix');
}

/** insert() calls that wrote a user chat message (saveUserMessage). */
function userMessageInsertCalls() {
  return (queryBuilder.insert as jest.Mock).mock.calls
    .map((c: any[], i: number) => ({ args: c[0], i }))
    .filter((c) => c.args && c.args.role === 'user' && c.args.thread_id === THREAD_ID);
}

/** insert() calls that wrote an assistant chat message (postTaskOpeningMessage). */
function assistantMessageInsertCalls() {
  return (queryBuilder.insert as jest.Mock).mock.calls
    .map((c: any[]) => c[0])
    .filter((a) => a && a.role === 'assistant' && a.thread_id === THREAD_ID);
}

function setTask(row: any) {
  setTableResponse('aegis_agent_tasks', 'maybeSingle', { data: row, error: null });
}

function setAgentFixRows(rows: any[]) {
  setTableResponse('project_security_fixes', 'then', { data: rows, error: null });
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  jest.clearAllMocks();
});

describe('sendTaskFollowup', () => {
  const args = { taskId: TASK_ID, userId: USER_ID, organizationId: ORG_A, message: 'bump it to v3 instead' };

  it('wakes a terminal target: saves the message BEFORE the rpc, boots one machine', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: THREAD_ID, status: 'completed' });
    setAgentFixRows([{ id: FIX_ID, status: 'completed' }]);
    setRpcResponse('wake_agent_fix', { data: FIX_ID, error: null });

    const result = await sendTaskFollowup(args);
    expect(result).toEqual({ woke: true, queued: false, threadId: THREAD_ID });

    // The user turn was persisted with the chat path's shape...
    const msgInserts = userMessageInsertCalls();
    expect(msgInserts).toHaveLength(1);
    expect(msgInserts[0].args.content).toBe('bump it to v3 instead');
    expect(msgInserts[0].args.metadata).toEqual({
      parts: [{ type: 'text', text: 'bump it to v3 instead' }],
    });

    // ...BEFORE the wake rpc fired (so a failed wake never loses the message).
    const wakes = wakeRpcCalls();
    expect(wakes).toHaveLength(1);
    expect(wakes[0][1]).toEqual({ p_fix_id: FIX_ID });
    const insertOrder = (queryBuilder.insert as jest.Mock).mock.invocationCallOrder[msgInserts[0].i];
    const rpcIdx = rpcMock.mock.calls.findIndex((c: any[]) => c[0] === 'wake_agent_fix');
    const rpcOrder = rpcMock.mock.invocationCallOrder[rpcIdx];
    expect(insertOrder).toBeLessThan(rpcOrder);

    expect(startFixMachine).toHaveBeenCalledTimes(1);
  });

  it('queues on an active target (rpc returns null): no machine boot', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: THREAD_ID, status: 'working' });
    setAgentFixRows([{ id: FIX_ID, status: 'executing' }]);
    setRpcResponse('wake_agent_fix', { data: null, error: null });

    const result = await sendTaskFollowup(args);
    expect(result).toEqual({ woke: false, queued: true, threadId: THREAD_ID });
    expect(userMessageInsertCalls()).toHaveLength(1);
    expect(startFixMachine).not.toHaveBeenCalled();
  });

  it('cross-org: rejects BEFORE saving the message or waking', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_B, thread_id: THREAD_ID, status: 'completed' });

    await expect(sendTaskFollowup(args)).rejects.toThrow('Task not in current organization');
    expect(userMessageInsertCalls()).toHaveLength(0);
    expect(wakeRpcCalls()).toHaveLength(0);
  });

  it('zero-fix task: posts the canned "nothing in progress" reply, never wakes', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: THREAD_ID, status: 'completed' });
    setAgentFixRows([]);

    const result = await sendTaskFollowup(args);
    expect(result).toEqual({ woke: false, queued: false, threadId: THREAD_ID });
    const assistant = assistantMessageInsertCalls();
    expect(assistant).toHaveLength(1);
    expect(assistant[0].content).toContain("nothing in progress");
    expect(wakeRpcCalls()).toHaveLength(0);
    expect(startFixMachine).not.toHaveBeenCalled();
  });

  it('swallows a machine-boot failure: still reports woke (recovery cron is the backstop)', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: THREAD_ID, status: 'failed' });
    setAgentFixRows([{ id: FIX_ID, status: 'failed' }]);
    setRpcResponse('wake_agent_fix', { data: FIX_ID, error: null });
    (startFixMachine as jest.Mock).mockRejectedValueOnce(new Error('fly is down'));

    const result = await sendTaskFollowup(args);
    expect(result).toEqual({ woke: true, queued: false, threadId: THREAD_ID });
  });

  it('throws when the task has no chat thread', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: null, status: 'completed' });
    await expect(sendTaskFollowup(args)).rejects.toThrow('Task has no chat thread');
    expect(userMessageInsertCalls()).toHaveLength(0);
  });

  it('throws on a wake_agent_fix RPC error (a terminal row must never report queued)', async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: THREAD_ID, status: 'completed' });
    setAgentFixRows([{ id: FIX_ID, status: 'completed' }]);
    setRpcResponse('wake_agent_fix', { data: null, error: { message: 'connection reset' } });

    await expect(sendTaskFollowup(args)).rejects.toThrow(
      'Failed to wake the task agent: connection reset',
    );
    expect(startFixMachine).not.toHaveBeenCalled();
  });

  it("proposed task: posts the not-accepted-yet reply, never looks up fixes or wakes", async () => {
    setTask({ id: TASK_ID, organization_id: ORG_A, thread_id: THREAD_ID, status: 'proposed' });

    const result = await sendTaskFollowup(args);
    expect(result).toEqual({ woke: false, queued: false, threadId: THREAD_ID });
    // The message is still persisted (visible in the thread)...
    expect(userMessageInsertCalls()).toHaveLength(1);
    // ...but the reply is the accept nudge, not the misleading "nothing in
    // progress" one, and no fix-row lookup / wake / boot happens.
    const assistant = assistantMessageInsertCalls();
    expect(assistant).toHaveLength(1);
    expect(assistant[0].content).toContain("hasn't been accepted yet");
    const fixReads = (supabase.from as jest.Mock).mock.calls.filter(
      (c: any[]) => c[0] === 'project_security_fixes',
    );
    expect(fixReads).toHaveLength(0);
    expect(wakeRpcCalls()).toHaveLength(0);
    expect(startFixMachine).not.toHaveBeenCalled();
  });

  it('throws Task not found for a missing task', async () => {
    setTask(null);
    await expect(sendTaskFollowup(args)).rejects.toThrow('Task not found');
  });
});

describe('cancelTask Stop-restore split', () => {
  const args = { taskId: TASK_ID, userId: USER_ID, organizationId: ORG_A };

  function updateCallsWithStatus(status: string) {
    return (queryBuilder.update as jest.Mock).mock.calls
      .map((c: any[]) => c[0])
      .filter((a) => a && a.status === status);
  }
  /** Every .in() call in order — pins the atomic status guards on the writes. */
  function allInCalls(): any[][] {
    return (queryBuilder.in as jest.Mock).mock.calls.map((c: any[]) => [c[0], c[1]]);
  }
  const CANDIDATE_STATUSES = ['planning', 'approved', 'executing'];
  const UNCLAIMED_STATUSES = ['planning', 'approved'];

  beforeEach(() => {
    setTask({ id: TASK_ID, organization_id: ORG_A });
  });

  it('restores an UNCLAIMED (approved) resume of a completed task instead of rejecting it', async () => {
    setAgentFixRows([
      { id: FIX_ID, status: 'approved', plan: { strategy: 'agent', resume: true, prior_status: 'completed' } },
    ]);

    const { cancelled } = await cancelTask(args);
    expect(cancelled).toBe(0);

    const restores = updateCallsWithStatus('completed');
    expect(restores).toHaveLength(1);
    expect(restores[0].completed_at).toEqual(expect.any(String));
    expect(updateCallsWithStatus('rejected')).toHaveLength(0);
    // The restore write re-verifies UNCLAIMED status (a worker claiming the row
    // to 'executing' between the SELECT and this UPDATE must win).
    expect(allInCalls()).toEqual([
      ['status', CANDIDATE_STATUSES], // candidates SELECT
      ['id', [FIX_ID]],               // restore write...
      ['status', UNCLAIMED_STATUSES], // ...guarded to unclaimed rows only
    ]);
  });

  it('still rejects an EXECUTING resume-of-completed (the worker must see rejected to abort)', async () => {
    setAgentFixRows([
      { id: FIX_ID, status: 'executing', plan: { strategy: 'agent', resume: true, prior_status: 'completed' } },
    ]);

    const { cancelled } = await cancelTask(args);
    expect(cancelled).toBe(1);
    expect(updateCallsWithStatus('completed')).toHaveLength(0);
    const rejects = updateCallsWithStatus('rejected');
    expect(rejects).toHaveLength(1);
    expect(rejects[0].rejected_by_user_id).toBe(USER_ID);
    // The reject write re-verifies in-flight status (a row that reached a
    // terminal state between the SELECT and this UPDATE must not be clobbered).
    expect(allInCalls()).toEqual([
      ['status', CANDIDATE_STATUSES], // candidates SELECT
      ['id', [FIX_ID]],               // reject write...
      ['status', CANDIDATE_STATUSES], // ...guarded to still-in-flight rows
    ]);
  });

  it('rejects a plain first-run executing row (no resume plan)', async () => {
    setAgentFixRows([
      { id: FIX_ID, status: 'executing', plan: { strategy: 'agent', summary: 'fix it' } },
    ]);

    const { cancelled } = await cancelTask(args);
    expect(cancelled).toBe(1);
    expect(updateCallsWithStatus('completed')).toHaveLength(0);
    expect(updateCallsWithStatus('rejected')).toHaveLength(1);
  });

  it('splits a mixed set: restores the unclaimed resume, rejects the rest', async () => {
    const OTHER = '00000000-0000-0000-0000-0000000000f2';
    setAgentFixRows([
      { id: FIX_ID, status: 'approved', plan: { resume: true, prior_status: 'completed' } },
      { id: OTHER, status: 'executing', plan: { resume: true, prior_status: 'completed' } },
    ]);

    const { cancelled } = await cancelTask(args);
    expect(cancelled).toBe(1);
    expect(updateCallsWithStatus('completed')).toHaveLength(1);
    expect(updateCallsWithStatus('rejected')).toHaveLength(1);
    expect(allInCalls()).toEqual([
      ['status', CANDIDATE_STATUSES], // candidates SELECT
      ['id', [FIX_ID]],               // restore write
      ['status', UNCLAIMED_STATUSES],
      ['id', [OTHER]],                // reject write
      ['status', CANDIDATE_STATUSES],
    ]);
  });

  it('does not restore a resume of a FAILED prior run (prior_status !== completed)', async () => {
    setAgentFixRows([
      { id: FIX_ID, status: 'approved', plan: { resume: true, prior_status: 'failed' } },
    ]);

    const { cancelled } = await cancelTask(args);
    expect(cancelled).toBe(1);
    expect(updateCallsWithStatus('completed')).toHaveLength(0);
    expect(updateCallsWithStatus('rejected')).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Brief enrichment: vulnDependencyNote tells the agent up front whether the
// vulnerable package is direct or transitive (live e2e: it otherwise burns a
// run discovering transitivity by spelunking the lockfile) + the fixed version.
// ---------------------------------------------------------------------------

const VULN_TARGET: AegisTaskTarget = {
  findingType: 'vulnerability',
  findingKey: 'fk-setvalue',
  projectId: PROJECT_ID,
  label: 'set-value CVE-2021-23440',
};

function setActiveRun(runId: string | null) {
  setTableResponse('projects', 'single', {
    data: { active_extraction_run_id: runId },
    error: null,
  });
}
function setVulnRow(row: any) {
  setTableResponse('project_dependency_vulnerabilities', 'maybeSingle', { data: row, error: null });
}
function setDepRow(row: any) {
  setTableResponse('project_dependencies', 'maybeSingle', { data: row, error: null });
}

describe('vulnDependencyNote', () => {
  it('transitive dep -> overrides/resolutions note with the fixed version', async () => {
    setActiveRun('run-1');
    setVulnRow({ project_dependency_id: 'pd-1', fixed_versions: ['3.36.0'] });
    setDepRow({ name: 'set-value', version: '2.0.0', is_direct: false });

    const note = await vulnDependencyNote(VULN_TARGET);
    expect(note).toContain('set-value@2.0.0 is a TRANSITIVE dependency');
    expect(note).toContain('"overrides" (npm) or "resolutions" (yarn)');
    expect(note).toContain('(>= 3.36.0)');
    expect(note).toContain('do not hand-edit the lockfile');
  });

  it('direct dep -> manifest note with the fixed version', async () => {
    setActiveRun('run-1');
    setVulnRow({ project_dependency_id: 'pd-1', fixed_versions: ['4.17.21'] });
    setDepRow({ name: 'lodash', version: '4.17.20', is_direct: true });

    const note = await vulnDependencyNote(VULN_TARGET);
    expect(note).toContain('lodash@4.17.20 is a direct dependency listed in the project manifest');
    expect(note).toContain('the fixed version is 4.17.21');
    expect(note).not.toContain('TRANSITIVE');
  });

  it('returns null when the vuln row is missing', async () => {
    setActiveRun('run-1');
    setVulnRow(null);
    expect(await vulnDependencyNote(VULN_TARGET)).toBeNull();
  });

  it('returns null when the dependency row is missing', async () => {
    setActiveRun('run-1');
    setVulnRow({ project_dependency_id: 'pd-1', fixed_versions: [] });
    setDepRow(null);
    expect(await vulnDependencyNote(VULN_TARGET)).toBeNull();
  });

  it('omits the version clause when fixed_versions is empty', async () => {
    setActiveRun(null); // also covers the no-active-run fallback path
    setVulnRow({ project_dependency_id: 'pd-1', fixed_versions: [] });
    setDepRow({ name: 'set-value', version: '2.0.0', is_direct: false });

    const note = await vulnDependencyNote(VULN_TARGET);
    expect(note).toContain('TRANSITIVE');
    expect(note).not.toContain('>=');
  });

  it('cites the semver-max across multiple fixed versions (one per affected range)', async () => {
    setActiveRun('run-1');
    setVulnRow({ project_dependency_id: 'pd-1', fixed_versions: ['1.2.3', '2.0.1', '1.9.9'] });
    setDepRow({ name: 'set-value', version: '1.0.0', is_direct: true });

    const note = await vulnDependencyNote(VULN_TARGET);
    expect(note).toContain('the fixed version is 2.0.1');
  });

  it('returns null for non-vulnerability targets without querying', async () => {
    const note = await vulnDependencyNote({ ...VULN_TARGET, findingType: 'semgrep' });
    expect(note).toBeNull();
    expect(supabase.from as jest.Mock).not.toHaveBeenCalled();
  });
});

describe('acceptTask brief enrichment', () => {
  const taskRow = {
    id: TASK_ID,
    organization_id: ORG_A,
    project_id: PROJECT_ID,
    thread_id: THREAD_ID, // finding-door shape: thread pre-created
    kind: 'fix',
    title: 'Fix set-value',
    description: 'Fix set-value CVE-2021-23440',
    status: 'proposed',
    source: 'finding',
    targets: [VULN_TARGET],
    total_fixes: 0,
    completed_fixes: 0,
    failed_fixes: 0,
    summary: null,
    accepted_at: null,
    completed_at: null,
    created_at: '2026-07-04T00:00:00Z',
    updated_at: '2026-07-04T00:00:00Z',
  };
  const args = { taskId: TASK_ID, userId: USER_ID, organizationId: ORG_A };

  it('appends the dependency note to the findingBrief handed to insertAgentFixRow', async () => {
    setTask(taskRow);
    // The proposed→working CAS reads back the claimed row via .update().select('id').
    setTableResponse('aegis_agent_tasks', 'then', { data: [{ id: TASK_ID }], error: null });
    setActiveRun('run-1');
    // One PDV maybeSingle response serves BOTH reads (resolveTargetFindingId
    // needs osv_id; the note needs project_dependency_id + fixed_versions).
    setVulnRow({ osv_id: 'GHSA-4jqc-8m5r-9rpr', project_dependency_id: 'pd-1', fixed_versions: ['3.36.0'] });
    setDepRow({ name: 'set-value', version: '2.0.0', is_direct: false });
    (insertAgentFixRow as jest.Mock).mockResolvedValue({ fixId: FIX_ID });

    const { threadId } = await acceptTask(args);
    expect(threadId).toBe(THREAD_ID);
    expect(insertAgentFixRow).toHaveBeenCalledTimes(1);
    const arg = (insertAgentFixRow as jest.Mock).mock.calls[0][0];
    expect(arg.findingBrief).toContain('set-value CVE-2021-23440'); // label kept
    expect(arg.findingBrief).toContain('TRANSITIVE');
    expect(arg.findingBrief).toContain('(>= 3.36.0)');
  });

  it('leaves the brief untouched when the note is unavailable', async () => {
    setTask(taskRow);
    // The proposed→working CAS reads back the claimed row via .update().select('id').
    setTableResponse('aegis_agent_tasks', 'then', { data: [{ id: TASK_ID }], error: null });
    setActiveRun('run-1');
    // Queue mode (no maybeSingle registered): the resolve read finds the vuln,
    // the note read misses — the accept must proceed with the plain brief.
    pushTableResponse('project_dependency_vulnerabilities', {
      data: { osv_id: 'GHSA-4jqc-8m5r-9rpr' },
      error: null,
    });
    pushTableResponse('project_dependency_vulnerabilities', { data: null, error: null });
    setDepRow(null);
    (insertAgentFixRow as jest.Mock).mockResolvedValue({ fixId: FIX_ID });

    await acceptTask(args);
    expect(insertAgentFixRow).toHaveBeenCalledTimes(1);
    const arg = (insertAgentFixRow as jest.Mock).mock.calls[0][0];
    expect(arg.findingBrief).toBe('set-value CVE-2021-23440\n\nFix set-value CVE-2021-23440');
    expect(arg.findingBrief).not.toContain('NOTE:');
  });

  it('a concurrent double-accept (CAS loses the proposed→working flip) does NOT fan out a second set of fixes', async () => {
    setTask(taskRow); // still 'proposed' per the loser's read
    setActiveRun('run-1');
    // The CAS flip matches 0 rows — the other concurrent Accept already claimed it.
    setTableResponse('aegis_agent_tasks', 'then', { data: [], error: null });
    setVulnRow({ osv_id: 'GHSA-4jqc-8m5r-9rpr', project_dependency_id: 'pd-1', fixed_versions: ['3.36.0'] });
    (insertAgentFixRow as jest.Mock).mockResolvedValue({ fixId: FIX_ID });

    const { threadId } = await acceptTask(args);
    expect(threadId).toBe(THREAD_ID); // idempotent — returns the existing thread
    expect(insertAgentFixRow).not.toHaveBeenCalled(); // no second fan-out
  });
});
