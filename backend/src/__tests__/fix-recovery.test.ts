import express from 'express';
import request from 'supertest';

import {
  setRpcResponse,
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
  supabase,
} from '../test/mocks/supabaseSingleton';

// The crash-wake path re-queues a woken row to 'approved', which the orphan
// sweep then tries to boot — stub the Fly client so no real API call happens.
jest.mock('../lib/fly-machines', () => ({
  startFixMachine: jest.fn().mockResolvedValue('machine-1'),
}));

// Smoke for the fix-recovery cron endpoint. Two regressions worth pinning:
//
//  1. recover_stuck_fix_jobs returns SETOF project_security_fixes (not int).
//     A previous migration changed it to RETURNS integer and the handler kept
//     iterating it as an array, silently swallowing recovery notifications and
//     reporting requeuedCount=0. Make sure handler iterates rows and reports
//     the right count.
//  2. fail_exhausted_fix_jobs filters status='executing' (the v1 lifecycle),
//     not the legacy 'running'. We can't reach into the SQL from a unit test,
//     but we can at least verify the handler iterates returned rows correctly
//     when the RPC returns rows.

process.env.INTERNAL_API_KEY = 'test-internal-key';

import fixRecoveryRouter from '../routes/fix-recovery';

function makeApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/internal/recovery', fixRecoveryRouter);
  return app;
}

beforeEach(() => {
  clearTableRegistry();
  clearRpcRegistry();
  jest.clearAllMocks();
});

function wakeRpcCalls() {
  return (supabase.rpc as jest.Mock).mock.calls.filter((c: any[]) => c[0] === 'wake_agent_fix');
}

describe('POST /api/internal/recovery/fix-jobs', () => {
  it('rejects without internal key', async () => {
    const res = await request(makeApp()).post('/api/internal/recovery/fix-jobs');
    expect(res.status).toBe(401);
  });

  it('reports requeued/failed counts and iterates recovered rows', async () => {
    setRpcResponse('recover_stuck_fix_jobs', {
      data: [
        { id: 'fix-1', project_id: 'proj-1', run_id: 'run-1', attempts: 1 },
        { id: 'fix-2', project_id: 'proj-2', run_id: 'run-2', attempts: 2 },
      ],
      error: null,
    });
    setRpcResponse('fail_exhausted_fix_jobs', {
      data: [{ id: 'fix-3', project_id: 'proj-3', run_id: 'run-3', attempts: 3 }],
      error: null,
    });
    // No orphaned approved jobs so the route doesn't try to spin up Fly.
    setTableResponse('project_security_fixes', 'then', { data: [], error: null });
    // Per-job extraction_logs inserts use .insert(...).then() — register an
    // OK shape so the chain doesn't reject.
    setTableResponse('extraction_logs', 'then', { data: null, error: null });

    const res = await request(makeApp())
      .post('/api/internal/recovery/fix-jobs')
      .set('x-internal-api-key', 'test-internal-key');
    expect(res.status).toBe(200);
    expect(res.body.requeued).toBe(2);
    expect(res.body.failed).toBe(1);
  });

  it('handles empty RPC results without crashing', async () => {
    setRpcResponse('recover_stuck_fix_jobs', { data: [], error: null });
    setRpcResponse('fail_exhausted_fix_jobs', { data: [], error: null });
    setTableResponse('project_security_fixes', 'then', { data: [], error: null });

    const res = await request(makeApp())
      .post('/api/internal/recovery/fix-jobs')
      .set('x-internal-api-key', 'test-internal-key');
    expect(res.status).toBe(200);
    expect(res.body.requeued).toBe(0);
    expect(res.body.failed).toBe(0);
  });
});

// Crash-wake: a machine crash mid-run strands any follow-up the user sent
// during that run (the worker's end-of-run drain never ran). The cron must
// re-queue such rows via wake_agent_fix — and ONLY such rows.
describe('POST /api/internal/recovery/fix-jobs crash-wake', () => {
  const failedAgentJob = {
    id: 'fix-3',
    project_id: 'proj-3',
    run_id: 'run-3',
    attempts: 1,
    strategy: 'agent',
    thread_id: 'thread-1',
    task_id: 'task-1',
    started_at: '2026-07-01T00:00:00Z',
    approved_at: '2026-06-30T23:59:00Z',
  };

  function post() {
    return request(makeApp())
      .post('/api/internal/recovery/fix-jobs')
      .set('x-internal-api-key', 'test-internal-key');
  }

  it('re-queues a failed agent row whose thread has a user message newer than the run', async () => {
    setRpcResponse('recover_stuck_fix_jobs', { data: [], error: null });
    setRpcResponse('fail_exhausted_fix_jobs', { data: [failedAgentJob], error: null });
    setRpcResponse('wake_agent_fix', { data: 'fix-3', error: null });
    // Single agent row for the task (v1 guard passes); the same response also
    // serves the orphan sweep, which then boots the stubbed machine.
    setTableResponse('project_security_fixes', 'then', { data: [{ id: 'fix-3' }], error: null });
    setTableResponse('aegis_chat_messages', 'then', { data: [{ id: 'msg-1' }], error: null });
    setTableResponse('extraction_logs', 'then', { data: null, error: null });

    const res = await post();
    expect(res.status).toBe(200);
    expect(res.body.crash_wakes).toBe(1);
    const wakes = wakeRpcCalls();
    expect(wakes).toHaveLength(1);
    expect(wakes[0][1]).toEqual({ p_fix_id: 'fix-3' });
  });

  it('does NOT wake when no user message arrived during the run', async () => {
    setRpcResponse('recover_stuck_fix_jobs', { data: [], error: null });
    setRpcResponse('fail_exhausted_fix_jobs', { data: [failedAgentJob], error: null });
    setTableResponse('project_security_fixes', 'then', { data: [{ id: 'fix-3' }], error: null });
    setTableResponse('aegis_chat_messages', 'then', { data: [], error: null });
    setTableResponse('extraction_logs', 'then', { data: null, error: null });

    const res = await post();
    expect(res.status).toBe(200);
    expect(res.body.crash_wakes).toBe(0);
    expect(wakeRpcCalls()).toHaveLength(0);
  });

  it('skips multi-agent-row tasks (v1: single-target only)', async () => {
    setRpcResponse('recover_stuck_fix_jobs', { data: [], error: null });
    setRpcResponse('fail_exhausted_fix_jobs', { data: [failedAgentJob], error: null });
    setTableResponse('project_security_fixes', 'then', { data: [{ id: 'fix-3' }, { id: 'fix-4' }], error: null });
    setTableResponse('aegis_chat_messages', 'then', { data: [{ id: 'msg-1' }], error: null });
    setTableResponse('extraction_logs', 'then', { data: null, error: null });

    const res = await post();
    expect(res.status).toBe(200);
    expect(res.body.crash_wakes).toBe(0);
    expect(wakeRpcCalls()).toHaveLength(0);
  });

  it('ignores non-agent rows and rows without a thread', async () => {
    setRpcResponse('recover_stuck_fix_jobs', { data: [], error: null });
    setRpcResponse('fail_exhausted_fix_jobs', {
      data: [
        { ...failedAgentJob, id: 'fix-a', strategy: 'code_patch' },
        { ...failedAgentJob, id: 'fix-b', thread_id: null },
      ],
      error: null,
    });
    setTableResponse('project_security_fixes', 'then', { data: [], error: null });
    setTableResponse('aegis_chat_messages', 'then', { data: [{ id: 'msg-1' }], error: null });
    setTableResponse('extraction_logs', 'then', { data: null, error: null });

    const res = await post();
    expect(res.status).toBe(200);
    expect(res.body.crash_wakes).toBe(0);
    expect(wakeRpcCalls()).toHaveLength(0);
  });
});
