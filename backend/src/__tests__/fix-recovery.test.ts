import express from 'express';
import request from 'supertest';

import {
  setRpcResponse,
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

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
});

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
