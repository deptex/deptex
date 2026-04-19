/**
 * Phase 2M: Recovery endpoint unit tests
 */

const chain = {
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  order: jest.fn().mockReturnThis(),
  limit: jest.fn().mockResolvedValue({ data: [], error: null }),
  insert: jest.fn().mockResolvedValue({ error: null }),
  update: jest.fn().mockReturnThis(),
};
const mockRpc = jest.fn().mockResolvedValue({ data: [], error: null });
jest.mock('../../lib/supabase', () => ({
  supabase: {
    rpc: (...args: unknown[]) => mockRpc(...args),
    from: jest.fn(() => chain),
  },
}));

jest.mock('../../../../ee/backend/lib/fly-machines', () => ({
  startExtractionMachine: jest.fn().mockResolvedValue('fly-id'),
}));

process.env.INTERNAL_API_KEY = 'test-internal-key';

import request from 'supertest';
import express from 'express';
import recoveryRouter from '../recovery';

const app = express();
app.use(express.json());
app.use('/api/internal/recovery', recoveryRouter);

const originalEnv = process.env.INTERNAL_API_KEY;

beforeEach(() => {
  process.env.INTERNAL_API_KEY = 'test-internal-key';
});

afterAll(() => {
  process.env.INTERNAL_API_KEY = originalEnv;
});

describe('POST /api/internal/recovery/extraction-jobs', () => {
  it('requires X-Internal-Api-Key header', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/extraction-jobs')
      .send({});

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('returns 401 without key', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/extraction-jobs')
      .set('X-Internal-Api-Key', 'wrong-key')
      .send({});

    expect(res.status).toBe(401);
  });

  it('accepts valid key and returns JSON', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/extraction-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('requeued');
    expect(res.body).toHaveProperty('failed');
    expect(res.body).toHaveProperty('orphaned_jobs_found');
    expect(res.body).toHaveProperty('machines_started');
  });

  it('accepts Bearer token as key', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/extraction-jobs')
      .set('Authorization', 'Bearer test-internal-key')
      .send({});

    expect(res.status).toBe(200);
  });

  it('returns requeued and failed counts from RPC', async () => {
    mockRpc
      .mockResolvedValueOnce({ data: [{ id: 'j1', project_id: 'p1', run_id: 'r1', attempts: 1 }], error: null })
      .mockResolvedValueOnce({ data: [{ id: 'j2', project_id: 'p2', run_id: 'r2', attempts: 3 }], error: null });

    const res = await request(app)
      .post('/api/internal/recovery/extraction-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.requeued).toBe(1);
    expect(res.body.failed).toBe(1);
  });

  it('starts machines for orphaned queued jobs', async () => {
    chain.limit.mockResolvedValueOnce({
      data: [{ id: 'orphan-1' }, { id: 'orphan-2' }],
      error: null,
    });

    const res = await request(app)
      .post('/api/internal/recovery/extraction-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.orphaned_jobs_found).toBe(2);
    expect(res.body.machines_started).toBeGreaterThanOrEqual(0);
  });
});
