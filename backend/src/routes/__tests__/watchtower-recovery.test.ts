/**
 * Phase 10B: Watchtower recovery endpoint unit tests
 */

const chain = {
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  order: jest.fn().mockReturnThis(),
  limit: jest.fn().mockResolvedValue({ data: [], error: null }),
};
const mockRpc = jest.fn().mockResolvedValue({ data: 0, error: null });
jest.mock('../../lib/supabase', () => ({
  supabase: {
    rpc: (...args: unknown[]) => mockRpc(...args),
    from: jest.fn(() => chain),
  },
}));

const mockStartWatchtowerMachine = jest.fn().mockResolvedValue('fly-wt-id');
jest.mock('../../../../ee/backend/lib/fly-machines', () => ({
  startWatchtowerMachine: (...args: unknown[]) => mockStartWatchtowerMachine(...args),
}));

process.env.INTERNAL_API_KEY = 'test-internal-key';

import request from 'supertest';
import express from 'express';
import watchtowerRecoveryRouter from '../watchtower-recovery';

const app = express();
app.use(express.json());
app.use('/api/internal/recovery', watchtowerRecoveryRouter);

const originalEnv = process.env.INTERNAL_API_KEY;

beforeEach(() => {
  jest.clearAllMocks();
  process.env.INTERNAL_API_KEY = 'test-internal-key';
  mockRpc.mockResolvedValue({ data: 0, error: null });
  chain.limit.mockResolvedValue({ data: [], error: null });
});

afterAll(() => {
  process.env.INTERNAL_API_KEY = originalEnv;
});

describe('POST /api/internal/recovery/watchtower-jobs', () => {
  it('requires X-Internal-Api-Key header', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .send({});

    expect(res.status).toBe(401);
    expect(res.body.error).toBe('Unauthorized');
  });

  it('returns 401 with wrong key', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('X-Internal-Api-Key', 'wrong-key')
      .send({});

    expect(res.status).toBe(401);
  });

  it('accepts valid key and returns JSON with recovered and machines_started', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('recovered');
    expect(res.body).toHaveProperty('orphaned_jobs_found');
    expect(res.body).toHaveProperty('machines_started');
    expect(mockRpc).toHaveBeenCalledWith('recover_stuck_watchtower_jobs');
  });

  it('accepts Bearer token as key', async () => {
    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('Authorization', 'Bearer test-internal-key')
      .send({});

    expect(res.status).toBe(200);
  });

  it('returns recovered count from RPC', async () => {
    mockRpc.mockResolvedValueOnce({ data: 2, error: null });

    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.recovered).toBe(2);
  });

  it('starts watchtower machine when orphaned queued jobs exist', async () => {
    chain.limit.mockResolvedValueOnce({
      data: [{ id: 'job-1' }],
      error: null,
    });

    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.orphaned_jobs_found).toBe(1);
    expect(res.body.machines_started).toBe(1);
    expect(mockStartWatchtowerMachine).toHaveBeenCalled();
  });

  it('returns 500 when recover_stuck_watchtower_jobs RPC fails', async () => {
    mockRpc.mockRejectedValueOnce(new Error('DB connection failed'));

    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(500);
    expect(res.body.error).toBeDefined();
  });

  it('returns 200 with machines_started 0 when startWatchtowerMachine throws', async () => {
    chain.limit.mockResolvedValueOnce({
      data: [{ id: 'job-1' }],
      error: null,
    });
    mockStartWatchtowerMachine.mockRejectedValueOnce(new Error('FLY_API_TOKEN missing'));

    const res = await request(app)
      .post('/api/internal/recovery/watchtower-jobs')
      .set('X-Internal-Api-Key', 'test-internal-key')
      .send({});

    expect(res.status).toBe(200);
    expect(res.body.orphaned_jobs_found).toBe(1);
    expect(res.body.machines_started).toBe(0);
  });
});
