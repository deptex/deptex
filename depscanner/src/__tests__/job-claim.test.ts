/**
 * Phase 2M: Job claim unit tests
 */

process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

const mockRpc = jest.fn();

const mockSupabase = {
  rpc: mockRpc,
  from: jest.fn().mockReturnThis(),
  update: jest.fn().mockReturnThis(),
  select: jest.fn().mockReturnThis(),
  eq: jest.fn().mockReturnThis(),
  single: jest.fn(),
};

import { claimJob } from '../job-db';

describe('claimJob', () => {
  const machineId = 'test-machine-1';

  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('returns the oldest queued job when one exists', async () => {
    const job = {
      id: 'job-1',
      project_id: 'proj-1',
      organization_id: 'org-1',
      status: 'processing',
      run_id: 'run-1',
      machine_id: machineId,
      payload: { repo_full_name: 'owner/repo' },
      attempts: 1,
      max_attempts: 3,
      error: null,
      started_at: new Date().toISOString(),
      heartbeat_at: new Date().toISOString(),
      completed_at: null,
      created_at: new Date().toISOString(),
    };

    mockRpc.mockResolvedValueOnce({ data: [job], error: null });

    // DAST_CREDENTIAL_KEY drives the supported-types list; set it so the test
    // can assert against the full DAST-enabled shape.
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    const result = await claimJob(mockSupabase as any, machineId);

    expect(mockRpc).toHaveBeenCalledWith('claim_scan_job', {
      p_machine_id: machineId,
      p_supported_types: ['extraction', 'dast', 'dast_zap', 'dast_nuclei'],
    });
    expect(result).toEqual(job);
  });

  it('sets status=processing, started_at, machine_id, increments attempts (via RPC)', async () => {
    const job = {
      id: 'job-2',
      status: 'processing',
      started_at: expect.any(String),
      machine_id: machineId,
      attempts: 1,
    };
    mockRpc.mockResolvedValueOnce({ data: [job], error: null });

    const result = await claimJob(mockSupabase as any, machineId);

    expect(result?.status).toBe('processing');
    expect(result?.machine_id).toBe(machineId);
    expect(result?.attempts).toBe(1);
  });

  it('returns null when no queued jobs exist', async () => {
    mockRpc.mockResolvedValueOnce({ data: [], error: null });

    const result = await claimJob(mockSupabase as any, machineId);

    expect(result).toBeNull();
  });

  it('throws when RPC returns error so the worker retries instead of treating it as idle', async () => {
    mockRpc.mockResolvedValueOnce({ data: null, error: { message: 'DB error' } });

    await expect(claimJob(mockSupabase as any, machineId)).rejects.toThrow('DB error');
  });

  it('two concurrent claims never return the same job when RPC simulates skip locked', async () => {
    const job1 = { id: 'job-a', project_id: 'p1', organization_id: 'o1', status: 'processing', run_id: 'r1', machine_id: machineId, payload: {}, attempts: 1, max_attempts: 3, error: null, started_at: '', heartbeat_at: '', completed_at: null, created_at: '' };
    const job2 = { id: 'job-b', project_id: 'p2', organization_id: 'o2', status: 'processing', run_id: 'r2', machine_id: 'machine-2', payload: {}, attempts: 1, max_attempts: 3, error: null, started_at: '', heartbeat_at: '', completed_at: null, created_at: '' };

    mockRpc
      .mockResolvedValueOnce({ data: [job1], error: null })
      .mockResolvedValueOnce({ data: [job2], error: null });

    const [r1, r2] = await Promise.all([
      claimJob(mockSupabase as any, 'machine-1'),
      claimJob(mockSupabase as any, 'machine-2'),
    ]);

    expect(r1?.id).toBe('job-a');
    expect(r2?.id).toBe('job-b');
    expect(r1?.id).not.toBe(r2?.id);
  });

  it('handles RPC returning single object (not array)', async () => {
    const job = { id: 'job-single', status: 'processing', project_id: 'p', organization_id: 'o', run_id: 'r', machine_id: machineId, payload: {}, attempts: 1, max_attempts: 3, error: null, started_at: '', heartbeat_at: '', completed_at: null, created_at: '' };
    mockRpc.mockResolvedValueOnce({ data: job, error: null });

    const result = await claimJob(mockSupabase as any, machineId);

    expect(result).toEqual(job);
  });
});
