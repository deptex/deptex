/**
 * Phase 2M: queueExtractionJob and cancelExtractionJob unit tests
 */

const mockRpc = jest.fn();
const mockFrom = jest.fn();
const mockStartExtractionMachine = jest.fn().mockResolvedValue('fly-id');

jest.mock('../../../../backend/src/lib/supabase', () => ({
  supabase: {
    from: (...args: unknown[]) => mockFrom(...args),
  },
}));

jest.mock('../fly-machines', () => ({
  startExtractionMachine: (...args: unknown[]) => mockStartExtractionMachine(...args),
}));

import { queueExtractionJob, cancelExtractionJob } from '../redis';

function createChain(resolved: { data?: unknown; error?: unknown } = { data: null, error: null }) {
  const chain: Record<string, jest.Mock> = {
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    in: jest.fn().mockReturnThis(),
    order: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn().mockResolvedValue(resolved),
    single: jest.fn().mockResolvedValue(resolved),
    insert: jest.fn().mockResolvedValue({ error: null }),
    update: jest.fn().mockReturnThis(),
  };
  mockFrom.mockReturnValue(chain);
  return chain;
}

describe('queueExtractionJob', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('inserts job and returns run_id when no existing job', async () => {
    const chain = createChain();
    chain.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
    chain.insert.mockResolvedValueOnce({ error: null });

    const result = await queueExtractionJob('proj-1', 'org-1', {
      repo_full_name: 'owner/repo',
      installation_id: 'inst-1',
      default_branch: 'main',
    });

    expect(result.success).toBe(true);
    expect(result.run_id).toBeDefined();
    expect(typeof result.run_id).toBe('string');
    expect(mockFrom).toHaveBeenCalledWith('extraction_jobs');
    expect(chain.insert).toHaveBeenCalledWith(
      expect.objectContaining({
        project_id: 'proj-1',
        organization_id: 'org-1',
        status: 'queued',
        payload: expect.objectContaining({
          repo_full_name: 'owner/repo',
          installation_id: 'inst-1',
          default_branch: 'main',
        }),
      })
    );
    expect(mockStartExtractionMachine).toHaveBeenCalled();
  });

  it('returns failure when extraction already in progress', async () => {
    createChain();
    mockFrom.mockImplementation((table: string) => {
      const ch: Record<string, jest.Mock> = {
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        in: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        maybeSingle: jest.fn().mockResolvedValue({
          data: table === 'extraction_jobs' ? { id: 'job-1', status: 'processing' } : null,
          error: null,
        }),
      };
      return ch;
    });

    const result = await queueExtractionJob('proj-1', 'org-1', {
      repo_full_name: 'owner/repo',
      installation_id: 'inst-1',
      default_branch: 'main',
    });

    expect(result.success).toBe(false);
    expect(result.error).toContain('already in progress');
    expect(mockStartExtractionMachine).not.toHaveBeenCalled();
  });

  it('continues when Fly machine start fails (job stays queued)', async () => {
    const chain = createChain();
    chain.maybeSingle.mockResolvedValueOnce({ data: null, error: null });
    chain.insert.mockResolvedValueOnce({ error: null });
    mockStartExtractionMachine.mockRejectedValueOnce(new Error('Fly API down'));

    const result = await queueExtractionJob('proj-1', 'org-1', {
      repo_full_name: 'owner/repo',
      installation_id: 'inst-1',
      default_branch: 'main',
    });

    expect(result.success).toBe(true);
    expect(result.run_id).toBeDefined();
  });
});

describe('cancelExtractionJob', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it('sets status to cancelled for active job', async () => {
    const chain = createChain();
    mockFrom.mockImplementation((table: string) => {
      const ch: Record<string, jest.Mock> = {
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        in: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        maybeSingle: jest.fn().mockResolvedValue(
          table === 'extraction_jobs'
            ? { data: { id: 'job-1', status: 'processing' }, error: null }
            : { data: null, error: null }
        ),
        update: jest.fn().mockReturnThis(),
      };
      return ch;
    });

    const result = await cancelExtractionJob('proj-1');

    expect(result.success).toBe(true);
    expect(mockFrom).toHaveBeenCalledWith('extraction_jobs');
  });

  it('returns error when no active extraction', async () => {
    const chain = createChain();
    chain.maybeSingle.mockResolvedValueOnce({ data: null, error: null });

    const result = await cancelExtractionJob('proj-1');

    expect(result.success).toBe(false);
    expect(result.error).toContain('No active extraction');
  });

  it('returns error when extraction already completed', async () => {
    let callCount = 0;
    mockFrom.mockImplementation(() => {
      callCount++;
      const ch: Record<string, jest.Mock> = {
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        in: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        maybeSingle: jest.fn().mockImplementation(() => {
          if (callCount === 1) {
            return Promise.resolve({ data: null, error: null });
          }
          return Promise.resolve({ data: { status: 'completed' }, error: null });
        }),
      };
      return ch;
    });

    const result = await cancelExtractionJob('proj-1');

    expect(result.success).toBe(false);
    expect(result.error).toContain('already completed');
  });

  it('returns error when extraction already cancelled', async () => {
    let callCount = 0;
    mockFrom.mockImplementation(() => {
      callCount++;
      const ch: Record<string, jest.Mock> = {
        select: jest.fn().mockReturnThis(),
        eq: jest.fn().mockReturnThis(),
        in: jest.fn().mockReturnThis(),
        order: jest.fn().mockReturnThis(),
        limit: jest.fn().mockReturnThis(),
        maybeSingle: jest.fn().mockImplementation(() => {
          if (callCount === 1) {
            return Promise.resolve({ data: null, error: null });
          }
          return Promise.resolve({ data: { status: 'cancelled' }, error: null });
        }),
      };
      return ch;
    });

    const result = await cancelExtractionJob('proj-1');

    expect(result.success).toBe(false);
    expect(result.error).toContain('already cancelled');
  });
});
