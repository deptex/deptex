/**
 * Phase 10B: watchtower-queue unit tests (queueWatchtowerJob, queueWatchtowerJobs).
 */

const mockSingle = jest.fn().mockResolvedValue({ data: { id: 'job-uuid-1' }, error: null });
const mockInsert = jest.fn().mockImplementation((arg: unknown) => {
  if (Array.isArray(arg)) {
    return Promise.resolve({ error: null });
  }
  return { select: jest.fn().mockReturnValue({ single: mockSingle }) };
});
const mockFrom = jest.fn(() => ({ insert: mockInsert }));

jest.mock('../../../../backend/src/lib/supabase', () => ({
  supabase: { from: (...args: unknown[]) => mockFrom(...args) },
}));

const mockStartWatchtowerMachine = jest.fn().mockResolvedValue('machine-id');
jest.mock('../fly-machines', () => ({
  startWatchtowerMachine: (...args: unknown[]) => mockStartWatchtowerMachine(...args),
}));

import { queueWatchtowerJob, queueWatchtowerJobs } from '../watchtower-queue';

describe('watchtower-queue (Phase 10B)', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    mockSingle.mockResolvedValue({ data: { id: 'job-uuid-1' }, error: null });
    mockInsert.mockImplementation((arg: unknown) => {
      if (Array.isArray(arg)) return Promise.resolve({ error: null });
      return { select: jest.fn().mockReturnValue({ single: mockSingle }) };
    });
  });

  describe('queueWatchtowerJob', () => {
    it('inserts job with required fields and calls startWatchtowerMachine', async () => {
      const result = await queueWatchtowerJob({
        payload: { watchedPackageId: 'wp-1' },
        packageName: 'lodash',
        organizationId: 'org-1',
        projectId: 'proj-1',
        dependencyId: 'dep-1',
        type: 'full_analysis',
        priority: 10,
      });

      expect(result.success).toBe(true);
      expect(result.jobId).toBe('job-uuid-1');
      expect(mockFrom).toHaveBeenCalledWith('watchtower_jobs');
      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          job_type: 'full_analysis',
          priority: 10,
          package_name: 'lodash',
          organization_id: 'org-1',
          project_id: 'proj-1',
          dependency_id: 'dep-1',
          payload: { watchedPackageId: 'wp-1' },
        })
      );
      expect(mockStartWatchtowerMachine).toHaveBeenCalled();
    });

    it('defaults job_type to full_analysis and priority to 10', async () => {
      await queueWatchtowerJob({
        payload: {},
        packageName: 'react',
      });

      expect(mockInsert).toHaveBeenCalledWith(
        expect.objectContaining({
          job_type: 'full_analysis',
          priority: 10,
          package_name: 'react',
          organization_id: null,
          project_id: null,
          dependency_id: null,
        })
      );
    });

    it('returns success false when insert fails', async () => {
      mockSingle.mockResolvedValueOnce({ data: null, error: { message: 'Constraint violation' } });

      const result = await queueWatchtowerJob({
        payload: {},
        packageName: 'pkg',
      });

      expect(result.success).toBe(false);
      expect(result.error).toBeDefined();
      expect(mockStartWatchtowerMachine).not.toHaveBeenCalled();
    });
  });

  describe('queueWatchtowerJobs', () => {
    it('batch inserts and calls startWatchtowerMachine once', async () => {
      mockInsert.mockResolvedValueOnce({ error: null });

      const result = await queueWatchtowerJobs([
        { payload: {}, packageName: 'a' },
        { payload: {}, packageName: 'b' },
      ]);

      expect(result.success).toBe(true);
      expect(result.count).toBe(2);
      expect(mockInsert).toHaveBeenCalledTimes(1);
      expect(mockInsert).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ package_name: 'a' }),
          expect.objectContaining({ package_name: 'b' }),
        ])
      );
      expect(mockStartWatchtowerMachine).toHaveBeenCalledTimes(1);
    });

    it('returns success true count 0 for empty array and does not call startWatchtowerMachine', async () => {
      const result = await queueWatchtowerJobs([]);

      expect(result.success).toBe(true);
      expect(result.count).toBe(0);
      expect(mockInsert).not.toHaveBeenCalled();
      expect(mockStartWatchtowerMachine).not.toHaveBeenCalled();
    });

    it('returns success false when batch insert fails', async () => {
      mockInsert.mockResolvedValueOnce({ error: { message: 'DB error' } });

      const result = await queueWatchtowerJobs([
        { payload: {}, packageName: 'a' },
      ]);

      expect(result.success).toBe(false);
      expect(result.count).toBe(0);
      expect(mockStartWatchtowerMachine).not.toHaveBeenCalled();
    });
  });
});
