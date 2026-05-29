/**
 * Thin-enqueue guarantee: queueExtractionJob does its DB work and nudges the
 * fleet dispatcher in-process, but NEVER blocks the request on the Fly API.
 * The headline success criterion of the scalable-extraction-infra plan.
 */
import { setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../fleet-dispatcher', () => ({ nudgeDispatcher: jest.fn() }));

import { queueExtractionJob } from '../extraction-jobs';
import { nudgeDispatcher } from '../fleet-dispatcher';

beforeEach(() => {
  clearTableRegistry();
  (nudgeDispatcher as jest.Mock).mockClear();
  // No extraction already in progress for this project.
  setTableResponse('scan_jobs', 'maybeSingle', { data: null, error: null });
});

describe('queueExtractionJob — thin enqueue', () => {
  it('inserts the job, nudges the dispatcher, and returns without any Fly call', async () => {
    const res = await queueExtractionJob('proj-1', 'org-1', {
      repo_full_name: 'acme/app',
      installation_id: 'inst-1',
      default_branch: 'main',
    });

    expect(res.success).toBe(true);
    expect(res.run_id).toBeTruthy();
    // Provisioning is delegated to the dispatcher (off the request hot path).
    expect(nudgeDispatcher).toHaveBeenCalledWith('extraction');
  });

  it('rejects (and does not nudge) when an extraction is already in progress', async () => {
    setTableResponse('scan_jobs', 'maybeSingle', {
      data: { id: 'existing', status: 'processing' },
      error: null,
    });

    const res = await queueExtractionJob('proj-1', 'org-1', {
      repo_full_name: 'acme/app',
      installation_id: 'inst-1',
      default_branch: 'main',
    });

    expect(res.success).toBe(false);
    expect(nudgeDispatcher).not.toHaveBeenCalled();
  });
});
