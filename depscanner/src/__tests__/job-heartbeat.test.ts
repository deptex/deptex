/**
 * sendHeartbeat bounded-retry semantics (P3 reliability fix).
 *
 * The heartbeat must distinguish three outcomes:
 *   - a clean query with >=1 row  → claim alive (true)
 *   - a clean query with 0 rows   → claim revoked (false)
 *   - query errors                → retry a bounded number of times; a blip is
 *     absorbed (eventual clean result wins), a sustained failure resolves to
 *     `false` (ownership unconfirmable) rather than the old always-true that
 *     masked a revoked claim forever.
 */

process.env.SUPABASE_URL = 'https://fake.supabase.co';
process.env.SUPABASE_SERVICE_ROLE_KEY = 'fake-key';

import { sendHeartbeat } from '../job-db';

function makeMock() {
  const select = jest.fn();
  const chain = {
    update: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    select,
  };
  const supabase = { from: jest.fn(() => chain) };
  return { supabase, select, chain };
}

describe('sendHeartbeat', () => {
  it('returns true when the guarded update affects >=1 row (claim alive)', async () => {
    const { supabase, select } = makeMock();
    select.mockResolvedValueOnce({ data: [{ id: 'job-1' }], error: null });

    const alive = await sendHeartbeat(supabase as any, 'job-1', 'machine-1', 'run-1');
    expect(alive).toBe(true);
    expect(select).toHaveBeenCalledTimes(1);
  });

  it('returns false on a clean 0-row result (claim revoked) without retrying', async () => {
    const { supabase, select } = makeMock();
    select.mockResolvedValueOnce({ data: [], error: null });

    const alive = await sendHeartbeat(supabase as any, 'job-1', 'machine-1', 'run-1', {
      retryDelayMs: 0,
    });
    expect(alive).toBe(false);
    // A clean query is authoritative — no retry burned on a real revoke.
    expect(select).toHaveBeenCalledTimes(1);
  });

  it('absorbs a transient blip: errors once, then a clean row → still alive (bounded)', async () => {
    const { supabase, select } = makeMock();
    select
      .mockResolvedValueOnce({ data: null, error: { message: 'transient: ECONNRESET' } })
      .mockResolvedValueOnce({ data: [{ id: 'job-1' }], error: null });

    const alive = await sendHeartbeat(supabase as any, 'job-1', 'machine-1', 'run-1', {
      retryDelayMs: 0,
    });
    expect(alive).toBe(true);
    expect(select).toHaveBeenCalledTimes(2); // 1 failed + 1 successful retry
  });

  it('returns false when every bounded attempt errors (sustained outage, no longer "alive forever")', async () => {
    const { supabase, select } = makeMock();
    select.mockResolvedValue({ data: null, error: { message: 'sustained: 503' } });

    const alive = await sendHeartbeat(supabase as any, 'job-1', 'machine-1', 'run-1', {
      retries: 2,
      retryDelayMs: 0,
    });
    expect(alive).toBe(false);
    expect(select).toHaveBeenCalledTimes(3); // 1 initial + 2 retries, all errored
  });

  it('a single transient error mid-run does not kill a healthy long scan', async () => {
    const { supabase, select } = makeMock();
    // First heartbeat blips then recovers; a later heartbeat is clean.
    select
      .mockResolvedValueOnce({ data: null, error: { message: 'blip' } })
      .mockResolvedValueOnce({ data: [{ id: 'job-1' }], error: null })
      .mockResolvedValueOnce({ data: [{ id: 'job-1' }], error: null });

    const first = await sendHeartbeat(supabase as any, 'job-1', 'm', 'r', { retryDelayMs: 0 });
    const second = await sendHeartbeat(supabase as any, 'job-1', 'm', 'r', { retryDelayMs: 0 });
    expect(first).toBe(true);
    expect(second).toBe(true);
  });
});
