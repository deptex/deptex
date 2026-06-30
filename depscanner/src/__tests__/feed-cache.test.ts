/**
 * KEV / EPSS in-process feed cache (P4 reliability fix).
 *
 * dep-scan.ts used to re-download the full CISA KEV catalog and re-query FIRST
 * EPSS on every scan. These helpers cache both with a TTL so back-to-back scans
 * on the same (serial, scale-to-zero) worker reuse the feed.
 */

import {
  getCachedKevSet,
  getCachedEpss,
  setCachedEpss,
  _resetFeedCache,
} from '../pipeline-helpers';

describe('KEV feed cache (getCachedKevSet)', () => {
  beforeEach(() => _resetFeedCache());

  it('cache-hit path: a second call within the TTL does NOT re-fetch', async () => {
    const fetcher = jest.fn(async () => new Set(['CVE-2024-0001', 'CVE-2024-0002']));

    const t0 = 1_000_000;
    const first = await getCachedKevSet(fetcher, t0, 60_000);
    const second = await getCachedKevSet(fetcher, t0 + 30_000, 60_000); // within TTL

    expect(fetcher).toHaveBeenCalledTimes(1); // served from cache the 2nd time
    expect([...first]).toEqual(['CVE-2024-0001', 'CVE-2024-0002']);
    expect(second).toBe(first); // same cached Set instance
  });

  it('re-fetches after the TTL expires', async () => {
    const fetcher = jest.fn(async () => new Set(['CVE-2024-0001']));
    const t0 = 1_000_000;
    await getCachedKevSet(fetcher, t0, 60_000);
    await getCachedKevSet(fetcher, t0 + 60_001, 60_000); // past TTL
    expect(fetcher).toHaveBeenCalledTimes(2);
  });

  it('does NOT cache an empty set (transient fetch failure), so the next scan retries', async () => {
    const fetcher = jest
      .fn()
      .mockResolvedValueOnce(new Set<string>()) // failed fetch → empty
      .mockResolvedValueOnce(new Set(['CVE-2024-0009']));

    const t0 = 1_000_000;
    const empty = await getCachedKevSet(fetcher, t0, 60_000);
    const filled = await getCachedKevSet(fetcher, t0 + 1, 60_000); // immediately retried

    expect(empty.size).toBe(0);
    expect([...filled]).toEqual(['CVE-2024-0009']);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
});

describe('EPSS score cache (getCachedEpss / setCachedEpss)', () => {
  beforeEach(() => _resetFeedCache());

  it('cache-hit path: a stored score is returned within the TTL', () => {
    const t0 = 2_000_000;
    setCachedEpss('CVE-2024-1111', 0.42, t0, 60_000);
    expect(getCachedEpss('CVE-2024-1111', t0 + 30_000)).toBe(0.42);
  });

  it('returns undefined for an unknown or expired CVE', () => {
    const t0 = 2_000_000;
    expect(getCachedEpss('CVE-2024-2222', t0)).toBeUndefined();
    setCachedEpss('CVE-2024-2222', 0.9, t0, 60_000);
    expect(getCachedEpss('CVE-2024-2222', t0 + 60_001)).toBeUndefined(); // expired
  });
});
