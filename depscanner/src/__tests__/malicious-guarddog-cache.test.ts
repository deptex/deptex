/**
 * Regression coverage for the GuardDog cache hit-detection fix.
 *
 * The bug: `readGuardDogCache` returned a bare `GuardDogRule[]` and the
 * caller used `length > 0` as the hit signal, so every CLEAN package (zero
 * findings — ~92% of all packages) looked like a cache MISS and was
 * re-downloaded + re-scanned on every extraction. The fix signals hit/miss
 * by ROW EXISTENCE + scanner_version match, with a TTL carve-out for
 * negative `fetch_error` rows.
 */
import {
  readGuardDogCache,
  GUARDDOG_FETCH_ERROR_RISK_LEVEL,
  GUARDDOG_FETCH_ERROR_TTL_MS,
} from '../malicious-scan';
import { GUARDDOG_VERSION, type GuardDogRule } from '../malicious/guarddog';

type Result = { data: unknown; error: unknown };

/**
 * Storage whose query chain (`.select().eq()...maybeSingle()`) resolves the
 * given result regardless of how many `.eq()` filters are chained.
 */
function storageReturning(result: Result): Parameters<typeof readGuardDogCache>[0] {
  const chain: Record<string, unknown> = {};
  chain.select = () => chain;
  chain.eq = () => chain;
  chain.maybeSingle = async () => result;
  return { from: () => chain } as unknown as Parameters<typeof readGuardDogCache>[0];
}

const SAMPLE_RULE: GuardDogRule = {
  rule_id: 'npm-exfiltrate-sensitive-data',
  severity: 'ERROR',
  message: 'exfiltration',
  evidence: [{ file_path: 'index.js', lines: [1, 1], snippet: 'fetch(...)' }],
};

describe('readGuardDogCache', () => {
  it('CLEAN cached row (empty findings, matching version) is a HIT — the regression', async () => {
    const storage = storageReturning({
      data: { findings: [], scanner_version: GUARDDOG_VERSION, risk_level: 'none', scanned_at: null },
      error: null,
    });
    const lookup = await readGuardDogCache(storage, 'lodash', '4.17.21', 'npm');
    expect(lookup.found).toBe(true); // was false under the old `length > 0` check
    expect(lookup.rules).toEqual([]);
  });

  it('cached row WITH findings (matching version) is a HIT carrying the rules', async () => {
    const storage = storageReturning({
      data: { findings: [SAMPLE_RULE], scanner_version: GUARDDOG_VERSION, risk_level: 'high', scanned_at: null },
      error: null,
    });
    const lookup = await readGuardDogCache(storage, 'evil', '1.0.0', 'npm');
    expect(lookup.found).toBe(true);
    expect(lookup.rules).toHaveLength(1);
    expect(lookup.rules[0].rule_id).toBe('npm-exfiltrate-sensitive-data');
  });

  it('no row is a MISS', async () => {
    const storage = storageReturning({ data: null, error: null });
    const lookup = await readGuardDogCache(storage, 'absent', '1.0.0', 'npm');
    expect(lookup.found).toBe(false);
    expect(lookup.rules).toEqual([]);
  });

  it('stale scanner_version is a MISS (new rules → must re-scan)', async () => {
    const storage = storageReturning({
      data: { findings: [], scanner_version: 'guarddog@0.0.1-old', risk_level: 'none', scanned_at: null },
      error: null,
    });
    const lookup = await readGuardDogCache(storage, 'lodash', '4.17.21', 'npm');
    expect(lookup.found).toBe(false);
  });

  it('DB error is a MISS', async () => {
    const storage = storageReturning({ data: null, error: { message: 'boom' } });
    const lookup = await readGuardDogCache(storage, 'x', '1.0.0', 'npm');
    expect(lookup.found).toBe(false);
  });

  describe('fetch_error negative cache (TTL-bounded)', () => {
    const now = 1_700_000_000_000;

    it('fresh fetch_error is a HIT (skip the re-fetch)', async () => {
      const storage = storageReturning({
        data: {
          findings: [],
          scanner_version: GUARDDOG_VERSION,
          risk_level: GUARDDOG_FETCH_ERROR_RISK_LEVEL,
          scanned_at: new Date(now - 1000).toISOString(),
        },
        error: null,
      });
      const lookup = await readGuardDogCache(storage, 'private-pkg', '1.0.0', 'npm', now);
      expect(lookup.found).toBe(true);
      expect(lookup.rules).toEqual([]);
    });

    it('stale fetch_error (past TTL) is a MISS (retry once)', async () => {
      const storage = storageReturning({
        data: {
          findings: [],
          scanner_version: GUARDDOG_VERSION,
          risk_level: GUARDDOG_FETCH_ERROR_RISK_LEVEL,
          scanned_at: new Date(now - GUARDDOG_FETCH_ERROR_TTL_MS - 1000).toISOString(),
        },
        error: null,
      });
      const lookup = await readGuardDogCache(storage, 'private-pkg', '1.0.0', 'npm', now);
      expect(lookup.found).toBe(false);
    });

    it('fetch_error with unparseable scanned_at is a MISS (fail safe → retry)', async () => {
      const storage = storageReturning({
        data: {
          findings: [],
          scanner_version: GUARDDOG_VERSION,
          risk_level: GUARDDOG_FETCH_ERROR_RISK_LEVEL,
          scanned_at: null,
        },
        error: null,
      });
      const lookup = await readGuardDogCache(storage, 'private-pkg', '1.0.0', 'npm', now);
      expect(lookup.found).toBe(false);
    });
  });
});
