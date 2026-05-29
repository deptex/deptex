// Phase 24a (v2.1a): startup probe for DAST_CREDENTIAL_KEY.
//
// The worker must NOT claim DAST jobs when the encryption key is missing —
// otherwise it would spawn an anonymous scan against a target that has
// has_credentials=true (the silent-anonymous-fallback failure mode the plan
// labels non-negotiable). The filter happens at the queue layer: we pass a
// supported-types list that excludes 'dast' / 'dast_zap' / 'dast_nuclei'
// when the key is unset, so claim_scan_job's FOR UPDATE SKIP LOCKED filter
// keeps DAST jobs in the queue rather than handing them to a misconfigured
// worker.

import { getSupportedJobTypes } from '../job-db';

describe('getSupportedJobTypes', () => {
  const originalEnv = { ...process.env };
  afterEach(() => {
    process.env = { ...originalEnv };
  });

  it('returns only extraction when DAST_CREDENTIAL_KEY is unset', () => {
    delete process.env.DAST_CREDENTIAL_KEY;
    expect(getSupportedJobTypes()).toEqual(['extraction']);
  });

  it('returns extraction + all DAST types when DAST_CREDENTIAL_KEY is set', () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    const types = getSupportedJobTypes();
    expect(types).toContain('extraction');
    expect(types).toContain('dast');
    expect(types).toContain('dast_zap');
    expect(types).toContain('dast_nuclei');
    // v2.1d /criticalreview SVED-1 fix: Test-login queues a distinct type
    // so old workers can't accidentally claim it and run a real scan.
    expect(types).toContain('dast_zap_dry_run');
  });

  it('returns only extraction when DAST_CREDENTIAL_KEY is empty string', () => {
    process.env.DAST_CREDENTIAL_KEY = '';
    expect(getSupportedJobTypes()).toEqual(['extraction']);
  });

  it('SCAN_TYPE=extraction claims only extraction even with the DAST key set', () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    process.env.SCAN_TYPE = 'extraction';
    expect(getSupportedJobTypes()).toEqual(['extraction']);
  });

  it('SCAN_TYPE=dast claims only dast types (never extraction)', () => {
    process.env.DAST_CREDENTIAL_KEY = '0'.repeat(64);
    process.env.SCAN_TYPE = 'dast';
    const types = getSupportedJobTypes();
    expect(types).not.toContain('extraction');
    expect(types).toEqual(['dast', 'dast_zap', 'dast_nuclei', 'dast_zap_dry_run']);
  });
});
