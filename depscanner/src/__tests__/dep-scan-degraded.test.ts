/**
 * Unit tests for the dep-scan DEGRADED-run detector (dep-scan.ts).
 *
 * Regression guard for the VFN1 false-clean P0: dep-scan's VDB-refresh download
 * broke mid-stream with `requests.exceptions.ChunkedEncodingError: Connection
 * broken: IncompleteRead(...)`, it logged "No vulnerability scan results
 * available", produced 0 results, and STILL exited 0. The exit-0 branch in
 * doDepScan then set `depScanSucceeded = true`, the OSV safety-net's `force`
 * (`!depScanSucceeded`) stayed off, and a genuinely-vulnerable repo
 * (express@4.18.2) was reported CLEAN.
 *
 * `detectDegradedDepScan` is the load-bearing decision: when it returns
 * `degraded`, doDepScan keeps `depScanSucceeded = false`, which (a) force-fires
 * the OSV fallback and (b) trips the loud-fail guard if OSV is also down. When
 * it returns not-degraded, the exit-0 run is a normal clean success.
 */

import { detectDegradedDepScan } from '../pipeline-steps/dep-scan';

// A realistic dep-scan run whose VDB download was truncated mid-stream. dep-scan
// logs the requests/urllib3 exception, then the "No vulnerability scan results
// available" WARNING, and exits 0 with no usable VDR.
const VDB_CHUNKED_ENCODING_OUTPUT = `
[12:01:33] INFO     Refreshing the vulnerability database
Traceback (most recent call last):
  File "/usr/lib/python3/dist-packages/urllib3/response.py", line 761, in _update_chunk_length
  File "/usr/lib/python3/dist-packages/requests/models.py", line 818, in generate
requests.exceptions.ChunkedEncodingError: ("Connection broken: IncompleteRead(1048576 bytes read, 4194304 more expected)", IncompleteRead(1048576 bytes read, 4194304 more expected))
[12:02:10] WARNING  No vulnerability scan results available
`.trim();

// A clean dep-scan run: the project genuinely has no known vulnerabilities. NONE
// of the degraded signatures appear — dep-scan's clean path uses its own
// "No oss vulnerabilities" success line.
const CLEAN_NO_VULNS_OUTPUT = `
[12:01:33] INFO     Scanning based on npm purls
[12:01:40] INFO     No oss vulnerabilities found ✅
Dependency Scan Completed
`.trim();

describe('detectDegradedDepScan', () => {
  it('(a) flags a truncated VDB download (ChunkedEncodingError) with 0 results as degraded', () => {
    const res = detectDegradedDepScan(VDB_CHUNKED_ENCODING_OUTPUT);
    expect(res.degraded).toBe(true);
    // The first matching cause wins; it must name the real network failure, not
    // a misleading "0 vulnerabilities" picture.
    expect(res.reason).toMatch(/ChunkedEncodingError/i);
  });

  it('(b) does NOT flag a genuinely clean run (no error signature, 0 vulns)', () => {
    const res = detectDegradedDepScan(CLEAN_NO_VULNS_OUTPUT);
    expect(res.degraded).toBe(false);
    expect(res.reason).toBeUndefined();
  });

  it('flags IncompleteRead even without the ChunkedEncodingError class name', () => {
    const res = detectDegradedDepScan(
      'urllib3.exceptions.ProtocolError: ("Connection broken: IncompleteRead(0 bytes read, 8 more expected)")',
    );
    expect(res.degraded).toBe(true);
    expect(res.reason).toMatch(/IncompleteRead|Connection broken|network/i);
  });

  it('flags a generic requests network exception during the VDB refresh', () => {
    const res = detectDegradedDepScan(
      '[12:00:00] INFO Downloading vulnerability database\nrequests.exceptions.ConnectionError: HTTPSConnectionPool(host=\'...\'): Max retries exceeded',
    );
    expect(res.degraded).toBe(true);
  });

  it('flags an explicit "failed to download the vulnerability database" line', () => {
    const res = detectDegradedDepScan('ERROR  Unable to download the vulnerability database, aborting refresh');
    expect(res.degraded).toBe(true);
    expect(res.reason).toMatch(/VDB|database/i);
  });

  it('flags dep-scan\'s "No vulnerability scan results available" warning (results object absent)', () => {
    const res = detectDegradedDepScan('[12:02:10] WARNING  No vulnerability scan results available');
    expect(res.degraded).toBe(true);
    expect(res.reason).toMatch(/no vulnerability scan results/i);
  });

  it('flags a corrupt/incomplete VDB', () => {
    const res = detectDegradedDepScan('The vulnerability database is corrupt or incomplete');
    expect(res.degraded).toBe(true);
  });

  it('does NOT flag empty / undefined / null output', () => {
    expect(detectDegradedDepScan('').degraded).toBe(false);
    expect(detectDegradedDepScan(undefined).degraded).toBe(false);
    expect(detectDegradedDepScan(null).degraded).toBe(false);
  });

  it('does NOT flag an ordinary scan banner that merely mentions the vulnerability database', () => {
    // "0 results" alone (and benign mentions of the DB) must not be treated as a
    // failure — only an actual error/refresh-failure signature counts.
    const res = detectDegradedDepScan(
      '[12:01:30] INFO Using local vulnerability database at /data/vdb\n[12:01:45] INFO 0 vulnerabilities found',
    );
    expect(res.degraded).toBe(false);
  });
});
