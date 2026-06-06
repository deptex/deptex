/**
 * A ScanFailedError marks an EXPECTED, handled scan-level failure — the scan
 * could not complete for a reason that is already recorded (scan_jobs.error,
 * project_repositories error state, extraction_step_errors / the admin failures
 * page) and surfaced to the user. It is a PROJECT outcome, not a worker bug:
 * the worker handled it gracefully.
 *
 * The job loop (index.ts) uses this to skip Sentry — a customer's unresolvable
 * manifest is not an exception worth paging on; alerting on it just desensitizes
 * us to real crashes. Anything that is NOT a ScanFailedError (an unexpected
 * throw, a null-deref, an infra failure) still goes to Sentry.
 */
export class ScanFailedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScanFailedError';
    // Preserve the prototype chain so `instanceof ScanFailedError` works after
    // TypeScript's ES2020 downlevel (Error breaks the chain otherwise).
    Object.setPrototypeOf(this, ScanFailedError.prototype);
  }
}
