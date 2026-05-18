/**
 * Per-detector error tracking.
 *
 * Detector exceptions are caught per-file so one buggy detector doesn't abort
 * a whole repo's extraction — but a bare `catch {}` would silently zero a
 * framework's entry points. Instead we count failures per detector here so
 * the usage-extraction step can surface them once in its log.
 */

const detectorErrorCounts = new Map<string, number>();
let firstError: { detector: string; message: string } | null = null;

/** Record a detector failure. Called from every language module's detect loop. */
export function recordDetectorError(detectorName: string, err: unknown): void {
  detectorErrorCounts.set(detectorName, (detectorErrorCounts.get(detectorName) ?? 0) + 1);
  if (!firstError) {
    firstError = { detector: detectorName, message: err instanceof Error ? err.message : String(err) };
  }
}

/** Snapshot the accumulated detector errors. */
export function getDetectorErrorSummary(): { total: number; perDetector: Record<string, number>; firstError: { detector: string; message: string } | null } {
  let total = 0;
  const perDetector: Record<string, number> = {};
  for (const [name, count] of detectorErrorCounts) {
    perDetector[name] = count;
    total += count;
  }
  return { total, perDetector, firstError };
}

/** Reset counters — called at the start of each extraction run. */
export function resetDetectorErrors(): void {
  detectorErrorCounts.clear();
  firstError = null;
}
