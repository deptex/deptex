/**
 * Watchtower anomaly score thresholds for UI display.
 * Aligned with backend scoring: worker ~80 max, poller ~130 max.
 * - Below mild: single mild anomaly (noise).
 * - Mild: multiple mild signals or one strong; "worth a look".
 * - High: multiple strong/critical signals; "needs review".
 */
/** Yellow band: at least two moderate signals or one strong (e.g. 10+10 or 15+5). */
export const ANOMALY_MILD_THRESHOLD = 30;
/** Red band: multiple strong/critical signals (e.g. security files + first-time + volume). */
export const ANOMALY_HIGH_THRESHOLD = 60;

/**
 * Returns the Tailwind text color class for an anomaly score.
 * 1–29: neutral (muted), 30–59: warning (yellow), 60+: error (red).
 */
export function getAnomalyColor(score: number): string {
  if (score >= ANOMALY_HIGH_THRESHOLD) return 'text-error';
  if (score >= ANOMALY_MILD_THRESHOLD) return 'text-warning';
  return 'text-foreground-secondary';
}
